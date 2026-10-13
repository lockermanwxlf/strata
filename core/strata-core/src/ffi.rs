//! The UniFFI surface (implementation plan, Phase 8): one `Vault` object per open
//! vault, with coarse-grained calls. Kotlin never sees keys, and secret values cross
//! only as `ByteArray`s: `reveal` hands out one value at a time, and summaries and
//! details never carry them. The caller zeroes every `ByteArray` it sends or gets.
//!
//! Calls block: Argon2 runs for a large fraction of a second, and syncing touches the
//! disk. The Kotlin wrappers run them off the UI thread.
//!
//! Alarms are state, not failures: `sync` and the unlock calls report them in
//! `SyncSummary::alarm`, and the vault stays open to read (spec §9.4).

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use zeroize::Zeroizing;

use crate::crypto::{SecretBytes, SecretKey, generate, random_id};
use crate::error::{AlarmKind, CoreError};
use crate::format::Id;
use crate::format::body::Op;
use crate::keys::create::create_vault as create_vault_files;
use crate::keys::strength;
use crate::keys::unlock::{Credential, local_slots, unlock};
use crate::local::{FsLocalStore, LocalStore};
use crate::merge::edit::{Edit, new_entry_id as fresh_entry_id};
use crate::merge::view::{EntryView, Field};
use crate::policy::check_platform_policy;
use crate::protector::{PlatformProtector, ProtectorError};
use crate::sync::session::{GC_GRACE_MS, PurgeReport, Rotated, SessionOf, SyncReport};
use crate::sync::{FsStore, RemoteStore};

type FfiSession = SessionOf<Arc<dyn RemoteStore>, Arc<dyn LocalStore>>;

/// Errors as Kotlin sees them. Messages carry no secrets (see `error.rs`).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VaultError {
    #[error("rejected {what}: {why}")]
    Rejected { what: String, why: String },
    /// From unlock (the vault stays locked) or a change refused because of an
    /// alarm. `sync` reports alarms in its summary instead.
    #[error("security alarm: {kind}")]
    Alarm { kind: AlarmKind },
    #[error("this vault needs a newer version of Strata (format {found})")]
    UpdateRequired { found: u16 },
    #[error("the vault is locked")]
    Locked,
    #[error("the vault's key was changed on another device; unlock again to keep editing")]
    KeyRotated,
    #[error("another device changed the vault key at the same time; unlock with its password")]
    ConflictingRotation,
    #[error("that password or recovery key doesn't unlock this vault")]
    WrongCredential,
    #[error("{detail}")]
    RecoveryWords { detail: String },
    #[error("{detail}")]
    Policy { detail: String },
    #[error("the system random number generator is unavailable")]
    Rng,
    #[error("storage error: {detail}")]
    Io { detail: String },
    #[error("no such {what}")]
    NotFound { what: String },
    /// The field holds concurrent values; use `reveal_conflict`.
    #[error("the field has conflicting values")]
    FieldConflict,
    /// The user cancelled the platform prompt.
    #[error("cancelled")]
    Cancelled,
    /// The platform key behind a local unlock is gone (for example, biometric
    /// enrollment changed). Unlock with the password; the slot is then removed.
    #[error("this device's unlock key is no longer valid; unlock with the password")]
    KeyInvalidated,
    #[error("device unlock unavailable: {detail}")]
    ProtectorUnavailable { detail: String },
}

impl From<ProtectorError> for VaultError {
    fn from(e: ProtectorError) -> Self {
        match e {
            ProtectorError::Cancelled => VaultError::Cancelled,
            ProtectorError::KeyInvalidated => VaultError::KeyInvalidated,
            ProtectorError::Unavailable { reason } => {
                VaultError::ProtectorUnavailable { detail: reason }
            }
            ProtectorError::Platform { detail } => VaultError::ProtectorUnavailable { detail },
            ProtectorError::WrongPin => VaultError::WrongCredential,
        }
    }
}

impl From<CoreError> for VaultError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::Rejected { what, why } => VaultError::Rejected {
                what: what.into(),
                why: why.into(),
            },
            CoreError::Alarm(kind) => VaultError::Alarm { kind },
            CoreError::UpdateRequired { found } => VaultError::UpdateRequired { found },
            CoreError::Locked => VaultError::Locked,
            CoreError::KeyRotated => VaultError::KeyRotated,
            CoreError::ConflictingRotation => VaultError::ConflictingRotation,
            CoreError::WrongCredential => VaultError::WrongCredential,
            CoreError::RecoveryWords(e) => VaultError::RecoveryWords {
                detail: e.to_string(),
            },
            CoreError::Policy(e) => VaultError::Policy {
                detail: e.to_string(),
            },
            CoreError::Rng => VaultError::Rng,
            CoreError::Io(e) => VaultError::Io {
                detail: e.to_string(),
            },
        }
    }
}

type Result<T, E = VaultError> = std::result::Result<T, E>;

#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncSummary {
    pub applied: u32,
    pub uploaded: u32,
    /// Events waiting for a key, a predecessor or dependencies.
    pub held: u32,
    /// Files that aren't valid events or snapshots, set aside.
    pub rejected: u32,
    pub far_future: u32,
    /// Another device rotated the key: read-only until the next unlock.
    pub key_rotated: bool,
    /// Another device's concurrent rotation won: read-only until `rejoin_*`.
    pub lost_rotation: bool,
    pub identity_reset: bool,
    pub integrity_unverified: bool,
    pub snapshot_written: bool,
    pub files_deleted: u32,
    /// Set when this sync raised (or had already raised) an alarm.
    pub alarm: Option<AlarmKind>,
}

impl SyncSummary {
    fn alarmed(kind: AlarmKind) -> Self {
        Self {
            applied: 0,
            uploaded: 0,
            held: 0,
            rejected: 0,
            far_future: 0,
            key_rotated: false,
            lost_rotation: false,
            identity_reset: false,
            integrity_unverified: false,
            snapshot_written: false,
            files_deleted: 0,
            alarm: Some(kind),
        }
    }

    fn from_report(r: &SyncReport) -> Self {
        Self {
            applied: count(r.applied),
            uploaded: count(r.uploaded),
            held: count(r.held.len()),
            rejected: count(r.rejected.len()),
            far_future: count(r.far_future.len()),
            key_rotated: r.key_rotated,
            lost_rotation: r.lost_rotation,
            identity_reset: r.identity_reset,
            integrity_unverified: r.integrity_unverified,
            snapshot_written: false,
            files_deleted: 0,
            alarm: None,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VaultStatus {
    pub locked: bool,
    pub alarm: Option<AlarmKind>,
    pub key_rotated: bool,
    pub lost_rotation: bool,
    /// Secret fields with concurrent values.
    pub conflicts: u32,
    /// Entries deleted on another device while edited here: keep or delete?
    pub unanswered_deletes: u32,
    /// Changes by retired or suspect devices (`revert_flagged`).
    pub flagged_changes: u32,
    pub suspect_devices: u32,
}

/// One line of the entry list. Never holds a secret field's value.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EntrySummary {
    pub id: String,
    /// The `title` and `username` fields, when they aren't secret.
    pub title: Option<String>,
    pub username: Option<String>,
    pub tags: Vec<String>,
    /// In the trash.
    pub deleted: bool,
    pub has_conflict: bool,
    pub unanswered_delete: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EntryDetail {
    pub id: String,
    pub fields: Vec<FieldInfo>,
    pub tags: Vec<String>,
    pub deleted: bool,
    pub unanswered_delete: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FieldInfo {
    pub name: String,
    pub secret: bool,
    /// The value of a non-secret field. Always `None` for secret ones: the UI shows a
    /// placeholder and calls `reveal`.
    pub value: Option<String>,
    /// How many concurrent values the field holds; 0 when there's no conflict.
    pub conflict_candidates: u32,
}

/// One side of a conflict. Not `Debug`: it holds a secret value.
#[derive(uniffi::Record)]
pub struct ConflictCandidate {
    /// `None`: this side deleted the field.
    pub value: Option<Vec<u8>>,
    pub device_id: String,
    pub device_name: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceInfo {
    pub client_id: String,
    pub name: String,
    pub this_device: bool,
    pub retired: bool,
    pub suspect: bool,
}

/// A change to apply. Not `Debug`: `SetField` carries a value.
#[derive(uniffi::Enum)]
pub enum EntryEdit {
    /// Sets a field, or removes it with `value: None`. `password` and `otp` are
    /// always secret.
    SetField {
        entry_id: String,
        name: String,
        value: Option<Vec<u8>>,
        secret: bool,
    },
    DeleteEntry {
        entry_id: String,
    },
    /// "Keep" after an unanswered delete; also restores from the trash.
    KeepEntry {
        entry_id: String,
    },
    AddTag {
        entry_id: String,
        tag: String,
    },
    RemoveTag {
        entry_id: String,
        tag: String,
    },
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RotationSummary {
    pub epoch: u32,
    /// The recovery slot couldn't be carried over; offer a new recovery key.
    pub recovery_lost: bool,
}

impl From<&Rotated> for RotationSummary {
    fn from(r: &Rotated) -> Self {
        Self {
            epoch: r.epoch,
            recovery_lost: r.recovery_lost,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PurgeSummary {
    pub rotation: RotationSummary,
    pub events_deleted: u32,
    pub snapshots_deleted: u32,
    /// Files the purge couldn't cover, which may still mention the entry.
    pub events_left: u32,
    pub snapshots_left: u32,
}

impl From<&PurgeReport> for PurgeSummary {
    fn from(r: &PurgeReport) -> Self {
        Self {
            rotation: (&r.rotated).into(),
            events_deleted: count(r.events_deleted),
            snapshots_deleted: count(r.snapshots_deleted),
            events_left: count(r.events_left),
            snapshots_left: count(r.snapshots_left),
        }
    }
}

#[derive(Debug, Clone, Copy, uniffi::Record)]
pub struct StrengthEstimate {
    pub guesses_log10: f64,
    /// The UI must warn and ask for an explicit "use anyway" (spec §6.2).
    pub warn: bool,
}

/// A new vault and its recovery words, shown to the user once.
#[derive(uniffi::Record)]
pub struct NewVault {
    pub vault: Arc<Vault>,
    pub recovery_words: Vec<u8>,
}

#[derive(uniffi::Object)]
pub struct Vault {
    store: Arc<dyn RemoteStore>,
    local: Arc<dyn LocalStore>,
    device_name: String,
    session: Mutex<Option<FfiSession>>,
    /// Mirrors whether `session` is set, readable without waiting for a call that
    /// holds the session (a sync, or Argon2 in a password change).
    unlocked: AtomicBool,
    /// Slot secrets from local slots unlocked or enrolled while open, kept to re-wrap
    /// the slots after the key changes without another prompt (spec §7.2). As
    /// sensitive as the epoch keys the session holds anyway, and dropped on lock.
    local_secrets: Mutex<Vec<(Id, SecretKey)>>,
    /// Protectors whose key turned out to be invalidated: their slots are removed at
    /// the next unlock (spec §11).
    invalidated: Mutex<Vec<u8>>,
}

/// Creates a vault in the empty directory `vault_dir`, with this device's local state
/// in `state_dir`, and returns it unlocked.
#[uniffi::export]
pub fn create_vault(
    vault_dir: String,
    state_dir: String,
    password: Vec<u8>,
    device_name: String,
) -> Result<NewVault> {
    let password = Zeroizing::new(password);
    let vault = Vault::new(vault_dir, state_dir, device_name)?;
    let created = create_vault_files(&*vault.store, &*vault.local, &password, &vault.device_name)?;
    vault.unlock_with(Credential::Password(&password))?;
    Ok(NewVault {
        vault,
        recovery_words: created.recovery_words.expose().to_vec(),
    })
}

/// The weak-password estimate (spec §6.2). Advisory: any password is allowed.
#[uniffi::export]
pub fn password_strength(password: Vec<u8>) -> Result<StrengthEstimate> {
    let password = Zeroizing::new(password);
    let s = strength::password_strength(&password)?;
    Ok(StrengthEstimate {
        guesses_log10: s.guesses_log10,
        warn: s.warn,
    })
}

/// A random password of `length` (8 to 128) characters: letters and digits, plus
/// symbols if asked. The caller zeroes the result.
#[uniffi::export]
pub fn generate_password(length: u32, symbols: bool) -> Result<Vec<u8>> {
    let password = generate::password(length as usize, symbols)?;
    Ok(password.expose().to_vec())
}

/// Where this device keeps local state on desktop systems (spec §11), or `None` if
/// the platform's usual variable isn't set. Android passes its app directory instead.
#[uniffi::export]
pub fn default_state_dir() -> Option<String> {
    FsLocalStore::default_dir().and_then(|d| d.to_str().map(str::to_string))
}

/// A fresh entry ID. The entry exists once its first field is set.
#[uniffi::export]
pub fn new_entry_id() -> Result<String> {
    Ok(hex::encode(fresh_entry_id()?))
}

impl Vault {
    fn new(vault_dir: String, state_dir: String, device_name: String) -> Result<Arc<Self>> {
        Op::SetDeviceName {
            name: device_name.clone(),
        }
        .validate("device name")?;
        Ok(Arc::new(Self {
            store: Arc::new(FsStore::new(vault_dir)),
            local: Arc::new(FsLocalStore::new(state_dir)),
            device_name,
            session: Mutex::new(None),
            unlocked: AtomicBool::new(false),
            local_secrets: Mutex::new(Vec::new()),
            invalidated: Mutex::new(Vec::new()),
        }))
    }

    /// The session slot. A panic while it was held may have left the session half
    /// way through a change, so after one the vault is locked rather than trusted.
    fn slot(&self) -> MutexGuard<'_, Option<FfiSession>> {
        match self.session.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                *guard = None;
                self.unlocked.store(false, Ordering::SeqCst);
                self.session.clear_poison();
                guard
            }
        }
    }

    fn with_session<T>(&self, f: impl FnOnce(&mut FfiSession) -> Result<T>) -> Result<T> {
        let mut slot = self.slot();
        let session = slot.as_mut().ok_or(VaultError::Locked)?;
        f(session)
    }

    fn unlock_with(&self, credential: Credential<'_>) -> Result<SyncSummary> {
        let unlocked = unlock(&*self.store, &*self.local, credential)?;
        let mut session = SessionOf::new(
            Arc::clone(&self.store),
            Arc::clone(&self.local),
            unlocked,
            &self.device_name,
        )?;
        let summary = sync_and_maintain(&mut session)?;
        for protector_id in std::mem::take(&mut *lock(&self.invalidated)) {
            session.remove_local_slots(protector_id)?;
        }
        self.refresh_local_slots(&mut session)?;
        *self.slot() = Some(session);
        self.unlocked.store(true, Ordering::SeqCst);
        Ok(summary)
    }

    fn rejoin_with(&self, credential: Credential<'_>) -> Result<()> {
        self.with_session(|s| Ok(s.rejoin(credential)?))
    }

    /// After anything that may have changed the key: re-wraps the local slots whose
    /// secret is held, and drops stale ones.
    fn refresh_local_slots(&self, session: &mut FfiSession) -> Result<()> {
        Ok(session.refresh_local_slots(&lock(&self.local_secrets))?)
    }

    fn remember_secret(&self, slot_id: Id, secret: SecretKey) {
        let mut secrets = lock(&self.local_secrets);
        secrets.retain(|(id, _)| *id != slot_id);
        secrets.push((slot_id, secret));
    }
}

/// Locks a plain mutex, ignoring poisoning: these hold no invariants a panic could break.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[uniffi::export]
impl Vault {
    /// A locked handle on an existing vault. `device_name` is used if this device
    /// joins the vault (its first change registers it).
    #[uniffi::constructor]
    pub fn open(vault_dir: String, state_dir: String, device_name: String) -> Result<Arc<Self>> {
        Self::new(vault_dir, state_dir, device_name)
    }

    pub fn is_locked(&self) -> bool {
        !self.unlocked.load(Ordering::SeqCst)
    }

    /// Unlocks with the password (UTF-8), then syncs.
    pub fn unlock_password(&self, password: Vec<u8>) -> Result<SyncSummary> {
        let password = Zeroizing::new(password);
        self.unlock_with(Credential::Password(&password))
    }

    /// Unlocks with the 24 recovery words as typed (UTF-8), then syncs.
    pub fn unlock_recovery(&self, words: Vec<u8>) -> Result<SyncSummary> {
        let words = Zeroizing::new(words);
        self.unlock_with(Credential::RecoveryWords(&words))
    }

    /// Forgets every key and decrypted value this handle holds. Waits for a call in
    /// progress to finish; `is_locked` turns true at once.
    pub fn lock(&self) {
        self.unlocked.store(false, Ordering::SeqCst);
        *self.slot() = None;
        lock(&self.local_secrets).clear();
    }

    /// Uploads pending changes and takes in everyone else's. Also snapshots when
    /// enough event files have piled up, and collects garbage past the grace period.
    pub fn sync(&self) -> Result<SyncSummary> {
        self.with_session(sync_and_maintain)
    }

    pub fn status(&self) -> VaultStatus {
        let slot = self.slot();
        let Some(session) = slot.as_ref() else {
            return VaultStatus {
                locked: true,
                alarm: None,
                key_rotated: false,
                lost_rotation: false,
                conflicts: 0,
                unanswered_deletes: 0,
                flagged_changes: 0,
                suspect_devices: 0,
            };
        };
        let view = session.view();
        let review = session.review();
        let conflicts = view
            .entries
            .values()
            .flat_map(|e| e.fields.values())
            .filter(|f| matches!(f, Field::Conflict { .. }))
            .count();
        VaultStatus {
            locked: false,
            alarm: session.alarm(),
            key_rotated: session.key_rotated(),
            lost_rotation: session.lost_rotation(),
            conflicts: count(conflicts),
            unanswered_deletes: count(
                view.entries
                    .values()
                    .filter(|e| e.unanswered_delete)
                    .count(),
            ),
            flagged_changes: count(review.flagged.len()),
            suspect_devices: count(review.suspect_devices.len()),
        }
    }

    /// Every entry, trash included, in ID order.
    pub fn entries(&self) -> Result<Vec<EntrySummary>> {
        self.with_session(|s| {
            Ok(s.view()
                .entries
                .iter()
                .map(|(id, entry)| EntrySummary {
                    id: hex::encode(id),
                    title: plain_value(entry, "title"),
                    username: plain_value(entry, "username"),
                    tags: tags(entry),
                    deleted: entry.deleted,
                    has_conflict: entry
                        .fields
                        .values()
                        .any(|f| matches!(f, Field::Conflict { .. })),
                    unanswered_delete: entry.unanswered_delete,
                })
                .collect())
        })
    }

    pub fn entry(&self, entry_id: String) -> Result<EntryDetail> {
        let id = parse_id(&entry_id)?;
        self.with_session(|s| {
            let view = s.view();
            let entry = view.entries.get(&id).ok_or(not_found("entry"))?;
            let fields = entry
                .fields
                .iter()
                .map(|(name, field)| match field {
                    Field::Value { value, secret, .. } => FieldInfo {
                        name: name.to_string(),
                        secret: *secret,
                        value: (!secret).then(|| text(value)),
                        conflict_candidates: 0,
                    },
                    Field::Conflict { candidates } => FieldInfo {
                        name: name.to_string(),
                        secret: true,
                        value: None,
                        conflict_candidates: count(candidates.len()),
                    },
                })
                .collect();
            Ok(EntryDetail {
                id: entry_id.clone(),
                fields,
                tags: tags(entry),
                deleted: entry.deleted,
                unanswered_delete: entry.unanswered_delete,
            })
        })
    }

    /// One field's value. The caller zeroes the array when done with it.
    pub fn reveal(&self, entry_id: String, field: String) -> Result<Vec<u8>> {
        let id = parse_id(&entry_id)?;
        self.with_session(|s| {
            let view = s.view();
            let entry = view.entries.get(&id).ok_or(not_found("entry"))?;
            match entry.fields.get(field.as_str()) {
                Some(Field::Value { value, .. }) => Ok(value.expose().to_vec()),
                Some(Field::Conflict { .. }) => Err(VaultError::FieldConflict),
                None => Err(not_found("field")),
            }
        })
    }

    /// Every value of a field in conflict, with the device that wrote it. Resolve by
    /// setting the field again. The caller zeroes the values.
    pub fn reveal_conflict(
        &self,
        entry_id: String,
        field: String,
    ) -> Result<Vec<ConflictCandidate>> {
        let id = parse_id(&entry_id)?;
        self.with_session(|s| {
            let view = s.view();
            let entry = view.entries.get(&id).ok_or(not_found("entry"))?;
            let Some(Field::Conflict { candidates }) = entry.fields.get(field.as_str()) else {
                return Err(not_found("conflict"));
            };
            Ok(candidates
                .iter()
                .map(|c| ConflictCandidate {
                    value: c.value.map(|v| v.expose().to_vec()),
                    device_id: hex::encode(c.dot.client_id),
                    device_name: view
                        .devices
                        .get(&c.dot.client_id)
                        .map(|d| d.name.to_string()),
                })
                .collect())
        })
    }

    /// Applies the edits as one change.
    pub fn apply(&self, edits: Vec<EntryEdit>) -> Result<()> {
        let edits = edits
            .into_iter()
            .map(|e| {
                Ok(match e {
                    EntryEdit::SetField {
                        entry_id,
                        name,
                        value,
                        secret,
                    } => Edit::SetField {
                        entry_id: parse_id(&entry_id)?,
                        name,
                        value: value.map(SecretBytes::new),
                        secret,
                    },
                    EntryEdit::DeleteEntry { entry_id } => Edit::DeleteEntry {
                        entry_id: parse_id(&entry_id)?,
                    },
                    EntryEdit::KeepEntry { entry_id } => Edit::KeepEntry {
                        entry_id: parse_id(&entry_id)?,
                    },
                    EntryEdit::AddTag { entry_id, tag } => Edit::AddTag {
                        entry_id: parse_id(&entry_id)?,
                        tag,
                    },
                    EntryEdit::RemoveTag { entry_id, tag } => Edit::RemoveTag {
                        entry_id: parse_id(&entry_id)?,
                        tag,
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;
        self.with_session(|s| Ok(s.write(edits)?))
    }

    pub fn devices(&self) -> Result<Vec<DeviceInfo>> {
        self.with_session(|s| {
            let suspects = s.review().suspect_devices;
            let me = s.client_id();
            Ok(s.view()
                .devices
                .iter()
                .map(|(id, d)| DeviceInfo {
                    client_id: hex::encode(id),
                    name: d.name.to_string(),
                    this_device: *id == me,
                    retired: d.retired_after.is_some(),
                    suspect: suspects.contains(id),
                })
                .collect())
        })
    }

    pub fn rename_device(&self, name: String) -> Result<()> {
        self.with_session(|s| Ok(s.write(vec![Edit::SetDeviceName { name }])?))
    }

    /// A password change rotates the vault key (spec §7.2). Other devices unlock
    /// with the new password once.
    pub fn change_password(&self, new_password: Vec<u8>) -> Result<RotationSummary> {
        let new_password = Zeroizing::new(new_password);
        self.with_session(|s| {
            let rotated = s.change_password(&new_password)?;
            self.refresh_local_slots(s)?;
            Ok((&rotated).into())
        })
    }

    /// Returns the new recovery words; the old ones stop working.
    pub fn replace_recovery_key(&self, password: Vec<u8>) -> Result<Vec<u8>> {
        let password = Zeroizing::new(password);
        self.with_session(|s| {
            let words = s.replace_recovery_key(&password)?;
            self.refresh_local_slots(s)?;
            Ok(words.expose().to_vec())
        })
    }

    /// Retires the device and rotates the key so it can't read anything new.
    pub fn revoke_device(&self, client_id: String, password: Vec<u8>) -> Result<RotationSummary> {
        let password = Zeroizing::new(password);
        let id = parse_id(&client_id)?;
        self.with_session(|s| {
            let rotated = s.revoke_device(id, &password)?;
            self.refresh_local_slots(s)?;
            Ok((&rotated).into())
        })
    }

    /// After `lost_rotation`: switches to the winning device's key with its password.
    pub fn rejoin_password(&self, password: Vec<u8>) -> Result<()> {
        let password = Zeroizing::new(password);
        self.rejoin_with(Credential::Password(&password))
    }

    pub fn rejoin_recovery(&self, words: Vec<u8>) -> Result<()> {
        let words = Zeroizing::new(words);
        self.rejoin_with(Credential::RecoveryWords(&words))
    }

    /// Removes an entry for good (spec §10.4). Rotates the key.
    pub fn purge(&self, entry_id: String, password: Vec<u8>) -> Result<PurgeSummary> {
        let password = Zeroizing::new(password);
        let id = parse_id(&entry_id)?;
        self.with_session(|s| {
            let purged = s.purge(id, &password)?;
            self.refresh_local_slots(s)?;
            Ok((&purged).into())
        })
    }

    /// Reverts every change flagged for review; returns how many edits that took.
    pub fn revert_flagged(&self) -> Result<u32> {
        self.with_session(|s| Ok(count(s.revert_flagged()?)))
    }
}

/// Unlocking with a platform protector (spec §11). These await the protector, which
/// may show a prompt, without holding the session.
#[uniffi::export]
impl Vault {
    /// The protectors with a local slot that can unlock this device (`protector_id`s,
    /// spec §11). Works while locked, for the unlock screen.
    pub fn local_unlocks(&self) -> Result<Vec<u8>> {
        let mut ids: Vec<u8> = local_slots(&*self.store, &*self.local)?
            .into_iter()
            .map(|s| s.protector_id)
            .collect();
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    /// Unlocks with `protector`'s local slot, then syncs. If the platform key was
    /// invalidated, fails with `KeyInvalidated`; the slot goes at the next unlock.
    pub async fn unlock_local(
        &self,
        protector: Arc<dyn PlatformProtector>,
        protector_id: u8,
    ) -> Result<SyncSummary> {
        let slot = local_slots(&*self.store, &*self.local)?
            .into_iter()
            .filter(|s| s.protector_id == protector_id)
            .max_by_key(|s| s.epoch)
            .ok_or_else(|| not_found("device unlock"))?;
        let unwrapped = match protector.unwrap(hex::encode(slot.slot_id), slot.blob).await {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(ProtectorError::KeyInvalidated) => return Err(self.invalidate(protector_id)),
            Err(e) => return Err(e.into()),
        };
        let Ok(secret) = SecretKey::from_slice(&unwrapped) else {
            return Err(self.invalidate(protector_id));
        };
        match self.unlock_with(Credential::LocalSlot {
            slot_id: slot.slot_id,
            secret: &secret,
        }) {
            Ok(summary) => {
                self.remember_secret(slot.slot_id, secret);
                Ok(summary)
            }
            // The protector returned something that opens nothing: as good as gone.
            Err(VaultError::WrongCredential) => Err(self.invalidate(protector_id)),
            Err(e) => Err(e),
        }
    }

    /// Adds (or replaces) this device's local slot for `protector`. Needs the vault
    /// unlocked. The core checks the protector against the slot policy (spec §6.2).
    pub async fn enable_local_unlock(
        &self,
        protector: Arc<dyn PlatformProtector>,
        protector_id: u8,
    ) -> Result<()> {
        let caps = protector.capabilities();
        check_platform_policy(&caps).map_err(CoreError::from)?;
        if self.is_locked() {
            return Err(VaultError::Locked);
        }
        let slot_id = random_id()?;
        let secret = SecretKey::generate()?;
        let blob = protector
            .wrap(hex::encode(slot_id), secret.expose().to_vec())
            .await?;
        self.with_session(|s| {
            Ok(s.add_local_slot(slot_id, protector_id, blob, &secret, &caps)?)
        })?;
        self.remember_secret(slot_id, secret);
        Ok(())
    }

    /// Removes this device's local slots for `protector_id`.
    pub fn disable_local_unlock(&self, protector_id: u8) -> Result<()> {
        self.with_session(|s| Ok(s.remove_local_slots(protector_id)?))
    }
}

impl Vault {
    fn invalidate(&self, protector_id: u8) -> VaultError {
        lock(&self.invalidated).push(protector_id);
        VaultError::KeyInvalidated
    }
}

/// Syncs, then snapshots and collects garbage when the session may write.
/// An alarm becomes part of the summary instead of an error.
fn sync_and_maintain(session: &mut FfiSession) -> Result<SyncSummary> {
    let report = match session.sync() {
        Ok(report) => report,
        Err(CoreError::Alarm(kind)) => return Ok(SyncSummary::alarmed(kind)),
        Err(e) => return Err(e.into()),
    };
    let mut summary = SyncSummary::from_report(&report);
    // An alarm raised by an earlier sync stays in force even if this one found nothing.
    summary.alarm = session.alarm();
    if report.key_rotated || report.lost_rotation {
        return Ok(summary);
    }
    let maintenance = (|| -> Result<(), CoreError> {
        if session.snapshot_due() {
            session.write_snapshot()?;
            summary.snapshot_written = true;
        }
        let gc = session.collect_garbage(GC_GRACE_MS)?;
        summary.files_deleted = count(gc.events_deleted + gc.snapshots_deleted);
        Ok(())
    })();
    match maintenance {
        Ok(()) => {}
        // Another device rotated in the meantime: the next unlock catches up.
        Err(CoreError::KeyRotated) => summary.key_rotated = true,
        Err(CoreError::Alarm(kind)) => summary.alarm = Some(kind),
        Err(e) => return Err(e.into()),
    }
    Ok(summary)
}

fn parse_id(hex_id: &str) -> Result<Id> {
    hex::decode(hex_id)
        .ok()
        .and_then(|bytes| Id::try_from(bytes.as_slice()).ok())
        .ok_or(VaultError::Rejected {
            what: "id".into(),
            why: "not 32 hex digits".into(),
        })
}

fn not_found(what: &str) -> VaultError {
    VaultError::NotFound { what: what.into() }
}

/// A non-secret field's value as text.
fn plain_value(entry: &EntryView<'_>, name: &str) -> Option<String> {
    match entry.fields.get(name)? {
        Field::Value {
            value,
            secret: false,
            ..
        } => Some(text(value)),
        _ => None,
    }
}

/// Only ever called on non-secret values.
fn text(value: &SecretBytes) -> String {
    String::from_utf8_lossy(value.expose()).into_owned()
}

fn tags(entry: &EntryView<'_>) -> Vec<String> {
    entry.tags.iter().map(|t| t.to_string()).collect()
}

/// Counts cross as `u32`; a vault never comes near the limit.
fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests;
