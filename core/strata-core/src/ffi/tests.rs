//! The FFI surface end to end, on real directories: what Kotlin will see.

use super::*;

const PASSWORD: &[u8] = b"correct horse battery staple";

struct Dirs {
    vault: tempfile::TempDir,
    states: tempfile::TempDir,
}

impl Dirs {
    fn new() -> Self {
        Self {
            vault: tempfile::tempdir().unwrap(),
            states: tempfile::tempdir().unwrap(),
        }
    }

    fn vault(&self) -> String {
        self.vault.path().to_str().unwrap().into()
    }

    /// Each device keeps its local state in its own directory.
    fn state(&self, device: &str) -> String {
        self.states.path().join(device).to_str().unwrap().into()
    }

    fn create(&self) -> NewVault {
        create_vault(
            self.vault(),
            self.state("laptop"),
            PASSWORD.to_vec(),
            "Laptop".into(),
        )
        .unwrap()
    }

    fn open(&self, device: &str) -> Arc<Vault> {
        let vault = Vault::open(self.vault(), self.state(device), device.into()).unwrap();
        vault.unlock_password(PASSWORD.to_vec()).unwrap();
        vault
    }
}

fn set(entry_id: &str, name: &str, value: &[u8]) -> EntryEdit {
    EntryEdit::SetField {
        entry_id: entry_id.into(),
        name: name.into(),
        value: Some(value.to_vec()),
        secret: false,
    }
}

#[test]
fn create_edit_and_read_back() {
    let dirs = Dirs::new();
    let created = dirs.create();
    assert_eq!(
        String::from_utf8(created.recovery_words.clone())
            .unwrap()
            .split_whitespace()
            .count(),
        24
    );
    let vault = created.vault;
    assert!(!vault.is_locked());
    let id = new_entry_id().unwrap();
    vault
        .apply(vec![
            set(&id, "title", b"Bank"),
            set(&id, "username", b"me"),
            set(&id, "password", b"hunter2"),
            EntryEdit::AddTag {
                entry_id: id.clone(),
                tag: "money".into(),
            },
        ])
        .unwrap();

    let entries = vault.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].title.as_deref(), Some("Bank"));
    assert_eq!(entries[0].username.as_deref(), Some("me"));
    assert_eq!(entries[0].tags, vec!["money".to_string()]);

    // The detail shows the password as secret, with no value; reveal hands it out.
    let detail = vault.entry(id.clone()).unwrap();
    let password = detail.fields.iter().find(|f| f.name == "password").unwrap();
    assert!(password.secret && password.value.is_none());
    assert_eq!(
        vault.reveal(id.clone(), "password".into()).unwrap(),
        b"hunter2"
    );
    assert!(matches!(
        vault.reveal(id.clone(), "nope".into()),
        Err(VaultError::NotFound { .. })
    ));

    vault.lock();
    assert!(vault.is_locked() && vault.status().locked);
    assert!(matches!(vault.entries(), Err(VaultError::Locked)));
    assert!(matches!(
        vault.unlock_password(b"wrong".to_vec()),
        Err(VaultError::WrongCredential)
    ));
    vault.unlock_password(PASSWORD.to_vec()).unwrap();
    assert_eq!(vault.entries().unwrap().len(), 1);
}

#[test]
fn two_devices_sync_and_see_conflicts() {
    let dirs = Dirs::new();
    let laptop = dirs.create().vault;
    let phone = dirs.open("phone");
    let id = new_entry_id().unwrap();
    laptop.apply(vec![set(&id, "title", b"Mail")]).unwrap();
    assert_eq!(phone.sync().unwrap().applied, 1);
    assert_eq!(phone.entries().unwrap()[0].title.as_deref(), Some("Mail"));

    // Both change the password without seeing each other: a conflict, both kept.
    laptop
        .apply(vec![set(&id, "password", b"from laptop")])
        .unwrap();
    phone
        .apply(vec![set(&id, "password", b"from phone")])
        .unwrap();
    laptop.sync().unwrap();
    let status = laptop.status();
    assert_eq!(status.conflicts, 1);
    assert!(matches!(
        laptop.reveal(id.clone(), "password".into()),
        Err(VaultError::FieldConflict)
    ));
    let mut values: Vec<Vec<u8>> = laptop
        .reveal_conflict(id.clone(), "password".into())
        .unwrap()
        .into_iter()
        .map(|c| c.value.unwrap())
        .collect();
    values.sort();
    assert_eq!(
        values,
        vec![b"from laptop".to_vec(), b"from phone".to_vec()]
    );
    assert_eq!(laptop.devices().unwrap().len(), 2);
}

#[test]
fn a_password_change_reaches_the_other_device() {
    let dirs = Dirs::new();
    let laptop = dirs.create().vault;
    let phone = dirs.open("phone");
    phone
        .apply(vec![set(&new_entry_id().unwrap(), "title", b"x")])
        .unwrap();
    laptop.sync().unwrap();
    assert_eq!(
        laptop
            .change_password(b"new password".to_vec())
            .unwrap()
            .epoch,
        1
    );

    let summary = phone.sync().unwrap();
    assert!(summary.key_rotated && phone.status().key_rotated);
    assert!(matches!(
        phone.apply(vec![set(&new_entry_id().unwrap(), "title", b"y")]),
        Err(VaultError::KeyRotated)
    ));
    phone.lock();
    assert!(matches!(
        phone.unlock_password(PASSWORD.to_vec()),
        Err(VaultError::WrongCredential)
    ));
    assert!(
        !phone
            .unlock_password(b"new password".to_vec())
            .unwrap()
            .key_rotated
    );
    phone
        .apply(vec![set(&new_entry_id().unwrap(), "title", b"y")])
        .unwrap();
}

#[test]
fn an_alarm_is_reported_not_thrown() {
    let dirs = Dirs::new();
    let laptop = dirs.create().vault;
    laptop
        .apply(vec![set(&new_entry_id().unwrap(), "title", b"x")])
        .unwrap();
    // Someone deletes the laptop's latest event from the folder.
    let events = dirs.vault.path().join("events");
    let latest = std::fs::read_dir(&events)
        .unwrap()
        .map(|e| e.unwrap().path())
        .max()
        .unwrap();
    std::fs::remove_file(latest).unwrap();
    let summary = laptop.sync().unwrap();
    assert_eq!(summary.alarm, Some(AlarmKind::Rollback));
    assert_eq!(laptop.status().alarm, Some(AlarmKind::Rollback));
    // Still readable; nothing more is written.
    assert!(laptop.entries().is_ok());
    assert!(matches!(
        laptop.apply(vec![set(&new_entry_id().unwrap(), "title", b"y")]),
        Err(VaultError::Alarm { .. })
    ));
}

#[test]
fn bad_input_is_rejected_cleanly() {
    let dirs = Dirs::new();
    assert!(Vault::open(dirs.vault(), dirs.state("x"), String::new()).is_err());
    let vault = dirs.create().vault;
    assert!(matches!(
        vault.entry("not hex".into()),
        Err(VaultError::Rejected { .. })
    ));
    assert!(password_strength(b"password".to_vec()).unwrap().warn);
    assert!(
        !password_strength(b"correct horse battery staple violin".to_vec())
            .unwrap()
            .warn
    );
}

// ---- Local slots with a fake platform protector (spec §11) ----------------------

use std::pin::pin;
use std::task::{Context, Poll, Waker};

use crate::protector::{ProtectorCaps, ProtectorError};

/// Runs a future that never waits: the fake protector answers at once.
fn ready<F: std::future::Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("the fake protector never waits"),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Normal,
    Cancel,
    Invalidated,
}

/// A stand-in for a hardware keystore: "wraps" by XOR with a key it keeps.
struct FakeProtector {
    caps: ProtectorCaps,
    key: u8,
    mode: std::sync::Mutex<Mode>,
}

const HARDWARE: ProtectorCaps = ProtectorCaps {
    hardware_backed: true,
    rate_limited: true,
    user_presence: true,
};

impl FakeProtector {
    fn new(caps: ProtectorCaps) -> Arc<Self> {
        Arc::new(Self {
            caps,
            key: 0x5a,
            mode: std::sync::Mutex::new(Mode::Normal),
        })
    }

    fn set(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }
}

#[async_trait::async_trait]
impl PlatformProtector for FakeProtector {
    fn capabilities(&self) -> ProtectorCaps {
        self.caps
    }

    async fn wrap(&self, _slot_id: String, secret: Vec<u8>) -> Result<Vec<u8>, ProtectorError> {
        Ok(secret.iter().map(|b| b ^ self.key).collect())
    }

    async fn unwrap(&self, _slot_id: String, blob: Vec<u8>) -> Result<Vec<u8>, ProtectorError> {
        match *self.mode.lock().unwrap() {
            Mode::Cancel => Err(ProtectorError::Cancelled),
            Mode::Invalidated => Err(ProtectorError::KeyInvalidated),
            Mode::Normal => Ok(blob.iter().map(|b| b ^ self.key).collect()),
        }
    }

    fn delete(&self, _slot_id: String) -> Result<(), ProtectorError> {
        Ok(())
    }
}

const FAKE: u8 = 1;

#[test]
fn a_local_slot_unlocks_and_cancel_or_invalidation_fall_back() {
    let dirs = Dirs::new();
    let vault = dirs.create().vault;
    vault
        .apply(vec![set(&new_entry_id().unwrap(), "title", b"x")])
        .unwrap();
    let protector = FakeProtector::new(HARDWARE);
    ready(vault.enable_local_unlock(protector.clone(), FAKE)).unwrap();
    assert_eq!(vault.local_unlocks().unwrap(), vec![FAKE]);

    vault.lock();
    assert_eq!(
        vault.local_unlocks().unwrap(),
        vec![FAKE],
        "visible while locked"
    );
    ready(vault.unlock_local(protector.clone(), FAKE)).unwrap();
    assert_eq!(vault.entries().unwrap().len(), 1);

    vault.lock();
    protector.set(Mode::Cancel);
    assert!(matches!(
        ready(vault.unlock_local(protector.clone(), FAKE)),
        Err(VaultError::Cancelled)
    ));
    assert!(vault.is_locked());
    assert_eq!(
        vault.local_unlocks().unwrap(),
        vec![FAKE],
        "a cancel keeps the slot"
    );

    protector.set(Mode::Invalidated);
    assert!(matches!(
        ready(vault.unlock_local(protector.clone(), FAKE)),
        Err(VaultError::KeyInvalidated)
    ));
    vault.unlock_password(PASSWORD.to_vec()).unwrap();
    assert!(
        vault.local_unlocks().unwrap().is_empty(),
        "the slot is gone after the password unlock"
    );
}

#[test]
fn the_policy_refuses_weak_protectors_without_hardware_rate_limiting() {
    let dirs = Dirs::new();
    let vault = dirs.create().vault;
    let software_pin = FakeProtector::new(ProtectorCaps {
        hardware_backed: false,
        rate_limited: false,
        user_presence: true,
    });
    assert!(matches!(
        ready(vault.enable_local_unlock(software_pin, FAKE)),
        Err(VaultError::Policy { .. })
    ));
    // Unlocked with the login session instead (Secret Service): strong, allowed.
    let session_keyring = FakeProtector::new(ProtectorCaps {
        hardware_backed: false,
        rate_limited: false,
        user_presence: false,
    });
    ready(vault.enable_local_unlock(session_keyring, FAKE)).unwrap();
}

#[test]
fn local_slots_follow_password_changes_without_another_prompt() {
    let dirs = Dirs::new();
    let laptop = dirs.create().vault;
    let phone = dirs.open("phone");
    let protector = FakeProtector::new(HARDWARE);
    ready(phone.enable_local_unlock(protector.clone(), FAKE)).unwrap();

    // Changed here: the phone still holds the slot secret from enrolling.
    phone.change_password(b"second password".to_vec()).unwrap();
    phone.lock();
    let summary = ready(phone.unlock_local(protector.clone(), FAKE)).unwrap();
    assert!(
        !summary.key_rotated,
        "the slot was re-wrapped to the new key"
    );

    // Changed on the laptop: the phone's slot opens only the old epoch, so it reads
    // and asks for the password once, then re-wraps with the secret it just used.
    laptop.lock();
    laptop.unlock_password(b"second password".to_vec()).unwrap();
    laptop.change_password(b"third password".to_vec()).unwrap();
    phone.lock();
    let summary = ready(phone.unlock_local(protector.clone(), FAKE)).unwrap();
    assert!(summary.key_rotated);
    phone.unlock_password(b"third password".to_vec()).unwrap();
    phone.lock();
    let summary = ready(phone.unlock_local(protector.clone(), FAKE)).unwrap();
    assert!(!summary.key_rotated, "back to a one-step unlock");
}

#[test]
fn without_the_secret_a_stale_slot_is_dropped() {
    let dirs = Dirs::new();
    let vault = dirs.create().vault;
    let protector = FakeProtector::new(HARDWARE);
    ready(vault.enable_local_unlock(protector, FAKE)).unwrap();
    // A password unlock holds no slot secret, so a key change can't carry the slot over.
    vault.lock();
    vault.unlock_password(PASSWORD.to_vec()).unwrap();
    vault.change_password(b"second password".to_vec()).unwrap();
    assert!(vault.local_unlocks().unwrap().is_empty());
}

/// A platform folder (as Android's SAF folder would be) over a real directory.
struct DirFolder(FsStore);

impl ForeignFolder for DirFolder {
    fn list(&self, dir: String) -> Result<Vec<String>, crate::sync::FolderError> {
        let paths = if dir.is_empty() {
            self.0.list()
        } else {
            self.0.list_dir(&dir)
        };
        Ok(paths
            .map_err(folder_error)?
            .into_iter()
            .filter_map(|p| match dir.as_str() {
                "" => (!p.contains('/')).then_some(p),
                dir => p.strip_prefix(&format!("{dir}/")).map(str::to_string),
            })
            .collect())
    }

    fn read(&self, path: String, max_len: u64) -> Result<Vec<u8>, crate::sync::FolderError> {
        self.0.read(&path, max_len as usize).map_err(folder_error)
    }

    fn create(&self, path: String, bytes: Vec<u8>) -> Result<(), crate::sync::FolderError> {
        self.0.create(&path, &bytes).map_err(folder_error)
    }

    fn delete(&self, path: String) -> Result<(), crate::sync::FolderError> {
        self.0.delete(&path).map_err(folder_error)
    }
}

fn folder_error(e: CoreError) -> crate::sync::FolderError {
    use crate::sync::FolderError;
    match e {
        CoreError::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            FolderError::AlreadyExists
        }
        CoreError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => FolderError::NotFound,
        e => FolderError::Failed {
            detail: e.to_string(),
        },
    }
}

#[test]
fn a_platform_folder_holds_the_same_vault_as_a_directory() {
    let dirs = Dirs::new();
    let folder = || Arc::new(DirFolder(FsStore::new(dirs.vault()))) as Arc<dyn ForeignFolder>;
    let created = create_vault_in_folder(
        folder(),
        dirs.state("phone"),
        PASSWORD.to_vec(),
        "Phone".into(),
    )
    .unwrap();
    let id = new_entry_id().unwrap();
    created
        .vault
        .apply(vec![set(&id, "title", b"From the phone")])
        .unwrap();

    // The laptop opens the same files as a plain directory and writes back.
    let laptop = dirs.open("laptop");
    assert_eq!(
        laptop.entries().unwrap()[0].title.as_deref(),
        Some("From the phone")
    );
    laptop.apply(vec![set(&id, "user", b"me")]).unwrap();

    let phone = Vault::open_folder(folder(), dirs.state("phone"), "Phone".into()).unwrap();
    phone.unlock_password(PASSWORD.to_vec()).unwrap();
    assert_eq!(phone.reveal(id.clone(), "user".into()).unwrap(), b"me");
}
