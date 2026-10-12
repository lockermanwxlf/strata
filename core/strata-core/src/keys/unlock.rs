//! Unlocking (spec §6.3, §6.2.1): from a password or the recovery words to a
//! verified keyring, with key-ID pinning, the chain walk and the recovery anchor.

use std::cmp::Reverse;

use subtle::ConstantTimeEq;

use super::{Keyring, VaultFiles};
use crate::crypto::kdf;
use crate::crypto::random_id;
use crate::crypto::recovery::{self, RecoveryKeyPair};
use crate::crypto::sign::DeviceKey;
use crate::error::{AlarmKind, CoreError, Result};
use crate::format::Id;
use crate::format::epoch::EpochRecord;
use crate::format::slot::{SlotFile, SlotParams};
use crate::local::{LocalState, LocalStore, Pin, SealedLocalState, StateRecord};
use crate::sync::RemoteStore;

/// How many slots of the chosen kind unlock tries, newest first. Every password slot
/// costs a full Argon2 run, so this stops planted slots from making unlock
/// arbitrarily slow (spec §6.3 step 2).
pub const MAX_SLOTS_TRIED: usize = 8;

pub enum Credential<'a> {
    /// UTF-8 password bytes.
    Password(&'a [u8]),
    /// The 24 recovery words as typed, UTF-8.
    RecoveryWords(&'a [u8]),
}

pub struct Unlocked {
    pub vault_id: Id,
    pub keyring: Keyring,
    pub state: LocalState,
    /// This device had no local state for the vault, so it joined as a new client
    /// and pinned on trust (spec §6.3 step 5).
    pub new_client: bool,
    /// The vault has an epoch newer than the keyring's that this credential's slots
    /// don't reach, typically after a rotation that dropped the slot.
    pub newer_epoch_unreachable: bool,
    /// Files that failed to parse and were set aside.
    pub rejected_files: Vec<(String, CoreError)>,
    /// The raw epoch records. The sync session needs their cutover vectors and
    /// checks their signatures once their creators' keys are known.
    pub epoch_files: Vec<Vec<u8>>,
}

pub fn unlock(
    store: &dyn RemoteStore,
    local: &dyn LocalStore,
    credential: Credential<'_>,
) -> Result<Unlocked> {
    let mut files = VaultFiles::load(store)?;
    let vault_id = files.vault_id;
    let mut rejected = std::mem::take(&mut files.rejected);
    let records = files.epoch_records(&mut rejected)?;
    let slots = files.slots(&mut rejected)?;

    let local_bytes = local.load(&vault_id)?;
    let sealed = local_bytes
        .as_deref()
        .map(SealedLocalState::parse)
        .transpose()?;
    if sealed.as_ref().is_some_and(|s| s.vault_id != vault_id) {
        return Err(CoreError::rejected(
            "local state",
            "belongs to a different vault",
        ));
    }
    let pin = sealed.as_ref().map(|s| s.pin);
    if let Some(pin) = pin {
        check_records_against_pin(&records, &pin)?;
    }

    // Slots below the pinned epoch are stale (spec §6.3 step 4) and never tried.
    let min_epoch = pin.map_or(0, |p| p.epoch);
    let keyring = match credential {
        Credential::Password(password) => {
            open_password(&vault_id, &records, &slots, password, min_epoch)?
        }
        Credential::RecoveryWords(words) => {
            open_recovery(&vault_id, &records, &slots, words, min_epoch)?
        }
    };
    if let Some(pin) = pin {
        let reached = keyring.keys(pin.epoch).map(|k| k.key_id);
        if !reached.is_some_and(|id| bool::from(id.ct_eq(&pin.key_id))) {
            return Err(CoreError::Alarm(AlarmKind::SlotSubstitution));
        }
    }

    let (mut state, new_client) = match sealed {
        Some(sealed) => {
            let pin_keys = keyring
                .keys(sealed.pin.epoch)
                .expect("pin epoch verified above");
            (sealed.open(&pin_keys.local_state)?, false)
        }
        None => (new_client_state(vault_id)?, true),
    };
    // Pin the newest verified epoch (spec §6.3 step 7).
    let current = keyring.current_keys();
    state.pin = Pin {
        epoch: keyring.current(),
        key_id: current.key_id,
    };
    local.save(&vault_id, &state.seal(current)?)?;

    let newer_epoch_unreachable = records.iter().any(|r| r.epoch > keyring.current());
    drop(records);
    drop(slots);
    Ok(Unlocked {
        vault_id,
        newer_epoch_unreachable,
        keyring,
        state,
        new_client,
        rejected_files: rejected,
        epoch_files: files.epochs.into_iter().map(|(_, bytes)| bytes).collect(),
    })
}

/// Before any slot is tried: the pinned epoch's record must still be there, with
/// the pinned key ID. Epoch records are never deleted, so a missing one means the
/// storage went back in time; a different one means a key was substituted.
fn check_records_against_pin(records: &[EpochRecord<'_>], pin: &Pin) -> Result<()> {
    let at_pin: Vec<_> = records.iter().filter(|r| r.epoch == pin.epoch).collect();
    if at_pin.is_empty() {
        return Err(CoreError::Alarm(AlarmKind::Rollback));
    }
    if !at_pin
        .iter()
        .any(|r| bool::from(r.key_id.ct_eq(&pin.key_id)))
    {
        return Err(CoreError::Alarm(AlarmKind::SlotSubstitution));
    }
    Ok(())
}

fn open_password(
    vault_id: &Id,
    records: &[EpochRecord<'_>],
    slots: &[SlotFile<'_>],
    password: &[u8],
    min_epoch: u32,
) -> Result<Keyring> {
    let mut candidates: Vec<_> = slots
        .iter()
        .filter(|s| {
            matches!(s.params, SlotParams::Password { .. })
                && s.epoch >= min_epoch
                && has_record(records, s.epoch)
        })
        .collect();
    candidates.sort_by_key(|s| Reverse(s.epoch));
    candidates.truncate(MAX_SLOTS_TRIED);

    let mut inconsistent = None;
    for slot in candidates {
        let SlotParams::Password { argon, salt } = &slot.params else {
            unreachable!("filtered to password slots");
        };
        let slot_secret = kdf::password_slot_secret(password, salt, *argon)?;
        let kek = kdf::slot_kek(vault_id, &slot.slot_id, &slot_secret);
        let Ok(ek) = slot.open_with_kek(&kek) else {
            continue;
        };
        match Keyring::walk(vault_id, records, slot.epoch, ek) {
            Ok(keyring) => return Ok(keyring),
            Err(e) => inconsistent = Some(e),
        }
    }
    Err(inconsistent.unwrap_or(CoreError::WrongCredential))
}

fn open_recovery(
    vault_id: &Id,
    records: &[EpochRecord<'_>],
    slots: &[SlotFile<'_>],
    words: &[u8],
    min_epoch: u32,
) -> Result<Keyring> {
    let r = recovery::from_words(words)?;
    let keypair = RecoveryKeyPair::derive(&r);
    let mut candidates: Vec<_> = slots
        .iter()
        .filter(|s| {
            s.epoch >= min_epoch
                && has_record(records, s.epoch)
                && matches!(&s.params, SlotParams::Recovery { pk, .. }
                    if pk.as_slice() == keypair.public_key())
        })
        .collect();
    candidates.sort_by_key(|s| Reverse(s.epoch));
    candidates.truncate(MAX_SLOTS_TRIED);

    let mut inconsistent = None;
    for slot in candidates {
        let Ok(ek) = slot.open_recovery(&keypair) else {
            continue;
        };
        let keyring = match Keyring::walk(vault_id, records, slot.epoch, ek) {
            Ok(keyring) => keyring,
            Err(e) => {
                inconsistent = Some(e);
                continue;
            }
        };
        // Anyone can seal a key to the public key, so the anchor is what proves this
        // chain is the one the recovery key was made for (spec §6.2.1).
        let SlotParams::Recovery {
            pk,
            anchor_epoch,
            anchor_tag,
        } = &slot.params
        else {
            unreachable!("filtered to recovery slots");
        };
        let anchored = keyring.keys(*anchor_epoch).is_some_and(|k| {
            recovery::verify_anchor(
                &r,
                vault_id,
                *anchor_epoch,
                &k.key_id,
                pk.as_slice(),
                anchor_tag,
            )
        });
        if !anchored {
            return Err(CoreError::Alarm(AlarmKind::SlotSubstitution));
        }
        return Ok(keyring);
    }
    Err(inconsistent.unwrap_or(CoreError::WrongCredential))
}

/// Only slots whose epoch has a record are worth an attempt: a slot claiming some
/// epoch nobody created can't pass the key-ID check, and trying it first would
/// let planted slots crowd the real one out of `MAX_SLOTS_TRIED`.
fn has_record(records: &[EpochRecord<'_>], epoch: u32) -> bool {
    records.iter().any(|r| r.epoch == epoch)
}

/// A device unlocking a vault for the first time becomes a new client with its own
/// device key. Its first event will register it (spec §6.4).
fn new_client_state(vault_id: Id) -> Result<LocalState> {
    Ok(LocalState {
        vault_id,
        client_id: random_id()?,
        pin: Pin {
            epoch: 0,
            key_id: [0; 32],
        },
        local_slots: Vec::new(),
        record: StateRecord {
            device_seed: DeviceKey::generate()?.seed(),
            next_seq: 1,
            high_water: Vec::new(),
            pending: Vec::new(),
            snapshots: Vec::new(),
        },
    })
}

#[cfg(test)]
mod tests;
