//! Unlock tests (spec §6.3, §6.2.1, §14.3 "swapped slots"). Each attack is staged
//! the way an attacker who controls the storage could stage it.

use super::*;
use crate::crypto::SecretKey;
use crate::crypto::kdf::{Argon2Params, EpochKeys};
use crate::format::body::VectorClock;
use crate::format::epoch::{ChainWrap, NewEpoch};
use crate::format::names::FileName;
use crate::format::slot::{self as slot_format, KIND_PASSWORD, KIND_RECOVERY};
use crate::keys::create::{NewVault, create_vault};
use crate::local::MemoryLocalStore;
use crate::policy::SlotScope;
use crate::sync::MemoryStore;

const PASSWORD: &[u8] = b"correct horse battery staple";

fn new_vault_with(password: &[u8]) -> (MemoryStore, MemoryLocalStore, NewVault) {
    let store = MemoryStore::new();
    let local = MemoryLocalStore::new();
    let vault = create_vault(&store, &local, password, "Laptop").unwrap();
    (store, local, vault)
}

fn new_vault() -> (MemoryStore, MemoryLocalStore, NewVault) {
    new_vault_with(PASSWORD)
}

fn with_password(
    store: &MemoryStore,
    local: &MemoryLocalStore,
    password: &[u8],
) -> Result<Unlocked> {
    unlock(store, local, Credential::Password(password))
}

fn with_words(store: &MemoryStore, local: &MemoryLocalStore, vault: &NewVault) -> Result<Unlocked> {
    unlock(
        store,
        local,
        Credential::RecoveryWords(vault.recovery_words.expose()),
    )
}

fn alarm(result: Result<Unlocked>) -> AlarmKind {
    match result {
        Err(CoreError::Alarm(kind)) => kind,
        Err(e) => panic!("expected an alarm, got {e:?}"),
        Ok(_) => panic!("expected an alarm, but the vault unlocked"),
    }
}

fn is_wrong_credential(result: Result<Unlocked>) -> bool {
    matches!(result, Err(CoreError::WrongCredential))
}

/// Paths of the synced slots of one kind.
fn slot_paths(store: &MemoryStore, vault_id: &Id, kind: u8) -> Vec<String> {
    store
        .paths_in("slots")
        .into_iter()
        .filter(|p| {
            let bytes = store.get(p).unwrap();
            SlotFile::parse(&bytes, vault_id, SlotScope::Synced)
                .is_ok_and(|s| s.params.kind() == kind)
        })
        .collect()
}

fn password_slot(vault_id: &Id, epoch: u32, password: &[u8], ek: &SecretKey) -> (String, Vec<u8>) {
    let slot_id = random_id().unwrap();
    let salt = [7; 16];
    let secret = kdf::password_slot_secret(password, &salt, Argon2Params::DEFAULT).unwrap();
    let bytes = slot_format::seal_with_kek(
        vault_id,
        &slot_id,
        epoch,
        &SlotParams::Password {
            argon: Argon2Params::DEFAULT,
            salt,
        },
        &kdf::slot_kek(vault_id, &slot_id, &secret),
        ek,
    )
    .unwrap();
    (FileName::Slot { slot_id }.to_path(), bytes)
}

fn epoch_record(
    vault_id: &Id,
    epoch: u32,
    creator: Id,
    ek: &SecretKey,
    previous: Option<&SecretKey>,
) -> (String, Vec<u8>) {
    let keys = EpochKeys::derive(vault_id, ek);
    let cutover = if epoch == 0 {
        VectorClock::default()
    } else {
        VectorClock(vec![(creator, 1)])
    };
    let bytes = NewEpoch {
        vault_id: *vault_id,
        epoch,
        creator,
        key_id: keys.key_id,
        recovery_pk_hash: [0; 32],
        cutover: &cutover,
        chain: previous.map(|prev| ChainWrap {
            chain_key: &keys.chain,
            prev_epoch_key: prev,
            nonce: None,
        }),
    }
    .seal(&DeviceKey::generate().unwrap())
    .unwrap();
    (FileName::Epoch { epoch, creator }.to_path(), bytes)
}

/// Rotates to epoch 1 the way rotation will (spec §7.2): a new epoch key chained to
/// EK0, a new password slot, and (if `rewrap_recovery`) the recovery slot re-wrapped
/// with its anchor unchanged. The old password slot is removed; the old recovery slot
/// is removed only when it was re-wrapped.
fn rotate(store: &MemoryStore, unlocked: &Unlocked, new_password: &[u8], rewrap_recovery: bool) {
    let vault_id = unlocked.vault_id;
    let ek1 = SecretKey::generate().unwrap();
    let (path, bytes) = epoch_record(
        &vault_id,
        1,
        unlocked.state.client_id,
        &ek1,
        Some(unlocked.keyring.epoch_key(0).unwrap()),
    );
    store.put(&path, bytes);

    let old_password = slot_paths(store, &vault_id, KIND_PASSWORD);
    let old_recovery = slot_paths(store, &vault_id, KIND_RECOVERY);
    let (path, bytes) = password_slot(&vault_id, 1, new_password, &ek1);
    store.put(&path, bytes);
    for path in old_password {
        store.remove(&path);
    }
    if rewrap_recovery {
        for path in old_recovery {
            let bytes = store.remove(&path).unwrap();
            let params = SlotFile::parse(&bytes, &vault_id, SlotScope::Synced)
                .unwrap()
                .params
                .clone();
            let slot_id = random_id().unwrap();
            let rewrapped =
                slot_format::seal_recovery(&vault_id, &slot_id, 1, &params, &ek1, None).unwrap();
            store.put(&FileName::Slot { slot_id }.to_path(), rewrapped);
        }
    }
}

#[test]
fn create_then_unlock_on_the_same_device() {
    let (store, local, vault) = new_vault();
    let unlocked = with_password(&store, &local, PASSWORD).unwrap();
    assert!(!unlocked.new_client);
    assert_eq!(unlocked.state.client_id, vault.client_id);
    assert_eq!(unlocked.keyring.current(), 0);
    assert_eq!(unlocked.state.record.next_seq, 2);
    assert!(unlocked.rejected_files.is_empty());
    assert!(!unlocked.newer_epoch_unreachable);

    assert!(is_wrong_credential(with_password(
        &store,
        &local,
        b"wrong password"
    )));
    assert!(
        create_vault(&store, &local, PASSWORD, "Laptop").is_err(),
        "vault exists"
    );
}

#[test]
fn recovery_words_unlock_a_fresh_device() {
    let (store, _, vault) = new_vault();
    let fresh = MemoryLocalStore::new();
    let unlocked = with_words(&store, &fresh, &vault).unwrap();
    assert!(unlocked.new_client);
    assert_ne!(unlocked.state.client_id, vault.client_id);

    assert!(matches!(
        unlock(
            &store,
            &fresh,
            Credential::RecoveryWords(b"abandon ability")
        ),
        Err(CoreError::RecoveryWords(_))
    ));
    let (_, _, other) = new_vault_with(b"another vault's password");
    assert!(is_wrong_credential(with_words(&store, &fresh, &other)));
}

#[test]
fn a_fresh_device_pins_once_and_keeps_its_identity() {
    let (store, _, _) = new_vault();
    let fresh = MemoryLocalStore::new();
    let first = with_password(&store, &fresh, PASSWORD).unwrap();
    assert!(first.new_client);
    assert_eq!(first.state.record.next_seq, 1);
    let second = with_password(&store, &fresh, PASSWORD).unwrap();
    assert!(!second.new_client);
    assert_eq!(second.state.client_id, first.state.client_id);
    assert_eq!(second.state.pin, first.state.pin);
}

#[test]
fn slots_copied_from_another_vault_are_set_aside() {
    let (a, a_local, _) = new_vault();
    let (b, _, _) = new_vault_with(b"vault B's password");
    for path in b.paths_in("slots") {
        a.put(&path, b.get(&path).unwrap());
    }
    let unlocked = with_password(&a, &a_local, PASSWORD).unwrap();
    assert_eq!(
        unlocked.rejected_files.len(),
        2,
        "B's password and recovery slots"
    );
    assert!(is_wrong_credential(with_password(
        &a,
        &a_local,
        b"vault B's password"
    )));
}

#[test]
fn moved_slots_dont_open() {
    let (store, local, vault) = new_vault();
    let path = slot_paths(&store, &vault.vault_id, KIND_PASSWORD).remove(0);
    let original = store.get(&path).unwrap();

    // Renamed to another slot ID: the name no longer matches the contents.
    store.remove(&path);
    store.put(
        &FileName::Slot { slot_id: [9; 16] }.to_path(),
        original.clone(),
    );
    assert!(is_wrong_credential(with_password(&store, &local, PASSWORD)));
    store.remove(&FileName::Slot { slot_id: [9; 16] }.to_path());

    // Moved to another epoch: the epoch is part of the associated data.
    let mut other_epoch = original.clone();
    other_epoch[40] ^= 1;
    store.put(&path, other_epoch);
    assert!(is_wrong_credential(with_password(&store, &local, PASSWORD)));

    store.put(&path, original);
    with_password(&store, &local, PASSWORD).unwrap();
}

#[test]
fn a_substituted_key_raises_an_alarm_on_a_pinned_device() {
    let (store, local, vault) = new_vault();
    // Someone who knows the password (or partitions the AEAD) plants an epoch-0 record
    // for a key they chose, and a password slot that opens to it.
    let fake_ek = SecretKey::generate().unwrap();
    let (path, bytes) = epoch_record(&vault.vault_id, 0, [0xee; 16], &fake_ek, None);
    store.put(&path, bytes);
    for path in slot_paths(&store, &vault.vault_id, KIND_PASSWORD) {
        store.remove(&path);
    }
    let (path, bytes) = password_slot(&vault.vault_id, 0, PASSWORD, &fake_ek);
    store.put(&path, bytes);
    assert_eq!(
        alarm(with_password(&store, &local, PASSWORD)),
        AlarmKind::SlotSubstitution
    );

    // Replacing the real epoch-0 record outright is caught before any slot is tried.
    store.remove(
        &FileName::Epoch {
            epoch: 0,
            creator: vault.client_id,
        }
        .to_path(),
    );
    assert_eq!(
        alarm(with_password(&store, &local, PASSWORD)),
        AlarmKind::SlotSubstitution
    );

    // A fresh device has nothing to compare against: trust on first use (spec §1).
    assert!(with_password(&store, &MemoryLocalStore::new(), PASSWORD).is_ok());
}

#[test]
fn a_fabricated_vault_doesnt_open_with_the_real_recovery_key() {
    let (store, _, vault) = new_vault();
    // The vault ID and the recovery public key are cleartext, so an attacker can seal a
    // key of their own to the real recovery key. They can't make a matching anchor.
    let recovery_path = slot_paths(&store, &vault.vault_id, KIND_RECOVERY).remove(0);
    let recovery_bytes = store.get(&recovery_path).unwrap();
    let real_params = SlotFile::parse(&recovery_bytes, &vault.vault_id, SlotScope::Synced)
        .unwrap()
        .params
        .clone();

    let fake = MemoryStore::new();
    fake.put("strata-vault", store.get("strata-vault").unwrap());
    let fake_ek = SecretKey::generate().unwrap();
    let (path, bytes) = epoch_record(&vault.vault_id, 0, [0xee; 16], &fake_ek, None);
    fake.put(&path, bytes);
    let slot_id = random_id().unwrap();
    fake.put(
        &FileName::Slot { slot_id }.to_path(),
        slot_format::seal_recovery(&vault.vault_id, &slot_id, 0, &real_params, &fake_ek, None)
            .unwrap(),
    );

    let fresh = MemoryLocalStore::new();
    assert_eq!(
        alarm(with_words(&fake, &fresh, &vault)),
        AlarmKind::SlotSubstitution
    );
    assert!(
        fresh.load(&vault.vault_id).unwrap().is_none(),
        "nothing was pinned"
    );
}

#[test]
fn an_altered_anchor_doesnt_open() {
    let (store, local, vault) = new_vault();
    let path = slot_paths(&store, &vault.vault_id, KIND_RECOVERY).remove(0);
    let mut bytes = store.get(&path).unwrap();
    // params start at 47: pk[1216], anchor_epoch[4], anchor_tag[32]
    bytes[47 + 1216 + 4] ^= 1;
    store.put(&path, bytes);
    assert!(is_wrong_credential(with_words(&store, &local, &vault)));
}

#[test]
fn rotation_is_followed_through_the_chain() {
    let (store, local, vault) = new_vault();
    let before = with_password(&store, &local, PASSWORD).unwrap();
    rotate(&store, &before, b"a brand new password", true);

    assert!(is_wrong_credential(with_password(&store, &local, PASSWORD)));
    let after = with_password(&store, &local, b"a brand new password").unwrap();
    assert_eq!(after.keyring.current(), 1);
    assert!(
        after.keyring.keys(0).is_some(),
        "older epochs come through the chain"
    );
    assert_eq!(after.state.pin.epoch, 1, "the pin moved forward");
    assert_eq!(after.state.client_id, vault.client_id);

    // The recovery slot was re-wrapped without the recovery key, and its anchor (made
    // at epoch 0) still verifies through the chain on a fresh device.
    let fresh = with_words(&store, &MemoryLocalStore::new(), &vault).unwrap();
    assert_eq!(fresh.keyring.current(), 1);
}

#[test]
fn stale_slots_are_ignored_and_a_missing_epoch_is_a_rollback() {
    let (store, local, vault) = new_vault();
    let old_slot_path = slot_paths(&store, &vault.vault_id, KIND_PASSWORD).remove(0);
    let old_slot = store.get(&old_slot_path).unwrap();
    let before = with_password(&store, &local, PASSWORD).unwrap();
    rotate(&store, &before, b"a brand new password", true);
    with_password(&store, &local, b"a brand new password").unwrap(); // pins epoch 1

    // Replaying the old password slot and hiding the new one: the old slot is below
    // the pinned epoch, so it's never tried.
    store.put(&old_slot_path, old_slot);
    for path in slot_paths(&store, &vault.vault_id, KIND_PASSWORD) {
        if path != old_slot_path {
            store.remove(&path);
        }
    }
    assert!(is_wrong_credential(with_password(&store, &local, PASSWORD)));

    // Hiding the epoch-1 record as well puts the storage back before the pin.
    store.remove(
        &FileName::Epoch {
            epoch: 1,
            creator: vault.client_id,
        }
        .to_path(),
    );
    assert_eq!(
        alarm(with_password(&store, &local, PASSWORD)),
        AlarmKind::Rollback
    );
}

#[test]
fn a_slot_left_behind_by_rotation_reports_the_newer_epoch() {
    let (store, local, vault) = new_vault();
    let before = with_password(&store, &local, PASSWORD).unwrap();
    rotate(&store, &before, b"a brand new password", false);
    let unlocked = with_words(&store, &MemoryLocalStore::new(), &vault).unwrap();
    assert_eq!(unlocked.keyring.current(), 0);
    assert!(unlocked.newer_epoch_unreachable);
}

#[test]
fn tampered_local_state_is_rejected() {
    let (store, local, vault) = new_vault();
    let mut bytes = local.load(&vault.vault_id).unwrap().unwrap();
    bytes[44] ^= 1; // the pinned key ID
    local.save(&vault.vault_id, &bytes).unwrap();
    assert!(with_password(&store, &local, PASSWORD).is_err());
}

#[test]
fn a_newer_format_is_update_required() {
    let (store, local, _) = new_vault();
    let mut info = store.get("strata-vault").unwrap();
    info[4] = 2;
    store.put("strata-vault", info);
    assert!(matches!(
        with_password(&store, &local, PASSWORD),
        Err(CoreError::UpdateRequired { found: 2 })
    ));
}

#[test]
fn oversized_files_are_set_aside_unread() {
    let (store, local, _) = new_vault();
    store.put(
        &FileName::Slot { slot_id: [9; 16] }.to_path(),
        vec![0; slot_format::MAX_FILE_LEN + 1],
    );
    let unlocked = with_password(&store, &local, PASSWORD).unwrap();
    assert_eq!(unlocked.rejected_files.len(), 1);
}

#[test]
fn a_planted_copy_of_an_epoch_record_cant_hide_the_real_one() {
    let (store, local, vault) = new_vault();
    let before = with_password(&store, &local, PASSWORD).unwrap();
    rotate(&store, &before, b"a brand new password", true);
    // Copy the real epoch-1 record (public key ID and all) under a creator that sorts
    // first. Changing the creator changes the chain wrap's associated data, so its
    // wrap no longer opens: it's a decoy.
    let real = FileName::Epoch {
        epoch: 1,
        creator: vault.client_id,
    }
    .to_path();
    let mut decoy = store.get(&real).unwrap();
    decoy[28..44].copy_from_slice(&[0; 16]);
    store.put(
        &FileName::Epoch {
            epoch: 1,
            creator: [0; 16],
        }
        .to_path(),
        decoy,
    );

    let unlocked = with_password(&store, &local, b"a brand new password").unwrap();
    assert_eq!(unlocked.keyring.current(), 1);
    with_words(&store, &MemoryLocalStore::new(), &vault).unwrap();
}
