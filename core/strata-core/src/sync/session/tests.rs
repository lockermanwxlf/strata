//! Sync tests (spec §9.1, §9.4, §14.3): devices sharing a store, and an attacker
//! who controls that store (or holds the vault key) doing everything they can.

use std::sync::atomic::{AtomicBool, Ordering};

use proptest::prelude::*;

use super::*;
use crate::crypto::SecretBytes;
use crate::keys::create::create_vault;
use crate::keys::unlock::{Credential, unlock};
use crate::local::MemoryLocalStore;
use crate::merge::view::Field;
use crate::sync::{FsStore, MemoryStore};

const PASSWORD: &[u8] = b"correct horse battery staple";
const X: Id = [0x10; 16];
const Y: Id = [0x20; 16];

fn open<'a>(store: &'a dyn RemoteStore, local: &'a dyn LocalStore, name: &str) -> Session<'a> {
    let unlocked = unlock(store, local, Credential::Password(PASSWORD)).unwrap();
    let mut session = Session::new(store, local, unlocked, name).unwrap();
    session.sync().unwrap();
    session
}

fn set(entry: Id, name: &str, value: &str) -> Edit {
    Edit::SetField {
        entry_id: entry,
        name: name.into(),
        value: Some(SecretBytes::from_slice(value.as_bytes())),
        secret: false,
    }
}

fn field(session: &Session<'_>, entry: Id, name: &str) -> Option<String> {
    match session.view().entries.get(&entry)?.fields.get(name)? {
        Field::Value { value, .. } => Some(
            String::from_utf8(value.expose().to_vec())
                .unwrap_or_else(|e| hex::encode(e.into_bytes())),
        ),
        Field::Conflict { .. } => Some("<conflict>".into()),
    }
}

/// The whole vault as a string, values included (`Debug` redacts them).
fn contents(session: &Session<'_>) -> String {
    let view = session.view();
    let mut out = format!("{view:?}");
    for (id, entry) in &view.entries {
        for name in entry.fields.keys() {
            out += &format!("|{id:?}:{name}={:?}", field(session, *id, name));
        }
    }
    out
}

fn alarm<T>(result: Result<T>) -> AlarmKind {
    match result {
        Err(CoreError::Alarm(kind)) => kind,
        Err(e) => panic!("expected an alarm, got {e:?}"),
        Ok(_) => panic!("expected an alarm"),
    }
}

/// The path of a client's event.
fn event_path(client: Id, seq: u64) -> String {
    FileName::Event {
        client_id: client,
        seq,
    }
    .to_path()
}

/// Cases for property tests that unlock vaults (each unlock runs Argon2): a few by
/// default, more with PROPTEST_CASES.
fn slow_cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn new_vault() -> (MemoryStore, MemoryLocalStore) {
    let store = MemoryStore::new();
    let local = MemoryLocalStore::new();
    create_vault(&store, &local, PASSWORD, "Laptop").unwrap();
    (store, local)
}

/// Seals an event as `writer` would, but for `client`/`seq` and signed with
/// `signer`'s device key: how a key holder would forge or fork.
fn seal_as(
    writer: &Session<'_>,
    client: Id,
    seq: u64,
    signer: &DeviceKey,
    ops: Vec<Op>,
) -> Vec<u8> {
    let mut clock = writer.applied.clone();
    clock.observe(client, seq);
    let prev_hash = writer
        .events
        .get(&(client, seq - 1))
        .map_or([0; 32], |e| e.hash);
    EventHeader {
        vault_id: writer.vault_id,
        client_id: client,
        seq,
        epoch: writer.keyring.current(),
    }
    .seal(
        &EventBody {
            hlc: writer.latest_hlc + 1,
            clock,
            prev_hash,
            ops,
        },
        &writer.keyring.current_keys().event,
        signer,
        None,
    )
    .unwrap()
}

#[test]
fn two_devices_share_a_vault() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    a.write(vec![set(X, "title", "Bank")]).unwrap();

    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    assert_eq!(field(&b, X, "title").as_deref(), Some("Bank"));
    b.write(vec![set(X, "notes", "from the phone")]).unwrap();

    a.sync().unwrap();
    assert_eq!(contents(&a), contents(&b));
    let names: Vec<_> = a.view().devices.values().map(|d| d.name).collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"Laptop") && names.contains(&"Phone"));
}

#[test]
fn a_vault_on_disk_survives_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let store = FsStore::new(dir.path().join("vault"));
    let local = crate::local::FsLocalStore::new(dir.path().join("local"));
    create_vault(&store, &local, PASSWORD, "Laptop").unwrap();
    {
        let mut a = open(&store, &local, "Laptop");
        a.write(vec![set(X, "title", "Bank")]).unwrap();
        a.write(vec![set(X, "title", "Bank 2")]).unwrap();
    }
    let mut again = open(&store, &local, "Laptop");
    assert_eq!(field(&again, X, "title").as_deref(), Some("Bank 2"));
    again.write(vec![set(Y, "title", "Mail")]).unwrap();
    assert_eq!(again.state.record.next_seq, 5);
}

#[test]
fn a_deleted_event_is_a_rollback() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    a.write(vec![set(X, "title", "1")]).unwrap();
    a.write(vec![set(X, "title", "2")]).unwrap();
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");

    store.remove(&event_path(a.client_id(), 3));
    // Noticed by the running session and by a fresh one.
    assert_eq!(alarm(b.sync()), AlarmKind::Rollback);
    assert_eq!(
        alarm(b.write(vec![set(X, "title", "3")])),
        AlarmKind::Rollback
    );
    let unlocked = unlock(&store, &b_local, Credential::Password(PASSWORD)).unwrap();
    assert_eq!(
        alarm(
            Session::new(&store, &b_local, unlocked, "Phone")
                .unwrap()
                .sync()
        ),
        AlarmKind::Rollback
    );
}

#[test]
fn a_replaced_event_is_a_fork() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    a.write(vec![set(X, "title", "real")]).unwrap();
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");

    // A valid event for the same seq with different content, signed by A's own key:
    // what a device restored from an old backup would write.
    let mut stale_a = Session::new(
        &store,
        &a_local,
        unlock(&store, &a_local, Credential::Password(PASSWORD)).unwrap(),
        "Laptop",
    )
    .unwrap();
    stale_a.sync().unwrap();
    stale_a.applied = VectorClock(vec![(a.client_id(), 1)]);
    let other = seal_as(&stale_a, a.client_id(), 2, &a.device, vec![]);
    store.put(&event_path(a.client_id(), 2), other);
    assert_eq!(alarm(b.sync()), AlarmKind::Fork);
}

#[test]
fn a_reused_seq_is_a_fork_for_the_writer() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    let before = a_local.load(&a.vault_id).unwrap().unwrap();
    a.write(vec![set(X, "title", "first")]).unwrap();

    // Local state rolled back to before that write, and the device writes again
    // without syncing: same seq, different bytes.
    a_local.save(&a.vault_id, &before).unwrap();
    let unlocked = unlock(&store, &a_local, Credential::Password(PASSWORD)).unwrap();
    let mut stale = Session::new(&store, &a_local, unlocked, "Laptop").unwrap();
    stale.applied = VectorClock(vec![(a.client_id(), 1)]);
    stale.events.insert(
        (a.client_id(), 1),
        AppliedEvent {
            hash: a.events[&(a.client_id(), 1)].hash,
            hlc: 0,
            clock: VectorClock::default(),
            epoch: Some(0),
        },
    );
    assert_eq!(
        alarm(stale.write(vec![set(X, "title", "second")])),
        AlarmKind::Fork
    );
}

#[test]
fn restored_local_state_becomes_a_new_client() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    let vault_id = a.vault_id;
    let old_client = a.client_id();
    let before = a_local.load(&vault_id).unwrap().unwrap();
    a.write(vec![set(X, "title", "written before the restore")])
        .unwrap();

    a_local.save(&vault_id, &before).unwrap();
    let unlocked = unlock(&store, &a_local, Credential::Password(PASSWORD)).unwrap();
    let mut restored = Session::new(&store, &a_local, unlocked, "Laptop (restored)").unwrap();
    let report = restored.sync().unwrap();
    assert!(report.identity_reset);
    assert_ne!(restored.client_id(), old_client);
    restored
        .write(vec![set(X, "notes", "after the restore")])
        .unwrap();
    assert_eq!(
        field(&restored, X, "title").as_deref(),
        Some("written before the restore")
    );
    assert_eq!(restored.view().devices.len(), 2);
}

#[test]
fn copied_or_renamed_events_are_set_aside() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    a.write(vec![set(X, "title", "1")]).unwrap();
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");

    store.put(
        &event_path(a.client_id(), 9),
        store.get(&event_path(a.client_id(), 2)).unwrap(),
    );
    let report = b.sync().unwrap();
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(b.alarm(), None);

    let (other_vault, other_local) = new_vault();
    let mut other = open(&other_vault, &other_local, "Other");
    other.write(vec![set(X, "title", "elsewhere")]).unwrap();
    let path = event_path(other.client_id(), 2);
    store.put(&path, other_vault.get(&path).unwrap());
    assert_eq!(b.sync().unwrap().rejected.len(), 2);
}

#[test]
fn an_event_signed_by_another_device_is_a_forgery() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    b.write(vec![set(X, "title", "B")]).unwrap();
    b.sync().unwrap();

    // B holds the vault key and writes A's next event, signed with B's key.
    let forged = seal_as(&b, a.client_id(), 2, &b.device, vec![]);
    store.put(&event_path(a.client_id(), 2), forged);
    a.sync().unwrap_err();
    assert_eq!(a.alarm(), Some(AlarmKind::Forgery));
}

#[test]
fn a_tampered_epoch_record_signature_is_a_forgery() {
    let (store, a_local) = new_vault();
    let path = store.paths_in("epochs").remove(0);
    let mut record = store.get(&path).unwrap();
    *record.last_mut().unwrap() ^= 1;
    store.put(&path, record);
    // Epoch 0 has no chain wrap, so only the signature can catch this.
    let unlocked = unlock(&store, &a_local, Credential::Password(PASSWORD)).unwrap();
    assert_eq!(
        alarm(
            Session::new(&store, &a_local, unlocked, "Laptop")
                .unwrap()
                .sync()
        ),
        AlarmKind::Forgery
    );
}

#[test]
fn events_wait_for_their_dependencies() {
    let (store, a_local) = new_vault();
    let a = open(&store, &a_local, "Laptop");
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    b.write(vec![set(X, "title", "B")]).unwrap();
    let c_local = MemoryLocalStore::new();
    let mut c = open(&store, &c_local, "Tablet");
    c.write(vec![set(X, "notes", "C saw B")]).unwrap();

    // B's event goes missing for a while (a slow sync), so C's can't be applied yet.
    let b_path = event_path(b.client_id(), 1);
    let b_event = store.remove(&b_path).unwrap();
    let mut a = a;
    let report = a.sync().unwrap();
    assert_eq!(report.held.len(), 1);
    assert_eq!(report.held[0].1, Held::WaitingForDependencies);
    assert_eq!(field(&a, X, "notes"), None);

    store.put(&b_path, b_event);
    let report = a.sync().unwrap();
    assert!(report.held.is_empty());
    assert_eq!(field(&a, X, "notes").as_deref(), Some("C saw B"));
}

/// Fails every `create` while `fail` is set, like an unreachable sync folder.
struct FlakyStore {
    inner: MemoryStore,
    fail: AtomicBool,
}

impl RemoteStore for FlakyStore {
    fn list(&self) -> Result<Vec<String>> {
        self.inner.list()
    }
    fn read(&self, path: &str, max_len: usize) -> Result<Vec<u8>> {
        self.inner.read(path, max_len)
    }
    fn create(&self, path: &str, bytes: &[u8]) -> Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("offline").into());
        }
        self.inner.create(path, bytes)
    }
    fn delete(&self, path: &str) -> Result<()> {
        self.inner.delete(path)
    }
}

#[test]
fn a_failed_upload_is_retried_with_the_same_seq() {
    let store = FlakyStore {
        inner: MemoryStore::new(),
        fail: AtomicBool::new(false),
    };
    let a_local = MemoryLocalStore::new();
    create_vault(&store, &a_local, PASSWORD, "Laptop").unwrap();
    let mut a = open(&store, &a_local, "Laptop");

    store.fail.store(true, Ordering::SeqCst);
    assert!(matches!(
        a.write(vec![set(X, "title", "offline edit")]),
        Err(CoreError::Io(_))
    ));
    assert_eq!(a.state.record.pending.len(), 1);

    store.fail.store(false, Ordering::SeqCst);
    let report = a.sync().unwrap();
    assert_eq!(report.uploaded, 1);
    assert_eq!(field(&a, X, "title").as_deref(), Some("offline edit"));
    a.write(vec![set(X, "notes", "next")]).unwrap();
    let b_local = MemoryLocalStore::new();
    let b = open(&store, &b_local, "Phone");
    assert_eq!(contents(&a), contents(&b));
}

#[test]
fn a_retired_devices_later_changes_are_flagged_not_dropped() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    b.write(vec![set(X, "title", "fine")]).unwrap();
    a.sync().unwrap();
    a.write(vec![Edit::RetireClient {
        client_id: b.client_id(),
        last_seq: 1,
    }])
    .unwrap();
    // B hasn't heard and keeps writing.
    b.write(vec![set(X, "title", "after retirement")]).unwrap();

    a.sync().unwrap();
    assert_eq!(field(&a, X, "title").as_deref(), Some("after retirement"));
    let review = a.review();
    assert_eq!(
        review.flagged,
        vec![Dot {
            client_id: b.client_id(),
            seq: 2,
            op_index: 0
        }]
    );
    assert!(review.suspect_devices.is_empty());
}

// ---- Convergence through the files (spec §14.2) --------------------------------

#[derive(Debug, Clone)]
enum Step {
    Write {
        device: usize,
        entry: usize,
        value: u8,
        secret: bool,
    },
    Sync {
        device: usize,
    },
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        (0..3usize, 0..2usize, any::<u8>(), any::<bool>()).prop_map(
            |(device, entry, value, secret)| Step::Write {
                device,
                entry,
                value,
                secret
            }
        ),
        (0..3usize).prop_map(|device| Step::Sync { device }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(slow_cases(24)))]

    /// Three devices writing and syncing at random through one store end up with the
    /// same vault, every event signed, chained and checked on the way.
    #[test]
    fn devices_converge_through_the_store(steps in proptest::collection::vec(step(), 0..30)) {
        let (store, a_local) = new_vault();
        let locals = [a_local, MemoryLocalStore::new(), MemoryLocalStore::new()];
        let mut devices: Vec<Session<'_>> = ["A", "B", "C"]
            .iter()
            .zip(&locals)
            .map(|(name, local)| open(&store, local, name))
            .collect();
        for step in steps {
            match step {
                Step::Write { device, entry, value, secret } => {
                    devices[device].write(vec![Edit::SetField {
                        entry_id: [entry as u8 + 1; 16],
                        name: "f".into(),
                        value: Some(SecretBytes::from_slice(&[value])),
                        secret,
                    }]).unwrap();
                }
                Step::Sync { device } => { devices[device].sync().unwrap(); }
            }
        }
        for device in &mut devices {
            device.sync().unwrap();
        }
        for device in &mut devices {
            device.sync().unwrap();
        }
        let first = contents(&devices[0]);
        for device in &devices[1..] {
            prop_assert_eq!(&contents(device), &first);
        }
    }
}

#[test]
fn a_device_appearing_under_an_old_key_after_a_rotation_is_suspect() {
    use crate::crypto::SecretKey;
    use crate::crypto::kdf::{self, Argon2Params, EpochKeys};
    use crate::format::epoch::{ChainWrap, NewEpoch};
    use crate::format::slot::{self, SlotParams};

    let (store, a_local) = new_vault();
    let old = open(&store, &a_local, "Laptop");
    let vault_id = old.vault_id;

    // Rotate to epoch 1 the way rotation will (spec §7.2): the cutover is A's view.
    let ek1 = SecretKey::generate().unwrap();
    let keys1 = EpochKeys::derive(&vault_id, &ek1);
    let record = NewEpoch {
        vault_id,
        epoch: 1,
        creator: old.client_id(),
        key_id: keys1.key_id,
        recovery_pk_hash: [0; 32],
        cutover: &old.applied,
        chain: Some(ChainWrap {
            chain_key: &keys1.chain,
            prev_epoch_key: old.keyring.epoch_key(0).unwrap(),
            nonce: None,
        }),
    }
    .seal(&old.device)
    .unwrap();
    store.put(
        &FileName::Epoch {
            epoch: 1,
            creator: old.client_id(),
        }
        .to_path(),
        record,
    );
    let slot_id = random_id().unwrap();
    let salt = [3; 16];
    let secret =
        kdf::password_slot_secret(b"rotated password", &salt, Argon2Params::DEFAULT).unwrap();
    store.put(
        &FileName::Slot { slot_id }.to_path(),
        slot::seal_with_kek(
            &vault_id,
            &slot_id,
            1,
            &SlotParams::Password {
                argon: Argon2Params::DEFAULT,
                salt,
            },
            &kdf::slot_kek(&vault_id, &slot_id, &secret),
            &ek1,
        )
        .unwrap(),
    );

    // Someone holding the old key invents a device after the rotation.
    let intruder = random_id().unwrap();
    let intruder_key = DeviceKey::generate().unwrap();
    let event = seal_as(
        &old,
        intruder,
        1,
        &intruder_key,
        vec![Op::RegisterDevice {
            client_id: intruder,
            dev_pk: intruder_key.public_key(),
            name: "New phone".into(),
        }],
    );
    store.put(&event_path(intruder, 1), event);

    let unlocked = unlock(&store, &a_local, Credential::Password(b"rotated password")).unwrap();
    assert_eq!(unlocked.keyring.current(), 1);
    let mut a = Session::new(&store, &a_local, unlocked, "Laptop").unwrap();
    let report = a.sync().unwrap();
    assert_eq!(
        report.unverified_epoch_records, 0,
        "A's epoch records verify"
    );
    let review = a.review();
    assert_eq!(review.suspect_devices, vec![intruder]);
    assert_eq!(
        review.flagged,
        vec![Dot {
            client_id: intruder,
            seq: 1,
            op_index: 0
        }]
    );
}

/// Rotates the vault in `store` to epoch 1 with a new password slot, as `by` would.
fn rotate_to_epoch_1(store: &MemoryStore, by: &Session<'_>, new_password: &[u8]) {
    use crate::crypto::SecretKey;
    use crate::crypto::kdf::{self, Argon2Params, EpochKeys};
    use crate::format::epoch::{ChainWrap, NewEpoch};
    use crate::format::slot::{self, SlotParams};

    let vault_id = by.vault_id;
    let ek1 = SecretKey::generate().unwrap();
    let keys1 = EpochKeys::derive(&vault_id, &ek1);
    let record = NewEpoch {
        vault_id,
        epoch: 1,
        creator: by.client_id(),
        key_id: keys1.key_id,
        recovery_pk_hash: [0; 32],
        cutover: &by.applied,
        chain: Some(ChainWrap {
            chain_key: &keys1.chain,
            prev_epoch_key: by.keyring.epoch_key(0).unwrap(),
            nonce: None,
        }),
    }
    .seal(&by.device)
    .unwrap();
    store.put(
        &FileName::Epoch {
            epoch: 1,
            creator: by.client_id(),
        }
        .to_path(),
        record,
    );
    let slot_id = random_id().unwrap();
    let salt = [3; 16];
    let secret = kdf::password_slot_secret(new_password, &salt, Argon2Params::DEFAULT).unwrap();
    store.put(
        &FileName::Slot { slot_id }.to_path(),
        slot::seal_with_kek(
            &vault_id,
            &slot_id,
            1,
            &SlotParams::Password {
                argon: Argon2Params::DEFAULT,
                salt,
            },
            &kdf::slot_kek(&vault_id, &slot_id, &secret),
            &ek1,
        )
        .unwrap(),
    );
}

#[test]
fn after_a_rotation_an_old_session_stops_writing_until_it_unlocks_again() {
    let (store, a_local) = new_vault();
    let a = open(&store, &a_local, "Laptop");
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    b.write(vec![set(X, "title", "before")]).unwrap();

    rotate_to_epoch_1(&store, &a, b"rotated password");
    let report = b.sync().unwrap();
    assert!(report.key_rotated && b.key_rotated());
    assert!(matches!(
        b.write(vec![set(X, "password", "secret")]),
        Err(CoreError::KeyRotated)
    ));

    // Unlocking again with the new password catches B up; writes go under epoch 1.
    let unlocked = unlock(&store, &b_local, Credential::Password(b"rotated password")).unwrap();
    let mut b = Session::new(&store, &b_local, unlocked, "Phone").unwrap();
    b.sync().unwrap();
    b.write(vec![set(X, "title", "after")]).unwrap();
    let latest = store.get(&event_path(b.client_id(), 2)).unwrap();
    assert_eq!(
        SealedEvent::parse(&latest, &b.vault_id)
            .unwrap()
            .header
            .epoch,
        1
    );
}

#[test]
fn a_pending_event_is_resealed_under_the_new_key() {
    let store = FlakyStore {
        inner: MemoryStore::new(),
        fail: AtomicBool::new(false),
    };
    let a_local = MemoryLocalStore::new();
    create_vault(&store, &a_local, PASSWORD, "Laptop").unwrap();
    let mut a = open(&store, &a_local, "Laptop");
    store.fail.store(true, Ordering::SeqCst);
    a.write(vec![set(X, "password", "written offline")])
        .unwrap_err();
    store.fail.store(false, Ordering::SeqCst);

    // Meanwhile another device rotates. A must not publish its pending event under
    // the old key: after unlocking again it re-seals it under epoch 1.
    rotate_to_epoch_1(&store.inner, &a, b"rotated password");
    let unlocked = unlock(&store, &a_local, Credential::Password(b"rotated password")).unwrap();
    let mut a = Session::new(&store, &a_local, unlocked, "Laptop").unwrap();
    assert_eq!(a.sync().unwrap().uploaded, 1);
    let uploaded = store.inner.get(&event_path(a.client_id(), 2)).unwrap();
    assert_eq!(
        SealedEvent::parse(&uploaded, &a.vault_id)
            .unwrap()
            .header
            .epoch,
        1
    );
    assert_eq!(field(&a, X, "password").as_deref(), Some("written offline"));
}

#[test]
fn nothing_is_uploaded_after_an_alarm() {
    let store = FlakyStore {
        inner: MemoryStore::new(),
        fail: AtomicBool::new(false),
    };
    let a_local = MemoryLocalStore::new();
    create_vault(&store, &a_local, PASSWORD, "Laptop").unwrap();
    let mut a = open(&store, &a_local, "Laptop");
    a.write(vec![set(X, "title", "1")]).unwrap();
    store.fail.store(true, Ordering::SeqCst);
    a.write(vec![set(X, "title", "pending")]).unwrap_err();
    store.fail.store(false, Ordering::SeqCst);

    store.inner.remove(&event_path(a.client_id(), 2));
    assert_eq!(alarm(a.sync()), AlarmKind::Rollback);
    assert_eq!(alarm(a.sync()), AlarmKind::Rollback);
    assert!(
        store.inner.get(&event_path(a.client_id(), 3)).is_none(),
        "pending event held back"
    );
}

#[test]
fn the_device_name_is_checked_up_front() {
    let (store, local) = new_vault();
    let unlocked = unlock(&store, &local, Credential::Password(PASSWORD)).unwrap();
    assert!(Session::new(&store, &local, unlocked, "").is_err());
}

// ---- Snapshots and garbage collection (spec §10) ----------------------------------

fn event_count(store: &MemoryStore) -> usize {
    store.paths_in("events").len()
}

#[test]
fn after_compaction_a_fresh_device_still_sees_everything() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    for i in 0..5 {
        a.write(vec![set(X, "title", &format!("a{i}"))]).unwrap();
        b.write(vec![set(Y, "title", &format!("b{i}"))]).unwrap();
    }
    a.sync().unwrap();
    b.sync().unwrap();
    a.write_snapshot().unwrap();
    let gc = a.collect_garbage(0).unwrap();
    assert_eq!(event_count(&store), 0, "every event is under A's watermark");
    assert_eq!(gc.events_deleted, 11);

    // B's running session and a restarted one both accept the compaction.
    b.sync().unwrap();
    b.write(vec![set(Y, "notes", "after compaction")]).unwrap();
    let unlocked = unlock(&store, &b_local, Credential::Password(PASSWORD)).unwrap();
    let mut b2 = Session::new(&store, &b_local, unlocked, "Phone").unwrap();
    assert_eq!(b2.sync().unwrap().snapshots_loaded, 1);

    let c_local = MemoryLocalStore::new();
    let mut c = open(&store, &c_local, "Tablet");
    a.sync().unwrap();
    assert_eq!(contents(&c), contents(&a));
    assert_eq!(contents(&c), contents(&b2));
    c.write(vec![set(X, "notes", "new device")]).unwrap();
    a.sync().unwrap();
    assert_eq!(field(&a, X, "notes").as_deref(), Some("new device"));
}

#[test]
fn only_a_devices_own_snapshots_lead_it_to_delete() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    b.write(vec![set(X, "title", "b")]).unwrap();
    b.write_snapshot().unwrap();
    a.sync().unwrap();
    assert_eq!(a.collect_garbage(0).unwrap(), GarbageReport::default());

    // And within the grace period, not even the creator deletes.
    a.write(vec![set(X, "title", "a")]).unwrap();
    a.write_snapshot().unwrap();
    assert_eq!(
        a.collect_garbage(30 * 24 * 3600 * 1000).unwrap(),
        GarbageReport::default()
    );
}

#[test]
fn restoring_an_older_snapshot_is_a_rollback() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    a.write(vec![set(X, "title", "1")]).unwrap();
    let first = a.write_snapshot().unwrap();
    let first_path = FileName::Snapshot { snapshot_id: first }.to_path();
    let first_bytes = store.get(&first_path).unwrap();
    a.write(vec![set(X, "title", "2")]).unwrap();
    a.write_snapshot().unwrap();
    let gc = a.collect_garbage(0).unwrap();
    assert_eq!(gc.snapshots_deleted, 1, "the dominated older snapshot goes");
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");

    for path in store.paths_in("snapshots") {
        store.remove(&path);
    }
    store.put(&first_path, first_bytes);
    let unlocked = unlock(&store, &b_local, Credential::Password(PASSWORD)).unwrap();
    let mut fresh_b = Session::new(&store, &b_local, unlocked, "Phone").unwrap();
    assert_eq!(alarm(fresh_b.sync()), AlarmKind::Rollback);
    assert_eq!(alarm(b.sync()), AlarmKind::Rollback);
}

#[test]
fn replaying_a_compacted_event_changes_nothing() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    a.write(vec![set(X, "title", "1")]).unwrap();
    let path = event_path(a.client_id(), 2);
    let event = store.get(&path).unwrap();
    a.write(vec![set(X, "title", "2")]).unwrap();
    a.write_snapshot().unwrap();
    a.collect_garbage(0).unwrap();

    store.put(&path, event);
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    let report = b.sync().unwrap();
    assert_eq!(report.applied, 0);
    assert_eq!(field(&b, X, "title").as_deref(), Some("2"));
}

#[test]
fn a_snapshot_contradicting_an_applied_event_is_a_fork() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    a.write(vec![set(X, "title", "1")]).unwrap();
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    // A key holder writes a snapshot whose watermark disagrees about A's event 2.
    a.events.get_mut(&(a.client_id(), 2)).unwrap().hash = [0xee; 32];
    a.write_snapshot().unwrap();
    assert_eq!(alarm(b.sync()), AlarmKind::Fork);
}

#[test]
fn a_snapshot_with_a_bad_signature_is_a_forgery() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    a.write(vec![set(X, "title", "1")]).unwrap();
    let id = a.write_snapshot().unwrap();
    let path = FileName::Snapshot { snapshot_id: id }.to_path();
    let mut bytes = store.get(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    store.put(&path, bytes);
    let b_local = MemoryLocalStore::new();
    let unlocked = unlock(&store, &b_local, Credential::Password(PASSWORD)).unwrap();
    let mut b = Session::new(&store, &b_local, unlocked, "Phone").unwrap();
    assert_eq!(alarm(b.sync()), AlarmKind::Forgery);
}

#[derive(Debug, Clone)]
enum CompactStep {
    Write {
        device: usize,
        entry: usize,
        value: u8,
    },
    Sync {
        device: usize,
    },
    Snapshot {
        device: usize,
    },
    Collect {
        device: usize,
    },
}

fn compact_step() -> impl Strategy<Value = CompactStep> {
    prop_oneof![
        4 => (0..3usize, 0..2usize, any::<u8>())
            .prop_map(|(device, entry, value)| CompactStep::Write { device, entry, value }),
        3 => (0..3usize).prop_map(|device| CompactStep::Sync { device }),
        1 => (0..3usize).prop_map(|device| CompactStep::Snapshot { device }),
        1 => (0..3usize).prop_map(|device| CompactStep::Collect { device }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(slow_cases(16)))]

    /// Snapshots and garbage collection at random never change the vault: the devices
    /// converge, and a device joining at the end, from whatever snapshots and events
    /// are left, sees exactly the same (spec §10).
    #[test]
    fn compaction_never_changes_the_vault(steps in proptest::collection::vec(compact_step(), 0..30)) {
        let (store, a_local) = new_vault();
        let locals = [a_local, MemoryLocalStore::new(), MemoryLocalStore::new()];
        let mut devices: Vec<Session<'_>> = ["A", "B", "C"]
            .iter()
            .zip(&locals)
            .map(|(name, local)| open(&store, local, name))
            .collect();
        for step in steps {
            match step {
                CompactStep::Write { device, entry, value } => {
                    devices[device].write(vec![Edit::SetField {
                        entry_id: [entry as u8 + 1; 16],
                        name: "f".into(),
                        value: Some(SecretBytes::from_slice(&[value])),
                        secret: false,
                    }]).unwrap();
                }
                CompactStep::Sync { device } => { devices[device].sync().unwrap(); }
                CompactStep::Snapshot { device } => {
                    // A device that has never written can't sign a usable snapshot.
                    let _ = devices[device].write_snapshot();
                }
                CompactStep::Collect { device } => { devices[device].collect_garbage(0).unwrap(); }
            }
        }
        for _ in 0..2 {
            for device in &mut devices {
                device.sync().unwrap();
            }
        }
        let first = contents(&devices[0]);
        for device in &devices[1..] {
            prop_assert_eq!(&contents(device), &first);
        }
        let late_local = MemoryLocalStore::new();
        let late = open(&store, &late_local, "Late");
        prop_assert_eq!(&contents(&late), &first);
    }
}

#[test]
fn compaction_under_a_key_not_yet_held_is_unverified_not_an_alarm() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    a.write(vec![set(X, "title", "1")]).unwrap();
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");

    // A rotates, catches up, compacts under the new key and collects garbage.
    rotate_to_epoch_1(&store, &a, b"rotated password");
    let unlocked = unlock(&store, &a_local, Credential::Password(b"rotated password")).unwrap();
    let mut a = Session::new(&store, &a_local, unlocked, "Laptop").unwrap();
    a.sync().unwrap();
    a.write(vec![set(X, "title", "2")]).unwrap();
    a.write_snapshot().unwrap();
    a.collect_garbage(0).unwrap();

    // B can't read the new snapshot yet: its marks can't be checked, but that's
    // reported, not mistaken for a rollback. B can't write meanwhile.
    let report = b.sync().unwrap();
    assert!(report.key_rotated && report.integrity_unverified);
    assert!(matches!(
        b.write(vec![set(X, "notes", "x")]),
        Err(CoreError::KeyRotated)
    ));

    // Once B unlocks with the new password everything checks out again.
    let unlocked = unlock(&store, &b_local, Credential::Password(b"rotated password")).unwrap();
    let mut b = Session::new(&store, &b_local, unlocked, "Phone").unwrap();
    let report = b.sync().unwrap();
    assert!(!report.integrity_unverified && !report.key_rotated);
    assert_eq!(field(&b, X, "title").as_deref(), Some("2"));
}

// ---- Rotation and key management (spec §7.2, §6.2.1, §10.4) -----------------------

#[test]
fn changing_the_password_rotates_and_other_devices_follow() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    b.write(vec![set(X, "title", "before")]).unwrap();

    let rotated = a.change_password(b"new password").unwrap();
    assert_eq!((rotated.epoch, rotated.recovery_lost), (1, false));
    a.write(vec![set(X, "notes", "after")]).unwrap();
    assert!(matches!(
        unlock(
            &store,
            &MemoryLocalStore::new(),
            Credential::Password(PASSWORD)
        ),
        Err(CoreError::WrongCredential)
    ));

    // B notices, stops writing, and catches up with the new password.
    assert!(b.sync().unwrap().key_rotated);
    assert!(matches!(
        b.write(vec![set(X, "title", "stale")]),
        Err(CoreError::KeyRotated)
    ));
    let unlocked = unlock(&store, &b_local, Credential::Password(b"new password")).unwrap();
    let mut b = Session::new(&store, &b_local, unlocked, "Phone").unwrap();
    b.sync().unwrap();
    assert_eq!(field(&b, X, "notes").as_deref(), Some("after"));
    b.write(vec![set(X, "title", "caught up")]).unwrap();
    a.sync().unwrap();
    assert_eq!(contents(&a), contents(&b));
}

#[test]
fn a_replayed_old_password_slot_opens_only_the_old_epoch() {
    let (store, a_local) = new_vault();
    let old_slots: Vec<_> = store
        .paths_in("slots")
        .into_iter()
        .map(|p| {
            let bytes = store.get(&p).unwrap();
            (p, bytes)
        })
        .collect();
    let mut a = open(&store, &a_local, "Laptop");
    a.change_password(b"new password").unwrap();
    a.write(vec![set(X, "password", "after")]).unwrap();
    for (path, bytes) in old_slots {
        store.put(&path, bytes);
    }

    // A device that has caught up never tries a slot below its pin.
    assert!(matches!(
        unlock(&store, &a_local, Credential::Password(PASSWORD)),
        Err(CoreError::WrongCredential)
    ));
    // A fresh device gets the old epoch only: nothing newer to read, no writing.
    let fresh = MemoryLocalStore::new();
    let unlocked = unlock(&store, &fresh, Credential::Password(PASSWORD)).unwrap();
    assert!(unlocked.newer_epoch_unreachable);
    let mut old = Session::new(&store, &fresh, unlocked, "Old").unwrap();
    old.sync().unwrap();
    assert_eq!(field(&old, X, "password"), None);
    assert!(matches!(
        old.write(vec![set(X, "title", "x")]),
        Err(CoreError::KeyRotated)
    ));
}

#[test]
fn rotation_keeps_the_recovery_key_and_replacing_it_retires_the_old_one() {
    let store = MemoryStore::new();
    let a_local = MemoryLocalStore::new();
    let words = create_vault(&store, &a_local, PASSWORD, "Laptop")
        .unwrap()
        .recovery_words;
    let recover = |words: &SecretBytes| {
        unlock(
            &store,
            &MemoryLocalStore::new(),
            Credential::RecoveryWords(words.expose()),
        )
        .map(|u| u.keyring.current())
    };
    let mut a = open(&store, &a_local, "Laptop");

    a.change_password(b"new password").unwrap();
    assert_eq!(recover(&words).unwrap(), 1, "kept without the words");

    let new_words = a.replace_recovery_key(b"new password").unwrap();
    assert!(matches!(recover(&words), Err(CoreError::WrongCredential)));
    assert_eq!(recover(&new_words).unwrap(), 2);
    // The new key's anchor is at epoch 2, and later rotations keep it.
    a.change_password(b"newer password").unwrap();
    assert_eq!(recover(&new_words).unwrap(), 3);
}

#[test]
fn rotation_rewraps_only_the_recovery_key_the_epoch_record_names() {
    use crate::crypto::SecretKey;
    use crate::crypto::recovery::{self, RecoveryKeyPair};
    use crate::format::slot::{self, SlotFile, SlotParams};
    use crate::policy::SlotScope;

    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    // Someone who can write to the storage plants a recovery slot for their own key,
    // anchor and all. Without the record naming the real one, rotation would hand
    // them every later epoch key.
    let r = recovery::generate().unwrap();
    let pk = *RecoveryKeyPair::derive(&r).public_key();
    let key_id_0 = a.keyring.keys(0).unwrap().key_id;
    let planted_id = random_id().unwrap();
    let planted = slot::seal_recovery(
        &a.vault_id,
        &planted_id,
        0,
        &SlotParams::Recovery {
            anchor_tag: recovery::anchor_tag(&r, &a.vault_id, 0, &key_id_0, &pk),
            pk: Box::new(pk),
            anchor_epoch: 0,
        },
        &SecretKey::generate().unwrap(),
        None,
    )
    .unwrap();
    store.put(
        &FileName::Slot {
            slot_id: planted_id,
        }
        .to_path(),
        planted,
    );

    a.change_password(b"new password").unwrap();
    let recovery_pks: Vec<[u8; recovery::PUBLIC_KEY_LEN]> = store
        .paths_in("slots")
        .iter()
        .filter_map(|path| {
            let bytes = store.get(path).unwrap();
            match SlotFile::parse(&bytes, &a.vault_id, SlotScope::Synced)
                .unwrap()
                .params
            {
                SlotParams::Recovery { pk, .. } => Some(*pk),
                _ => None,
            }
        })
        .collect();
    assert_eq!(recovery_pks.len(), 1);
    assert_ne!(recovery_pks[0], pk);
    let words = recovery::to_words(&r);
    assert!(
        unlock(
            &store,
            &MemoryLocalStore::new(),
            Credential::RecoveryWords(words.expose())
        )
        .is_err()
    );
}

#[test]
fn a_missing_recovery_slot_is_reported_not_silently_dropped() {
    use crate::format::slot::{SlotFile, SlotParams};
    use crate::policy::SlotScope;

    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    for path in store.paths_in("slots") {
        let bytes = store.get(&path).unwrap();
        let slot = SlotFile::parse(&bytes, &a.vault_id, SlotScope::Synced).unwrap();
        if matches!(slot.params, SlotParams::Recovery { .. }) {
            store.remove(&path);
        }
    }
    assert!(a.change_password(b"new password").unwrap().recovery_lost);
    // The new epoch names no recovery key, so there's nothing more to lose.
    assert!(!a.change_password(b"newer password").unwrap().recovery_lost);
}

#[test]
fn a_revoked_device_reads_nothing_new_and_its_late_changes_can_be_reverted() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    b.write(vec![set(X, "title", "original")]).unwrap();
    a.sync().unwrap();

    assert!(a.revoke_device(a.client_id(), PASSWORD).is_err());
    a.revoke_device(b.client_id(), PASSWORD).unwrap();
    a.write(vec![set(X, "password", "new secret")]).unwrap();

    // B holds only the old key: the new event stays out of reach.
    let report = b.sync().unwrap();
    assert!(report.key_rotated);
    assert!(
        report
            .held
            .iter()
            .any(|(_, held)| *held == Held::UnknownEpoch(1))
    );
    assert_eq!(field(&b, X, "password"), None);

    // Whoever has B's keys writes under the old epoch anyway.
    let seq = b.state.record.next_seq;
    let value = |v: &str| Some(SecretBytes::from_slice(v.as_bytes()));
    let late = seal_as(
        &b,
        b.client_id(),
        seq,
        &b.device,
        vec![
            Op::SetField {
                entry_id: X,
                name: "title".into(),
                value: value("tampered"),
                secret: false,
            },
            Op::SetField {
                entry_id: Y,
                name: "title".into(),
                value: value("planted"),
                secret: false,
            },
        ],
    );
    store.put(&event_path(b.client_id(), seq), late);
    a.sync().unwrap();
    assert_eq!(field(&a, X, "title").as_deref(), Some("tampered"));
    assert_eq!(a.review().flagged.len(), 2);

    assert_eq!(a.revert_flagged().unwrap(), 2);
    assert_eq!(field(&a, X, "title").as_deref(), Some("original"));
    assert!(a.view().entries[&Y].deleted);
    assert_eq!(a.revert_flagged().unwrap(), 0, "nothing left to revert");
}

/// Puts `files` into the store just before the next epoch record is created: another
/// device's rotation landing while this one's is under way.
struct RaceStore {
    inner: MemoryStore,
    files: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
}

impl RemoteStore for RaceStore {
    fn list(&self) -> Result<Vec<String>> {
        self.inner.list()
    }
    fn read(&self, path: &str, max_len: usize) -> Result<Vec<u8>> {
        self.inner.read(path, max_len)
    }
    fn create(&self, path: &str, bytes: &[u8]) -> Result<()> {
        if path.starts_with("epochs/") {
            for (path, bytes) in self.files.lock().unwrap().drain(..) {
                self.inner.put(&path, bytes);
            }
        }
        self.inner.create(path, bytes)
    }
    fn delete(&self, path: &str) -> Result<()> {
        self.inner.delete(path)
    }
}

/// An epoch 1 record with `by`'s view as its cutover, claiming `creator`, with a
/// chosen key ID, signed by `signer`.
fn rival_record(
    by: &Session<'_>,
    creator: Id,
    signer: &DeviceKey,
    key_id: [u8; 32],
) -> (String, Vec<u8>) {
    use crate::crypto::SecretKey;
    use crate::format::epoch::{ChainWrap, NewEpoch};

    let chain_key = SecretKey::generate().unwrap();
    let bytes = NewEpoch {
        vault_id: by.vault_id,
        epoch: 1,
        creator,
        key_id,
        recovery_pk_hash: [0; 32],
        cutover: &by.applied,
        chain: Some(ChainWrap {
            chain_key: &chain_key,
            prev_epoch_key: by.keyring.epoch_key(0).unwrap(),
            nonce: None,
        }),
    }
    .seal(signer)
    .unwrap();
    let path = FileName::Epoch { epoch: 1, creator }.to_path();
    (path, bytes)
}

fn race_vault() -> (RaceStore, MemoryLocalStore) {
    let store = RaceStore {
        inner: MemoryStore::new(),
        files: Default::default(),
    };
    let local = MemoryLocalStore::new();
    create_vault(&store, &local, PASSWORD, "Laptop").unwrap();
    (store, local)
}

#[test]
fn a_rotation_that_meets_a_winning_rival_backs_out() {
    let (store, a_local) = race_vault();
    let mut a = open(&store, &a_local, "Laptop");
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    b.write(vec![set(X, "title", "b")]).unwrap();
    a.sync().unwrap();
    let before = store.list().unwrap();

    // B's record for epoch 1 has the lowest possible key ID and lands mid-rotation.
    let (rival_path, rival) = rival_record(&b, b.client_id(), &b.device, [0; 32]);
    *store.files.lock().unwrap() = vec![(rival_path.clone(), rival)];
    assert!(matches!(
        a.change_password(b"new password"),
        Err(CoreError::ConflictingRotation)
    ));
    // A took back its record and slots and left everything else alone.
    let mut expected = before;
    expected.push(rival_path);
    expected.sort();
    assert_eq!(store.list().unwrap(), expected);
    assert!(matches!(
        a.write(vec![set(X, "title", "a")]),
        Err(CoreError::KeyRotated)
    ));
}

#[test]
fn rivals_that_lose_or_cant_be_verified_dont_stop_a_rotation() {
    for winning_but_unsigned in [false, true] {
        let (store, a_local) = race_vault();
        let mut a = open(&store, &a_local, "Laptop");
        let b_local = MemoryLocalStore::new();
        let mut b = open(&store, &b_local, "Phone");
        b.write(vec![set(X, "title", "b")]).unwrap();
        a.sync().unwrap();

        // Either a registered device's record with a higher key ID, or a lowest-key
        // record from a device nobody registered: storage alone can't win.
        let rival = if winning_but_unsigned {
            rival_record(
                &b,
                random_id().unwrap(),
                &DeviceKey::generate().unwrap(),
                [0; 32],
            )
        } else {
            rival_record(&b, b.client_id(), &b.device, [0xff; 32])
        };
        *store.files.lock().unwrap() = vec![rival];
        a.change_password(b"new password").unwrap();
        a.write(vec![set(X, "title", "a")]).unwrap();
        assert!(!a.sync().unwrap().lost_rotation);
    }
}

#[test]
fn a_revoked_device_cant_win_the_current_epoch_after_the_fact() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    b.write(vec![set(X, "title", "b")]).unwrap();
    a.sync().unwrap();
    a.revoke_device(b.client_id(), PASSWORD).unwrap();

    // B still holds the epoch 0 key and its registered signing key. It writes its
    // own record for epoch 1 with the lowest possible key ID, properly signed.
    let (path, record) = rival_record(&b, b.client_id(), &b.device, [0; 32]);
    store.put(&path, record);
    let report = a.sync().unwrap();
    assert!(
        !report.lost_rotation,
        "a retired device's record never wins"
    );
    a.write(vec![set(X, "title", "still writing")]).unwrap();
}

#[test]
fn the_loser_of_a_concurrent_rotation_rejoins_and_keeps_its_changes() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    b.write(vec![set(X, "title", "shared")]).unwrap();
    a.sync().unwrap();
    drop(b);
    let (laptop_password, phone_password): (&[u8], &[u8]) = (b"laptop password", b"phone password");

    // Both change the password at the same moment, neither seeing the other: B in a
    // copy of the store whose new files arrive afterwards.
    let elsewhere = MemoryStore::new();
    for path in store.list().unwrap() {
        elsewhere.put(&path, store.get(&path).unwrap());
    }
    {
        let mut b = open(&elsewhere, &b_local, "Phone");
        b.change_password(phone_password).unwrap();
        b.write(vec![
            set(Y, "title", "from the phone"),
            set(X, "password", "phone secret"),
        ])
        .unwrap();
    }
    a.change_password(laptop_password).unwrap();
    a.write(vec![
        set(X, "notes", "from the laptop"),
        set(X, "password", "laptop secret"),
    ])
    .unwrap();
    for path in elsewhere.list().unwrap() {
        if store.get(&path).is_none() {
            store.put(&path, elsewhere.get(&path).unwrap());
        }
    }
    let unlocked = unlock(&store, &b_local, Credential::Password(phone_password)).unwrap();
    let mut b = Session::new(&store, &b_local, unlocked, "Phone").unwrap();

    // Exactly one key wins; which one depends on the random key IDs.
    let a_lost = a.sync().unwrap().lost_rotation;
    let b_lost = b.sync().unwrap().lost_rotation;
    assert_ne!(a_lost, b_lost);
    let (mut winner, mut loser, winning_password, losing_password, reissued) = if a_lost {
        (
            b,
            a,
            phone_password,
            laptop_password,
            (X, "notes", "from the laptop"),
        )
    } else {
        (
            a,
            b,
            laptop_password,
            phone_password,
            (Y, "title", "from the phone"),
        )
    };
    assert!(matches!(
        loser.write(vec![set(X, "title", "x")]),
        Err(CoreError::KeyRotated)
    ));
    // Its own password opens only the losing key.
    assert!(matches!(
        loser.rejoin(Credential::Password(losing_password)),
        Err(CoreError::WrongCredential)
    ));
    let old_client = loser.client_id();
    loser
        .rejoin(Credential::Password(winning_password))
        .unwrap();
    assert_ne!(loser.client_id(), old_client);
    loser
        .write(vec![set(X, "title", "after rejoining")])
        .unwrap();

    winner.sync().unwrap();
    assert!(!loser.sync().unwrap().lost_rotation);
    let (entry, name, value) = reissued;
    assert_eq!(field(&winner, entry, name).as_deref(), Some(value));
    assert_eq!(
        field(&winner, X, "title").as_deref(),
        Some("after rejoining")
    );
    // Both sides changed the password during the race. Re-issued on the shared
    // history, the loser's change stays concurrent: a conflict, not an overwrite.
    assert_eq!(field(&winner, X, "password").as_deref(), Some("<conflict>"));
    assert_eq!(contents(&winner), contents(&loser));
}

#[test]
fn purge_leaves_nothing_of_the_entry_behind() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    a.write(vec![
        set(X, "password", "hunter2"),
        set(Y, "title", "keep me"),
    ])
    .unwrap();
    b.sync().unwrap();
    b.write(vec![set(X, "notes", "more")]).unwrap();
    b.write_snapshot().unwrap();

    let report = a.purge(X, PASSWORD).unwrap();
    assert_eq!(report.rotated.epoch, 1);
    assert_eq!(
        (
            report.events_left,
            report.snapshots_left,
            report.snapshots_deleted
        ),
        (0, 0, 1)
    );
    assert_eq!(event_count(&store), 0);
    assert_eq!(store.paths_in("snapshots").len(), 1);
    assert!(!a.view().entries.contains_key(&X));

    // B can't write a snapshot that brings X back; once caught up it agrees.
    assert!(matches!(b.write_snapshot(), Err(CoreError::KeyRotated)));
    let unlocked = unlock(&store, &b_local, Credential::Password(PASSWORD)).unwrap();
    let mut b = Session::new(&store, &b_local, unlocked, "Phone").unwrap();
    b.sync().unwrap();
    assert_eq!(contents(&b), contents(&a));
    let c_local = MemoryLocalStore::new();
    let c = open(&store, &c_local, "Tablet");
    assert!(!c.view().entries.contains_key(&X));
    assert_eq!(field(&c, Y, "title").as_deref(), Some("keep me"));
}

#[test]
fn a_vanished_epoch_record_is_a_rollback() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    for path in store.paths_in("epochs") {
        store.remove(&path);
    }
    assert_eq!(alarm(a.sync()), AlarmKind::Rollback);
}

#[test]
fn late_events_from_a_device_known_at_the_rotation_are_accepted_unflagged() {
    let (store, a_local) = new_vault();
    let mut a = open(&store, &a_local, "Laptop");
    let b_local = MemoryLocalStore::new();
    let mut b = open(&store, &b_local, "Phone");
    b.write(vec![set(X, "title", "before")]).unwrap();
    a.sync().unwrap();
    a.change_password(b"new password").unwrap();

    // B was offline during the rotation and wrote under the key it had.
    let seq = b.state.record.next_seq;
    let late = seal_as(
        &b,
        b.client_id(),
        seq,
        &b.device,
        vec![Op::SetField {
            entry_id: X,
            name: "title".into(),
            value: Some(SecretBytes::from_slice(b"written offline")),
            secret: false,
        }],
    );
    store.put(&event_path(b.client_id(), seq), late);
    a.sync().unwrap();
    assert_eq!(field(&a, X, "title").as_deref(), Some("written offline"));
    assert_eq!(a.review(), Review::default());
}
