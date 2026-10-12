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
            epoch: 0,
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
    #![proptest_config(ProptestConfig::with_cases(24))]

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
