//! A sync session (spec §9.1, §9.4): an unlocked vault, its op set, and the rules
//! for writing events and taking in other devices' events.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::RemoteStore;
use crate::crypto::random_id;
use crate::crypto::sign::DeviceKey;
use crate::error::{AlarmKind, CoreError, Result};
use crate::format::Id;
use crate::format::body::{Dot, EventBody, Op, RetainedOp, SnapshotBody, VectorClock};
use crate::format::epoch::{self, EpochRecord};
use crate::format::event::{self, EventHeader, SealedEvent};
use crate::format::names::FileName;
use crate::format::snapshot::{self, SealedSnapshot, SnapshotHeader};
use crate::keys::unlock::Unlocked;
use crate::keys::{Keyring, MAX_KEY_FILES};
use crate::local::{LocalState, LocalStore};
use crate::merge::edit::Edit;
use crate::merge::view::VaultView;
use crate::merge::{OpRecord, OpSet};
use crate::model::hlc;

/// Why an event is waiting rather than applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Held {
    /// Its epoch's key isn't known yet (a rotation this device hasn't caught up with).
    UnknownEpoch(u32),
    /// The writer's previous event hasn't arrived.
    MissingPredecessor,
    /// Events it depends on haven't arrived (spec §9.1 step 5).
    WaitingForDependencies,
}

/// What a file already at one of this device's own names is (see `create_own`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Existing {
    Same,
    Other,
    Junk,
}

#[derive(Debug, Default)]
pub struct SyncReport {
    pub applied: usize,
    /// This device's own events that were waiting to be uploaded, now uploaded.
    pub uploaded: usize,
    pub held: Vec<(String, Held)>,
    /// Files that aren't valid events, set aside (not alarms).
    pub rejected: Vec<(String, CoreError)>,
    /// Events whose HLC is more than a day ahead of this device's clock (spec §8.3).
    pub far_future: Vec<String>,
    /// Epoch records whose creator's device key isn't known yet, so their
    /// signatures couldn't be checked this time.
    pub unverified_epoch_records: usize,
    /// A newer epoch exists than this device holds: it can read but not write until
    /// it unlocks again (spec §7.2).
    pub key_rotated: bool,
    /// This device's local state was older than its own events in the vault (for
    /// example restored from a backup), so it became a new client (spec §9.4).
    pub identity_reset: bool,
    /// Snapshots loaded this time.
    pub snapshots_loaded: usize,
    /// Event files in the store, for deciding when to snapshot (`snapshot_due`).
    pub event_files: usize,
    /// Some high-water events are gone, but a snapshot under a key this device
    /// doesn't hold yet may cover them. Not an alarm, and not silence either: it
    /// can't be verified until the device unlocks again (it can't write meanwhile).
    pub integrity_unverified: bool,
    /// Another device rotated to the same epoch at the same time and its key won.
    /// This device can't write until it rejoins with that device's password.
    pub lost_rotation: bool,
}

/// Snapshot once this many event files have piled up (`Session::snapshot_due`).
pub const SNAPSHOT_WHEN_EVENT_FILES: usize = 512;

/// A snapshot's watermark: `(client, seq, H(c, seq))` (spec §10.1).
type Watermark = Vec<(Id, u64, [u8; 32])>;

/// A snapshot this session loaded.
struct LoadedSnapshot {
    /// The epoch it was sealed in.
    epoch: u32,
    creator: Id,
    watermark: Watermark,
}

impl LoadedSnapshot {
    /// How far its watermark reaches into its own creator's events.
    fn creator_seq(&self) -> u64 {
        watermark_seq(&self.watermark, &self.creator)
    }
}

fn watermark_seq(watermark: &Watermark, client: &Id) -> u64 {
    watermark
        .iter()
        .find(|(c, _, _)| c == client)
        .map_or(0, |&(_, seq, _)| seq)
}

/// Retired clients and the lowest `last_seq` each was retired at (spec §9.2).
type Retired = BTreeMap<Id, u64>;

fn note_retirement(retired: &mut Retired, op: &Op) {
    if let Op::RetireClient {
        client_id,
        last_seq,
    } = op
    {
        let limit = retired.entry(*client_id).or_insert(*last_seq);
        *limit = (*limit).min(*last_seq);
    }
}

/// Whether `signer` is retired and a file it signed reaches `seq` of its own events,
/// past its `last_seq` (spec §6.4): such snapshots and epoch records are rejected.
fn signed_after_retirement(retired: &Retired, signer: &Id, seq: u64) -> bool {
    retired.get(signer).is_some_and(|&last_seq| seq > last_seq)
}

fn retired_signer(what: &'static str) -> CoreError {
    CoreError::rejected(what, "signed by a retired device after its last change")
}

/// The garbage-collection grace period (spec §10.3, OPEN-9): 30 days.
pub const GC_GRACE_MS: u64 = 30 * 24 * 60 * 60 * 1000;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct GarbageReport {
    pub events_deleted: usize,
    pub snapshots_deleted: usize,
}

/// What the user should review (spec §7.2, §9.2): changes the merge kept but that
/// came from a device that shouldn't have been writing.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Review {
    /// Devices that registered under an old key after a rotation.
    pub suspect_devices: Vec<Id>,
    /// Ops of retired devices after their `last_seq`, and every op of suspect devices.
    pub flagged: Vec<Dot>,
}

struct AppliedEvent {
    hash: [u8; 32],
    hlc: u64,
    clock: VectorClock,
    /// `None` for an event compacted into a snapshot: only its hash is known.
    epoch: Option<u32>,
}

enum Outcome {
    Applied { far_future: bool },
    AlreadyApplied,
    Held(Held),
    Rejected(CoreError),
}

/// A sync session over stores held as `R` and `L`: borrowed (`Session`), or shared
/// through `Arc` where the session has to own them (the FFI).
pub struct SessionOf<R, L> {
    store: R,
    local: L,
    vault_id: Id,
    keyring: Keyring,
    /// Epoch records by path, refreshed on every sync.
    epoch_files: BTreeMap<String, Vec<u8>>,
    state: LocalState,
    device: DeviceKey,
    device_name: String,
    ops: OpSet,
    /// Per client, the highest seq applied. Events are applied in order, so this is
    /// also every event below it.
    applied: VectorClock,
    events: BTreeMap<(Id, u64), AppliedEvent>,
    /// Device keys from `RegisterDevice`, for checking signatures (spec §6.4).
    registry: BTreeMap<Id, [u8; 32]>,
    latest_hlc: u64,
    alarm: Option<AlarmKind>,
    /// A newer epoch exists than this device holds (spec §7.2).
    rotated_away: bool,
    snapshots: BTreeMap<Id, LoadedSnapshot>,
    /// Snapshots set aside after they loaded, once a retirement ruled them out (spec
    /// §6.4). They stay out for the rest of the session.
    retired_snapshots: BTreeSet<Id>,
    /// A snapshot sealed under an epoch this device doesn't hold exists.
    unreadable_snapshot: bool,
    /// Event files at the last sync.
    event_files: usize,
    /// Another device rotated to the same epoch concurrently and its key won
    /// (spec §7.2): no writing until `rejoin`.
    lost_rotation: bool,
}

/// The usual session, borrowing its stores.
pub type Session<'s> = SessionOf<&'s dyn RemoteStore, &'s dyn LocalStore>;

impl<R: RemoteStore, L: LocalStore> SessionOf<R, L> {
    /// A session for an unlocked vault. `device_name` is used if this device still
    /// has to register (its first event), so it's checked now rather than at the
    /// first write. Call `sync` next.
    ///
    /// One session per device at a time: two sessions sharing local state would
    /// both use the same next seq, and the second upload would look like a fork.
    pub fn new(store: R, local: L, unlocked: Unlocked, device_name: &str) -> Result<Self> {
        Op::SetDeviceName {
            name: device_name.to_string(),
        }
        .validate("device name")?;
        Ok(Self {
            store,
            local,
            vault_id: unlocked.vault_id,
            device: DeviceKey::from_seed(&unlocked.state.record.device_seed),
            rotated_away: unlocked.newer_epoch_unreachable,
            keyring: unlocked.keyring,
            epoch_files: unlocked.epoch_files.into_iter().collect(),
            state: unlocked.state,
            device_name: device_name.to_string(),
            ops: OpSet::new(),
            applied: VectorClock::default(),
            events: BTreeMap::new(),
            registry: BTreeMap::new(),
            latest_hlc: 0,
            alarm: None,
            snapshots: BTreeMap::new(),
            retired_snapshots: BTreeSet::new(),
            unreadable_snapshot: false,
            event_files: 0,
            lost_rotation: false,
        })
    }

    /// Another device rotated the vault key and this one doesn't hold the new key:
    /// no writing until it unlocks again (spec §7.2).
    pub fn key_rotated(&self) -> bool {
        self.rotated_away
    }

    /// Another device's key won a concurrent rotation: no writing until `rejoin`
    /// (spec §7.2).
    pub fn lost_rotation(&self) -> bool {
        self.lost_rotation
    }

    pub fn client_id(&self) -> Id {
        self.state.client_id
    }

    pub fn view(&self) -> VaultView<'_> {
        self.ops.view()
    }

    /// The alarm raised in this session, if any. Once set, nothing more is written.
    pub fn alarm(&self) -> Option<AlarmKind> {
        self.alarm
    }

    /// The epoch of the newest key this device holds.
    pub fn current_epoch(&self) -> u32 {
        self.keyring.current()
    }

    pub fn vault_id(&self) -> Id {
        self.vault_id
    }

    /// Clears the alarm and syncs again, after the user repaired the folder (spec
    /// §9.5). Every check runs afresh, so an alarm whose cause remains comes back.
    pub fn recheck(&mut self) -> Result<SyncReport> {
        self.alarm = None;
        self.sync()
    }

    fn raise(&mut self, kind: AlarmKind) -> CoreError {
        self.alarm = Some(kind);
        CoreError::Alarm(kind)
    }

    /// Uploads this device's pending events, then takes in every new event.
    pub fn sync(&mut self) -> Result<SyncReport> {
        let mut report = self.take_in()?;
        // A retirement can arrive after a snapshot it rules out: snapshots load
        // before events. Start again without that snapshot, so the result is what
        // seeing the retirement first would have given (spec §6.4).
        let ruled_out = self.snapshots_after_retirement();
        if !ruled_out.is_empty() {
            self.retired_snapshots.extend(ruled_out);
            self.forget_merged();
            let uploaded = report.uploaded;
            report = self.take_in()?;
            report.uploaded += uploaded;
        }

        if !report.integrity_unverified {
            self.check_high_water()?;
        }
        self.check_epoch_signatures(&mut report)?;
        // Needs the device registry, so after the events are in.
        self.lost_rotation = self.lost_to().is_some();
        report.lost_rotation = self.lost_rotation;
        if self.applied.get(&self.state.client_id) >= self.state.record.next_seq {
            self.become_new_client()?;
            report.identity_reset = true;
        }
        self.record_high_water();
        self.save()?;
        Ok(report)
    }

    /// The first half of `sync`: lists the store, loads new snapshots, uploads what's
    /// pending and applies every new event.
    fn take_in(&mut self) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        let mut paths = self.store.list()?;
        self.refresh_epoch_files(&paths)?;
        self.notice_newer_epoch();
        report.key_rotated = self.rotated_away;
        self.event_files = paths.iter().filter(|p| p.starts_with("events/")).count();
        report.event_files = self.event_files;
        self.unreadable_snapshot = false;
        self.load_snapshots(&paths, &mut report)?;
        self.check_stored_high_water(&paths, &mut report)?;
        // Nothing is uploaded after an alarm (spec §9.4), or while a newer key exists
        // that this device doesn't hold (spec §7.2).
        if self.alarm.is_none() && !self.rotated_away && !self.state.record.pending.is_empty() {
            self.flush_pending(&mut report)?;
            paths = self.store.list()?;
        }

        let mut waiting = Vec::new();
        for path in paths {
            let Some(name @ FileName::Event { client_id, seq }) = FileName::parse(&path) else {
                continue;
            };
            if seq <= self.applied.get(&client_id) {
                continue;
            }
            match self.read_event(&path, name) {
                Ok(bytes) => waiting.push((seq, path, bytes)),
                Err(e @ CoreError::UpdateRequired { .. }) => return Err(e),
                Err(e) => report.rejected.push((path, e)),
            }
        }
        // Lower seqs first: most events then apply on the first pass.
        waiting.sort_by_key(|(seq, _, _)| *seq);
        let mut waiting: Vec<(String, Vec<u8>)> = waiting
            .into_iter()
            .map(|(_, path, bytes)| (path, bytes))
            .collect();
        loop {
            let mut progress = false;
            let mut next = Vec::new();
            report.held.clear();
            for (path, bytes) in waiting {
                match self.try_apply(&bytes)? {
                    Outcome::Applied { far_future } => {
                        report.applied += 1;
                        progress = true;
                        if far_future {
                            report.far_future.push(path);
                        }
                    }
                    Outcome::AlreadyApplied => {}
                    Outcome::Held(reason) => {
                        report.held.push((path.clone(), reason));
                        next.push((path, bytes));
                    }
                    Outcome::Rejected(e) => report.rejected.push((path, e)),
                }
            }
            waiting = next;
            if !progress {
                break;
            }
        }
        Ok(report)
    }

    /// Drops everything learned from events and snapshots, so they can be taken in
    /// again from the store.
    fn forget_merged(&mut self) {
        self.ops = OpSet::new();
        self.applied = VectorClock::default();
        self.events.clear();
        self.registry.clear();
        self.latest_hlc = 0;
        self.snapshots.clear();
        self.unreadable_snapshot = false;
    }

    /// Every retired client in the op set, with its `last_seq` (spec §9.2).
    fn retired(&self) -> Retired {
        let mut retired = Retired::new();
        for record in self.ops.iter() {
            note_retirement(&mut retired, &record.op);
        }
        retired
    }

    /// Loaded snapshots whose creators are now known to have been retired before
    /// they wrote them (spec §6.4).
    fn snapshots_after_retirement(&self) -> Vec<Id> {
        let retired = self.retired();
        self.snapshots
            .iter()
            .filter(|(_, s)| signed_after_retirement(&retired, &s.creator, s.creator_seq()))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Writes `edits` as this device's next event (spec §8). The seq is persisted
    /// before the upload, and the event is kept as pending until the upload succeeds.
    pub fn write(&mut self, edits: Vec<Edit>) -> Result<()> {
        let ops = self.ops.ops_for(edits);
        self.write_ops(ops)
    }

    /// Refuses unless this device may write: no alarm, and it holds the newest key
    /// (spec §7.2), which also means it didn't lose a concurrent rotation.
    fn check_writable(&self) -> Result<()> {
        if let Some(kind) = self.alarm {
            return Err(CoreError::Alarm(kind));
        }
        if self.rotated_away || self.lost_rotation {
            return Err(CoreError::KeyRotated);
        }
        Ok(())
    }

    /// Sets `rotated_away` if the folder has an epoch record newer than this device's
    /// key (spec §7.2).
    /// Counts only records that parse, as unlock does (`refresh_epoch_files` runs
    /// first): a half-written record from a crashed rotation must not stop every
    /// device from writing.
    fn notice_newer_epoch(&mut self) {
        let current = self.keyring.current();
        if self.epoch_records().any(|r| r.epoch > current) {
            self.rotated_away = true;
        }
    }

    /// `check_writable` against a fresh listing: a device that hasn't synced since
    /// another device rotated must not write under the old key (spec §7.2). That
    /// matters most for purge, whose rotation is what stops a device that hasn't
    /// caught up from snapshotting the purged entry back into the vault.
    fn check_writable_now(&mut self) -> Result<()> {
        self.check_writable()?;
        let paths = self.store.list_dir("epochs")?;
        self.refresh_epoch_files(&paths)?;
        self.notice_newer_epoch();
        self.check_writable()
    }

    fn write_ops(&mut self, ops: Vec<Op>) -> Result<()> {
        let clock = self.applied.clone();
        self.write_event(ops, clock)
    }

    /// Writes `ops` as this device's next event, on top of `clock`: normally the
    /// applied clock, but `rejoin` passes the history shared before a lost rotation,
    /// so re-issued changes stay concurrent with what the winning side did since.
    fn write_event(&mut self, mut ops: Vec<Op>, mut clock: VectorClock) -> Result<()> {
        self.check_writable_now()?;
        let client = self.state.client_id;
        let seq = self.state.record.next_seq;
        if seq == 1 {
            ops.insert(
                0,
                Op::RegisterDevice {
                    client_id: client,
                    dev_pk: self.device.public_key(),
                    name: self.device_name.clone(),
                },
            );
        }
        let prev_hash = if seq == 1 {
            [0; 32]
        } else {
            self.events
                .get(&(client, seq - 1))
                .map(|e| e.hash)
                .ok_or(CoreError::rejected(
                    "event",
                    "this device's previous event isn't applied; sync first",
                ))?
        };
        clock.observe(client, seq);
        let body = EventBody {
            hlc: hlc::next(self.latest_hlc, hlc::now_ms())?,
            clock,
            prev_hash,
            ops,
        };
        let header = EventHeader {
            vault_id: self.vault_id,
            client_id: client,
            seq,
            epoch: self.keyring.current(),
        };
        let bytes = header.seal(
            &body,
            &self.keyring.current_keys().event,
            &self.device,
            None,
        )?;

        self.state.record.next_seq = seq + 1;
        self.state.record.pending.push(bytes.clone());
        self.save()?;
        self.upload(&bytes)?;
        self.state.record.pending.retain(|p| p != &bytes);
        match self.try_apply(&bytes)? {
            Outcome::Applied { .. } => {}
            _ => unreachable!("this device's own new event always applies"),
        }
        self.record_high_water();
        self.save()
    }

    /// What the user should review (spec §7.2, §9.2).
    pub fn review(&self) -> Review {
        let mut review = Review::default();
        let records: Vec<_> = self.epoch_records().collect();
        for &client in self.registry.keys() {
            let Some(first) = self.events.get(&(client, 1)) else {
                continue;
            };
            let rotated_without_it = records.iter().any(|r| {
                first.epoch.is_some_and(|e| r.epoch == e + 1)
                    && self
                        .keyring
                        .keys(r.epoch)
                        .is_some_and(|k| k.key_id == r.key_id)
                    && r.cutover.get(&client) == 0
            });
            if rotated_without_it {
                review.suspect_devices.push(client);
            }
        }
        let view = self.ops.view();
        for record in self.ops.iter() {
            let client = record.dot.client_id;
            let after_retirement = view
                .devices
                .get(&client)
                .and_then(|d| d.retired_after)
                .is_some_and(|last| record.dot.seq > last);
            if after_retirement || review.suspect_devices.contains(&client) {
                review.flagged.push(record.dot);
            }
        }
        review
    }

    fn read_event(&self, path: &str, name: FileName) -> Result<Vec<u8>> {
        let bytes = self.store.read(path, event::MAX_FILE_LEN)?;
        let sealed = SealedEvent::parse(&bytes, &self.vault_id)?;
        name.expect(sealed.header.file_name())?;
        Ok(bytes)
    }

    /// One event through spec §9.1. Errors are alarms only; an invalid event is an
    /// `Outcome::Rejected`.
    fn try_apply(&mut self, bytes: &[u8]) -> Result<Outcome> {
        let sealed = match SealedEvent::parse(bytes, &self.vault_id) {
            Ok(s) => s,
            Err(e) => return Ok(Outcome::Rejected(e)),
        };
        let header = sealed.header;
        let (client, seq) = (header.client_id, header.seq);
        if seq <= self.applied.get(&client) {
            return Ok(Outcome::AlreadyApplied);
        }
        if seq > 1 && self.applied.get(&client) < seq - 1 {
            return Ok(Outcome::Held(Held::MissingPredecessor));
        }
        let Some(keys) = self.keyring.keys(header.epoch) else {
            return Ok(Outcome::Held(Held::UnknownEpoch(header.epoch)));
        };
        let body = match sealed.open(&keys.event) {
            Ok(body) => body,
            Err(e) => return Ok(Outcome::Rejected(e)),
        };
        if body
            .clock
            .0
            .iter()
            .any(|(c, s)| *c != client && self.applied.get(c) < *s)
        {
            return Ok(Outcome::Held(Held::WaitingForDependencies));
        }

        let dev_pk = if seq == 1 {
            match &body.ops[0] {
                Op::RegisterDevice { dev_pk, .. } => *dev_pk,
                _ => unreachable!("validated: op 0 of a first event registers the device"),
            }
        } else {
            self.registry[&client]
        };
        if !sealed.signature_valid(&dev_pk) {
            return Err(self.raise(AlarmKind::Forgery));
        }
        if seq > 1 {
            let prev = &self.events[&(client, seq - 1)];
            if body.prev_hash != prev.hash {
                return Err(self.raise(AlarmKind::Fork));
            }
            if !body.clock.covers(&prev.clock) || body.hlc <= prev.hlc {
                return Ok(Outcome::Rejected(CoreError::rejected(
                    "event",
                    "goes back in time from its predecessor",
                )));
            }
        }

        if seq == 1 {
            self.registry.insert(client, dev_pk);
        }
        self.events.insert(
            (client, seq),
            AppliedEvent {
                hash: Sha256::digest(bytes).into(),
                hlc: body.hlc,
                clock: body.clock.clone(),
                epoch: Some(header.epoch),
            },
        );
        self.applied.observe(client, seq);
        self.latest_hlc = self.latest_hlc.max(body.hlc);
        let far_future = hlc::is_far_future(body.hlc, hlc::now_ms());
        self.ops.apply_event(client, seq, body);
        Ok(Outcome::Applied { far_future })
    }

    /// Spec §9.4, against the store: every high-water event must still be listed,
    /// with the hash this device recorded. Runs on every sync, so a long-running
    /// session notices deleted or replaced files, not just a fresh one.
    ///
    /// A compacted event is fine if a loaded snapshot's watermark covers it (spec
    /// §10.2); when the watermark names exactly that seq, its hash must match.
    fn check_stored_high_water(&mut self, paths: &[String], report: &mut SyncReport) -> Result<()> {
        let marks = self.state.record.high_water.clone();
        for (client, seq, hash) in marks {
            let path = FileName::Event {
                client_id: client,
                seq,
            }
            .to_path();
            if paths.binary_search(&path).is_ok() {
                let bytes = self.store.read(&path, event::MAX_FILE_LEN)?;
                if <[u8; 32]>::from(Sha256::digest(&bytes)) != hash {
                    return Err(self.raise(AlarmKind::Fork));
                }
                continue;
            }
            let mut covered = false;
            // Only snapshots still in the store count. One loaded earlier and deleted
            // since covers nothing, or deleting the newest snapshot would go unnoticed.
            let present = self.snapshots.iter().filter(|(id, _)| {
                paths
                    .binary_search(&FileName::Snapshot { snapshot_id: **id }.to_path())
                    .is_ok()
            });
            for (_, snapshot) in present {
                for &(c, s, h) in &snapshot.watermark {
                    if c == client && s >= seq {
                        if s == seq && h != hash {
                            return Err(self.raise(AlarmKind::Fork));
                        }
                        covered = true;
                    }
                }
            }
            if !covered {
                if self.unreadable_snapshot {
                    report.integrity_unverified = true;
                    continue;
                }
                return Err(self.raise(AlarmKind::Rollback));
            }
        }
        Ok(())
    }

    /// Spec §9.4, against what was applied: an event that is listed but couldn't be
    /// applied (say its dependencies vanished) is just as missing. A mark below a
    /// snapshot watermark has no applied event to compare; the store check covered it.
    fn check_high_water(&mut self) -> Result<()> {
        let marks = self.state.record.high_water.clone();
        for (client, seq, hash) in marks {
            if self.applied.get(&client) < seq {
                return Err(self.raise(AlarmKind::Rollback));
            }
            if self
                .events
                .get(&(client, seq))
                .is_some_and(|e| e.hash != hash)
            {
                return Err(self.raise(AlarmKind::Fork));
            }
        }
        Ok(())
    }

    /// Loads every snapshot not yet loaded (spec §10.2).
    fn load_snapshots(&mut self, paths: &[String], report: &mut SyncReport) -> Result<()> {
        for path in paths {
            let Some(name @ FileName::Snapshot { snapshot_id }) = FileName::parse(path) else {
                continue;
            };
            if self.snapshots.contains_key(&snapshot_id) {
                continue;
            }
            if self.retired_snapshots.contains(&snapshot_id) {
                report
                    .rejected
                    .push((path.clone(), retired_signer("snapshot")));
                continue;
            }
            let bytes = match self.store.read(path, snapshot::MAX_FILE_LEN) {
                Ok(bytes) => bytes,
                Err(e @ CoreError::Rejected { .. }) => {
                    report.rejected.push((path.clone(), e));
                    continue;
                }
                Err(e) => return Err(e),
            };
            match self.load_snapshot(&bytes, name)? {
                Some(e) => report.rejected.push((path.clone(), e)),
                None => report.snapshots_loaded += 1,
            }
        }
        Ok(())
    }

    /// One snapshot. `Ok(Some(e))` sets it aside; errors are alarms.
    fn load_snapshot(&mut self, bytes: &[u8], name: FileName) -> Result<Option<CoreError>> {
        let sealed = match SealedSnapshot::parse(bytes, &self.vault_id)
            .and_then(|s| name.expect(s.header.file_name()).map(|()| s))
        {
            Ok(s) => s,
            Err(e @ CoreError::UpdateRequired { .. }) => return Err(e),
            Err(e) => return Ok(Some(e)),
        };
        let header = sealed.header;
        let Some(keys) = self.keyring.keys(header.epoch) else {
            // A newer epoch this device can't open yet: try again after unlocking.
            self.unreadable_snapshot = true;
            return Ok(Some(CoreError::rejected("snapshot", "epoch key not held")));
        };
        let body = match sealed.open(&keys.snapshot) {
            Ok(body) => body,
            Err(e) => return Ok(Some(e)),
        };

        // The creator's key: as already known, or else from its own registration,
        // which reduction never drops (trust on first use, spec §10.2).
        let own_registration = body.ops.iter().find_map(|r| match &r.op {
            Op::RegisterDevice {
                client_id, dev_pk, ..
            } if *client_id == header.creator => Some(*dev_pk),
            _ => None,
        });
        let Some(creator_pk) = self
            .registry
            .get(&header.creator)
            .copied()
            .or(own_registration)
        else {
            return Ok(Some(CoreError::rejected(
                "snapshot",
                "creator isn't registered",
            )));
        };
        if !sealed.signature_valid(&creator_pk) {
            return Err(self.raise(AlarmKind::Forgery));
        }
        // Retirements in the snapshot count too, so the verdict doesn't depend on
        // whether this device had already applied them (spec §6.4).
        let mut retired = self.retired();
        for retained in &body.ops {
            note_retirement(&mut retired, &retained.op);
        }
        let creator_seq = watermark_seq(&body.watermark, &header.creator);
        if signed_after_retirement(&retired, &header.creator, creator_seq) {
            return Ok(Some(retired_signer("snapshot")));
        }
        for &(client, seq, hash) in &body.watermark {
            if self
                .events
                .get(&(client, seq))
                .is_some_and(|e| e.hash != hash)
            {
                return Err(self.raise(AlarmKind::Fork));
            }
        }

        let clocks: Vec<Arc<VectorClock>> = body.clocks.into_iter().map(Arc::new).collect();
        for retained in body.ops {
            if let Op::RegisterDevice {
                client_id, dev_pk, ..
            } = &retained.op
            {
                self.registry.entry(*client_id).or_insert(*dev_pk);
            }
            self.latest_hlc = self.latest_hlc.max(retained.hlc);
            self.ops.insert(OpRecord {
                dot: retained.dot,
                hlc: retained.hlc,
                clock: Arc::clone(&clocks[retained.vc_index as usize]),
                op: retained.op,
            });
        }
        // Everything up to the watermark now counts as applied; the watermark hash
        // stands in for the compacted predecessor (spec §9.1).
        for &(client, seq, hash) in &body.watermark {
            if self.applied.get(&client) < seq {
                self.applied.observe(client, seq);
                self.events.insert(
                    (client, seq),
                    AppliedEvent {
                        hash,
                        hlc: 0,
                        clock: VectorClock::default(),
                        epoch: None,
                    },
                );
            }
        }
        self.snapshots.insert(
            header.snapshot_id,
            LoadedSnapshot {
                epoch: header.epoch,
                creator: header.creator,
                watermark: body.watermark,
            },
        );
        Ok(None)
    }

    /// Whether it's time for this device to write a snapshot: once the store holds
    /// `SNAPSHOT_WHEN_EVENT_FILES` event files, so a new device doesn't have to
    /// replay thousands of them. Only a registered device can sign a usable one.
    pub fn snapshot_due(&self) -> bool {
        self.event_files >= SNAPSHOT_WHEN_EVENT_FILES
            && self.applied.get(&self.state.client_id) > 0
            && self.alarm.is_none()
            && !self.rotated_away
    }

    /// Writes a snapshot of this device's reduced op set (spec §10.3).
    pub fn write_snapshot(&mut self) -> Result<Id> {
        self.check_writable_now()?;
        let client = self.state.client_id;
        if self.applied.get(&client) == 0 {
            // Others verify the snapshot with this device's key, so it must be registered.
            return Err(CoreError::rejected(
                "snapshot",
                "this device hasn't written yet",
            ));
        }
        self.ops.reduce();
        let mut clocks = Vec::new();
        let mut clock_index: HashMap<*const VectorClock, u32> = HashMap::new();
        let mut ops = Vec::with_capacity(self.ops.len());
        for record in self.ops.iter() {
            let vc_index = *clock_index
                .entry(Arc::as_ptr(&record.clock))
                .or_insert_with(|| {
                    clocks.push(VectorClock::clone(&record.clock));
                    (clocks.len() - 1) as u32
                });
            ops.push(RetainedOp {
                dot: record.dot,
                hlc: record.hlc,
                vc_index,
                op: record.op.duplicate(),
            });
        }
        let watermark: Vec<_> = self
            .applied
            .0
            .iter()
            .map(|&(c, s)| (c, s, self.events[&(c, s)].hash))
            .collect();
        let snapshot_id = random_id()?;
        let header = SnapshotHeader {
            vault_id: self.vault_id,
            snapshot_id,
            creator: client,
            epoch: self.keyring.current(),
        };
        let body = SnapshotBody {
            watermark,
            clocks,
            ops,
        };
        let bytes = header.seal(
            &body,
            &self.keyring.current_keys().snapshot,
            &self.device,
            None,
        )?;
        self.store.create(&header.file_name().to_path(), &bytes)?;
        self.state
            .record
            .snapshots
            .push((snapshot_id, hlc::now_ms()));
        self.snapshots.insert(
            snapshot_id,
            LoadedSnapshot {
                epoch: header.epoch,
                creator: client,
                watermark: body.watermark,
            },
        );
        self.save()?;
        Ok(snapshot_id)
    }

    /// Deletes what this device's own snapshots make redundant, once they have
    /// existed for `grace_ms` (spec §10.3): the event files under their watermark,
    /// and this device's older snapshots they dominate. Never acts on another
    /// device's snapshot.
    pub fn collect_garbage(&mut self, grace_ms: u64) -> Result<GarbageReport> {
        self.check_writable()?;
        let now = hlc::now_ms();
        let mut report = GarbageReport::default();
        // Newest first, so that of two snapshots with equal watermarks (each "dominating"
        // the other) the newer is kept and the older deleted, never both.
        let mut ripe: Vec<(Id, u64)> = self
            .state
            .record
            .snapshots
            .iter()
            .filter(|(id, created)| {
                now.saturating_sub(*created) >= grace_ms && self.snapshots.contains_key(id)
            })
            .copied()
            .collect();
        if ripe.is_empty() {
            return Ok(report); // nothing to act on, so no need to list the store
        }
        ripe.sort_by_key(|&(_, created)| std::cmp::Reverse(created));
        let paths = self.store.list()?;
        for (id, _) in ripe {
            if !self.state.record.snapshots.iter().any(|(s, _)| *s == id) {
                continue; // already deleted as dominated by a newer one
            }
            let watermark = self.snapshots[&id].watermark.clone();
            let covers =
                |client: &Id, seq: u64| watermark.iter().any(|(c, s, _)| c == client && seq <= *s);
            for path in &paths {
                if let Some(FileName::Event { client_id, seq }) = FileName::parse(path)
                    && covers(&client_id, seq)
                    && self.delete_if_present(path)?
                {
                    report.events_deleted += 1;
                }
            }
            let dominated: Vec<Id> = self
                .state
                .record
                .snapshots
                .iter()
                .map(|(other, _)| *other)
                .filter(|other| {
                    *other != id
                        && self
                            .snapshots
                            .get(other)
                            .is_some_and(|s| s.watermark.iter().all(|(c, s, _)| covers(c, *s)))
                })
                .collect();
            for other in dominated {
                let path = FileName::Snapshot { snapshot_id: other }.to_path();
                if self.delete_if_present(&path)? {
                    report.snapshots_deleted += 1;
                }
                self.state.record.snapshots.retain(|(s, _)| *s != other);
            }
        }
        self.save()?;
        Ok(report)
    }

    fn delete_if_present(&self, path: &str) -> Result<bool> {
        match self.store.delete(path) {
            Ok(()) => Ok(true),
            Err(CoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Reads the epoch records that appeared since the last look (spec §7.1). The map
    /// follows the listing, and the pinned record must still be in it: records are
    /// never deleted, so a missing one means the storage went back in time (§6.3).
    fn refresh_epoch_files(&mut self, paths: &[String]) -> Result<()> {
        let listed: Vec<(&String, FileName)> = paths
            .iter()
            .filter_map(|p| match FileName::parse(p) {
                Some(name @ FileName::Epoch { .. }) => Some((p, name)),
                _ => None,
            })
            .collect();
        if listed.len() > MAX_KEY_FILES {
            return Err(CoreError::rejected("vault", "too many epoch files"));
        }
        self.epoch_files
            .retain(|path, _| paths.binary_search(path).is_ok());
        for (path, name) in listed {
            if self.epoch_files.contains_key(path) {
                continue;
            }
            let bytes = match self.store.read(path, epoch::MAX_LEN) {
                Ok(bytes) => bytes,
                Err(CoreError::Rejected { .. }) => continue,
                Err(e) => return Err(e),
            };
            match EpochRecord::parse(&bytes, &self.vault_id)
                .and_then(|r| name.expect(r.file_name()))
            {
                Ok(()) => {}
                Err(e @ CoreError::UpdateRequired { .. }) => return Err(e),
                // Set aside, as at unlock: one bad file mustn't block the others.
                Err(_) => continue,
            }
            self.epoch_files.insert(path.clone(), bytes);
        }
        let pin = self.state.pin;
        if !self
            .epoch_records()
            .any(|r| r.epoch == pin.epoch && r.key_id == pin.key_id)
        {
            return Err(self.raise(AlarmKind::Rollback));
        }
        Ok(())
    }

    /// The epoch records that parse. Only parsed records are kept, so this drops none
    /// in practice.
    fn epoch_records(&self) -> impl Iterator<Item = EpochRecord<'_>> {
        self.epoch_files
            .values()
            .filter_map(|bytes| EpochRecord::parse(bytes, &self.vault_id).ok())
    }

    /// The lowest key ID among records for `epoch` that beat `ours` (spec §7.2): a
    /// lower key ID, signed by a registered device that isn't retired. Unverifiable
    /// records never win, so storage alone can't make a device give up its key, and
    /// neither can a revoked device holding the previous key, even with a record it
    /// was allowed to sign (spec §6.4).
    fn competing_winner(&self, epoch: u32, ours: &[u8; 32]) -> Option<[u8; 32]> {
        let retired = self.retired();
        self.epoch_records()
            .filter(|r| r.epoch == epoch && r.key_id < *ours && !retired.contains_key(&r.creator))
            .filter(|r| {
                self.registry
                    .get(&r.creator)
                    .is_some_and(|pk| r.signature_valid(pk))
            })
            .map(|r| r.key_id)
            .min()
    }

    /// The key that beat this device's current one in a concurrent rotation, if any.
    /// Only the current epoch is contested (spec §7.2): rotating syncs first, so no
    /// device builds on a key it has seen lose, and once an epoch is behind the
    /// vault, no record written later can reopen it.
    fn lost_to(&self) -> Option<[u8; 32]> {
        let current = self.keyring.current();
        if current == 0 {
            return None; // a vault is created once
        }
        self.competing_winner(current, &self.keyring.current_keys().key_id)
    }

    /// Epoch-record signatures (spec §6.4), checked once the creator is registered.
    /// A record a retired device signed after its `last_seq` is rejected. Records are
    /// checked on every sync, so a retirement that arrives later still counts.
    fn check_epoch_signatures(&mut self, report: &mut SyncReport) -> Result<()> {
        let retired = self.retired();
        let mut forged = false;
        for (path, bytes) in &self.epoch_files {
            let Ok(record) = EpochRecord::parse(bytes, &self.vault_id) else {
                continue;
            };
            match self.registry.get(&record.creator) {
                Some(pk) if !record.signature_valid(pk) => forged = true,
                Some(_) => {
                    let seq = record.cutover.get(&record.creator);
                    if signed_after_retirement(&retired, &record.creator, seq) {
                        report
                            .rejected
                            .push((path.clone(), retired_signer("epoch record")));
                    }
                }
                None => report.unverified_epoch_records += 1,
            }
        }
        if forged {
            return Err(self.raise(AlarmKind::Forgery));
        }
        Ok(())
    }

    fn record_high_water(&mut self) {
        self.state.record.high_water = self
            .applied
            .0
            .iter()
            .map(|&(client, seq)| (client, seq, self.events[&(client, seq)].hash))
            .collect();
    }

    /// Spec §9.4: local state older than this device's own events means its seq
    /// counter went backwards. Carrying on would reuse seqs, so the device becomes a
    /// new client with a new key, keeping everything it has learned.
    fn become_new_client(&mut self) -> Result<()> {
        self.device = DeviceKey::generate()?;
        self.state.client_id = random_id()?;
        self.state.record.device_seed = self.device.seed();
        self.state.record.next_seq = 1;
        self.state.record.pending.clear();
        Ok(())
    }

    fn flush_pending(&mut self, report: &mut SyncReport) -> Result<()> {
        for bytes in self.state.record.pending.clone() {
            let fresh = self.reseal_for_current_epoch(&bytes)?;
            self.upload(&fresh)?;
            self.state.record.pending.retain(|p| p != &bytes);
            report.uploaded += 1;
        }
        Ok(())
    }

    /// A pending event sealed under an older epoch was never published, so its seq is
    /// still free: re-seal the same body under the current epoch rather than publish
    /// it under a key a revoked device may hold (spec §7.2).
    fn reseal_for_current_epoch(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let sealed = SealedEvent::parse(bytes, &self.vault_id)?;
        let current = self.keyring.current();
        if sealed.header.epoch == current {
            return Ok(bytes.to_vec());
        }
        let old_keys = self
            .keyring
            .keys(sealed.header.epoch)
            .ok_or(CoreError::rejected(
                "pending event",
                "its epoch key is gone",
            ))?;
        let body = sealed.open(&old_keys.event)?;
        EventHeader {
            epoch: current,
            ..sealed.header
        }
        .seal(
            &body,
            &self.keyring.current_keys().event,
            &self.device,
            None,
        )
    }

    /// Creates the event's file. An existing file with the same bytes is a retry
    /// that already succeeded; different bytes mean the seq was used twice.
    fn upload(&mut self, bytes: &[u8]) -> Result<()> {
        let header = SealedEvent::parse(bytes, &self.vault_id)?.header;
        let path = header.file_name().to_path();
        let existing = self.create_own(&path, bytes, event::MAX_FILE_LEN, |there| {
            self.judge_event(there, bytes)
        })?;
        match existing {
            None | Some(Existing::Same) => Ok(()),
            Some(Existing::Other | Existing::Junk) => Err(self.raise(AlarmKind::Fork)),
        }
    }

    /// Creates a file only this device ever writes: one of its events or epoch
    /// records. `None` once created. If the name is taken, `judge` says what's there:
    /// - the same thing: a retry of a write that succeeded;
    /// - something else this device signed: a fork, for the caller to handle;
    /// - junk, which doesn't verify: what a write that crashed half way leaves on
    ///   storage without atomic renames (spec §5). It is replaced: nobody else writes
    ///   this name, and a file that fails verification is nobody's data.
    pub(crate) fn create_own(
        &self,
        path: &str,
        bytes: &[u8],
        max_len: usize,
        judge: impl Fn(&[u8]) -> Existing,
    ) -> Result<Option<Existing>> {
        let taken = |e: &CoreError| matches!(e, CoreError::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists);
        match self.store.create(path, bytes) {
            Ok(()) => return Ok(None),
            Err(e) if taken(&e) => {}
            Err(e) => return Err(e),
        }
        let verdict = match self.store.read(path, max_len) {
            Ok(there) => judge(&there),
            // Too large to be anything this device wrote.
            Err(CoreError::Rejected { .. }) => Existing::Junk,
            Err(CoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Existing::Junk,
            Err(e) => return Err(e),
        };
        if verdict != Existing::Junk {
            return Ok(Some(verdict));
        }
        match self.store.delete(path) {
            Err(CoreError::Io(e)) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(CoreError::Io(e));
            }
            _ => {}
        }
        match self.store.create(path, bytes) {
            Ok(()) => Ok(None),
            // Taken again at once: not a leftover, so not something to replace twice.
            Err(e) if taken(&e) => Ok(Some(Existing::Junk)),
            Err(e) => Err(e),
        }
    }

    /// What a file found at the name of `ours`, one of this device's events, is.
    fn judge_event(&self, there: &[u8], ours: &[u8]) -> Existing {
        if there == ours {
            return Existing::Same;
        }
        let Ok(sealed) = SealedEvent::parse(there, &self.vault_id) else {
            return Existing::Junk;
        };
        let Ok(mine) = SealedEvent::parse(ours, &self.vault_id) else {
            return Existing::Other;
        };
        if sealed.header.file_name() != mine.header.file_name()
            || !sealed.signature_valid(&self.device.public_key())
        {
            return Existing::Junk;
        }
        // Signed by this device: the same change, perhaps sealed under an older
        // epoch before a crash, or a different one (a fork).
        let body = |e: &SealedEvent<'_>| {
            self.keyring
                .keys(e.header.epoch)
                .and_then(|k| e.open(&k.event).ok())
        };
        match (body(&sealed), body(&mine)) {
            (Some(a), Some(b)) if a == b => Existing::Same,
            _ => Existing::Other,
        }
    }

    fn save(&self) -> Result<()> {
        let pin_keys = self
            .keyring
            .keys(self.state.pin.epoch)
            .expect("the pinned epoch is in the keyring");
        self.local.save(&self.vault_id, &self.state.seal(pin_keys)?)
    }
}

mod local_slots;
mod rotate;

pub use local_slots::LocalSlot;
pub use rotate::{PurgeReport, RecoveryChoice, Rotated};

#[cfg(test)]
mod tests;
