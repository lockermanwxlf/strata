//! A sync session (spec §9.1, §9.4): an unlocked vault, its op set, and the rules
//! for writing events and taking in other devices' events.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::RemoteStore;
use crate::crypto::random_id;
use crate::crypto::sign::DeviceKey;
use crate::error::{AlarmKind, CoreError, Result};
use crate::format::Id;
use crate::format::body::{Dot, EventBody, Op, VectorClock};
use crate::format::epoch::EpochRecord;
use crate::format::event::{self, EventHeader, SealedEvent};
use crate::format::names::FileName;
use crate::keys::Keyring;
use crate::keys::unlock::Unlocked;
use crate::local::{LocalState, LocalStore};
use crate::merge::OpSet;
use crate::merge::edit::Edit;
use crate::merge::view::VaultView;
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
    epoch: u32,
}

enum Outcome {
    Applied { far_future: bool },
    AlreadyApplied,
    Held(Held),
    Rejected(CoreError),
}

pub struct Session<'s> {
    store: &'s dyn RemoteStore,
    local: &'s dyn LocalStore,
    vault_id: Id,
    keyring: Keyring,
    epoch_files: Vec<Vec<u8>>,
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
}

impl<'s> Session<'s> {
    /// A session for an unlocked vault. `device_name` is used if this device still
    /// has to register (its first event), so it's checked now rather than at the
    /// first write. Call `sync` next.
    ///
    /// One session per device at a time: two sessions sharing local state would
    /// both use the same next seq, and the second upload would look like a fork.
    pub fn new(
        store: &'s dyn RemoteStore,
        local: &'s dyn LocalStore,
        unlocked: Unlocked,
        device_name: &str,
    ) -> Result<Self> {
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
            epoch_files: unlocked.epoch_files,
            state: unlocked.state,
            device_name: device_name.to_string(),
            ops: OpSet::new(),
            applied: VectorClock::default(),
            events: BTreeMap::new(),
            registry: BTreeMap::new(),
            latest_hlc: 0,
            alarm: None,
        })
    }

    /// Another device rotated the vault key and this one doesn't hold the new key:
    /// no writing until it unlocks again (spec §7.2).
    pub fn key_rotated(&self) -> bool {
        self.rotated_away
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

    fn raise(&mut self, kind: AlarmKind) -> CoreError {
        self.alarm = Some(kind);
        CoreError::Alarm(kind)
    }

    /// Uploads this device's pending events, then takes in every new event.
    pub fn sync(&mut self) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        let mut paths = self.store.list()?;
        let current = self.keyring.current();
        if paths.iter().any(|p| {
            matches!(FileName::parse(p), Some(FileName::Epoch { epoch, .. }) if epoch > current)
        }) {
            self.rotated_away = true;
        }
        report.key_rotated = self.rotated_away;
        self.check_stored_high_water(&paths)?;
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

        self.check_high_water()?;
        self.check_epoch_signatures(&mut report)?;
        if self.applied.get(&self.state.client_id) >= self.state.record.next_seq {
            self.become_new_client()?;
            report.identity_reset = true;
        }
        self.record_high_water();
        self.save()?;
        Ok(report)
    }

    /// Writes `edits` as this device's next event (spec §8). The seq is persisted
    /// before the upload, and the event is kept as pending until the upload succeeds.
    pub fn write(&mut self, edits: Vec<Edit>) -> Result<()> {
        if let Some(kind) = self.alarm {
            return Err(CoreError::Alarm(kind));
        }
        if self.rotated_away {
            return Err(CoreError::KeyRotated);
        }
        let client = self.state.client_id;
        let seq = self.state.record.next_seq;
        let mut ops = self.ops.ops_for(edits);
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
        let mut clock = self.applied.clone();
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
        let records: Vec<_> = self
            .epoch_files
            .iter()
            .filter_map(|bytes| EpochRecord::parse(bytes, &self.vault_id).ok())
            .collect();
        for &client in self.registry.keys() {
            let Some(first) = self.events.get(&(client, 1)) else {
                continue;
            };
            let rotated_without_it = records.iter().any(|r| {
                r.epoch == first.epoch + 1
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
                epoch: header.epoch,
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
    fn check_stored_high_water(&mut self, paths: &[String]) -> Result<()> {
        let marks = self.state.record.high_water.clone();
        for (client, seq, hash) in marks {
            let path = FileName::Event {
                client_id: client,
                seq,
            }
            .to_path();
            if paths.binary_search(&path).is_err() {
                return Err(self.raise(AlarmKind::Rollback));
            }
            let bytes = self.store.read(&path, event::MAX_FILE_LEN)?;
            if <[u8; 32]>::from(Sha256::digest(&bytes)) != hash {
                return Err(self.raise(AlarmKind::Fork));
            }
        }
        Ok(())
    }

    /// Spec §9.4, against what was applied: an event that is listed but couldn't be
    /// applied (say its dependencies vanished) is just as missing.
    fn check_high_water(&mut self) -> Result<()> {
        let marks = self.state.record.high_water.clone();
        for (client, seq, hash) in marks {
            if self.applied.get(&client) < seq {
                return Err(self.raise(AlarmKind::Rollback));
            }
            if self.events[&(client, seq)].hash != hash {
                return Err(self.raise(AlarmKind::Fork));
            }
        }
        Ok(())
    }

    /// Epoch-record signatures (spec §6.4), checked once the creator is registered.
    fn check_epoch_signatures(&mut self, report: &mut SyncReport) -> Result<()> {
        let mut forged = false;
        for bytes in &self.epoch_files {
            let Ok(record) = EpochRecord::parse(bytes, &self.vault_id) else {
                continue;
            };
            match self.registry.get(&record.creator) {
                Some(pk) if !record.signature_valid(pk) => forged = true,
                Some(_) => {}
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
        match self.store.create(&path, bytes) {
            Ok(()) => Ok(()),
            Err(CoreError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if self.store.read(&path, event::MAX_FILE_LEN)? == bytes {
                    Ok(())
                } else {
                    Err(self.raise(AlarmKind::Fork))
                }
            }
            Err(e) => Err(e),
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

#[cfg(test)]
mod tests;
