//! Rotation and key management (spec §7.2, §6.2.1, §10.4): new epochs, changing the
//! password or recovery key, revoking devices, concurrent rotations, purge, and
//! reverting flagged changes.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use super::{Existing, SessionOf, Watermark};
use crate::crypto::kdf::{self, Argon2Params, EpochKeys};
use crate::crypto::recovery::{self, RecoveryKeyPair};
use crate::crypto::{SecretBytes, SecretKey, fill_random, random_id};
use crate::error::{CoreError, Result};
use crate::format::Id;
use crate::format::body::{Dot, Op, VectorClock};
use crate::format::epoch::{self, ChainWrap, EpochRecord, NewEpoch};
use crate::format::event::SealedEvent;
use crate::format::names::FileName;
use crate::format::slot::{self, SlotParams};
use crate::keys::VaultFiles;
use crate::keys::unlock::{Credential, open_keyring};
use crate::local::LocalStore;
use crate::local::Pin;
use crate::merge::OpSet;
use crate::merge::edit::Edit;
use crate::merge::view::{EntryView, Field};
use crate::sync::RemoteStore;

/// What a rotation does with the recovery key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryChoice {
    /// Re-wrap the new key to the current recovery key. The words aren't needed.
    Keep,
    /// Generate a new recovery key. The old one stops working.
    Replace,
}

#[derive(Debug)]
pub struct Rotated {
    pub epoch: u32,
    /// The new 24 recovery words when the rotation replaced the recovery key. Shown
    /// to the user once; never stored.
    pub recovery_words: Option<SecretBytes>,
    /// The vault had a recovery key but no slot for it could be found, so the new
    /// epoch has none. The UI should offer to create a new one.
    pub recovery_lost: bool,
}

#[derive(Debug)]
pub struct PurgeReport {
    pub rotated: Rotated,
    pub events_deleted: usize,
    pub snapshots_deleted: usize,
    /// Event files the purge snapshot doesn't cover: written concurrently, or not yet
    /// applied here. They may still mention the entry.
    pub events_left: usize,
    /// Snapshots this device couldn't read, left in place. They may too.
    pub snapshots_left: usize,
}

impl<R: RemoteStore, L: LocalStore> SessionOf<R, L> {
    /// Rotates to a new epoch (spec §7.2). `password` goes into the new epoch's
    /// password slot. It is the new password when this is a password change.
    ///
    /// Slots go up before the epoch record: without a record they are never tried
    /// (spec §6.3 step 2), whereas a record without slots would leave the new epoch
    /// unreachable for every device. Old slots are deleted last.
    pub fn rotate(&mut self, password: &[u8], recovery: RecoveryChoice) -> Result<Rotated> {
        self.check_writable()?;
        self.sync()?;
        self.check_writable()?;
        let client = self.state.client_id;
        if self.applied.get(&client) == 0 {
            // Others check the record's signature against this device's registration.
            self.write_ops(Vec::new())?;
        }
        let vault_id = self.vault_id;
        let current = self.keyring.current();
        let next = current
            .checked_add(1)
            .ok_or(CoreError::rejected("rotation", "no epochs left"))?;
        let ek = SecretKey::generate()?;
        let keys = EpochKeys::derive(&vault_id, &ek);

        let files = VaultFiles::load(&self.store)?;
        let mut set_aside = Vec::new();
        let old_slots: Vec<(String, u32, SlotParams)> = files
            .slots(&mut set_aside)?
            .into_iter()
            .map(|s| (s.file_name().to_path(), s.epoch, s.params.clone()))
            .collect();

        let mut recovery_words = None;
        let mut recovery_lost = false;
        let recovery_params = match recovery {
            RecoveryChoice::Keep => match self.recovery_named(current).as_slice() {
                [] => None,
                [hash] => {
                    let found = old_slots.iter().find_map(|(_, _, params)| match params {
                        SlotParams::Recovery { pk, .. }
                            if recovery::pk_hash(pk.as_slice()) == *hash =>
                        {
                            Some(params.clone())
                        }
                        _ => None,
                    });
                    recovery_lost = found.is_none();
                    found
                }
                // Holders of the key disagree about the recovery key. Keeping either
                // could hand the vault to the wrong one.
                _ => {
                    recovery_lost = true;
                    None
                }
            },
            RecoveryChoice::Replace => {
                let r = recovery::generate()?;
                let pair = RecoveryKeyPair::derive(&r);
                let pk = *pair.public_key();
                recovery_words = Some(recovery::to_words(&r));
                Some(SlotParams::Recovery {
                    anchor_tag: recovery::anchor_tag(&r, &vault_id, next, &keys.key_id, &pk),
                    pk: Box::new(pk),
                    anchor_epoch: next,
                })
            }
        };
        let recovery_pk_hash = match &recovery_params {
            Some(SlotParams::Recovery { pk, .. }) => recovery::pk_hash(pk.as_slice()),
            _ => [0; 32],
        };

        let mut new_slots = Vec::new();
        let slot_id = random_id()?;
        let argon = Argon2Params::DEFAULT;
        let mut salt = [0u8; 16];
        fill_random(&mut salt)?;
        let slot_secret = kdf::password_slot_secret(password, &salt, argon)?;
        new_slots.push((
            slot_id,
            slot::seal_with_kek(
                &vault_id,
                &slot_id,
                next,
                &SlotParams::Password { argon, salt },
                &kdf::slot_kek(&vault_id, &slot_id, &slot_secret),
                &ek,
            )?,
        ));
        if let Some(params) = &recovery_params {
            let slot_id = random_id()?;
            new_slots.push((
                slot_id,
                slot::seal_recovery(&vault_id, &slot_id, next, params, &ek, None)?,
            ));
        }
        let slot_path = |slot_id: Id| FileName::Slot { slot_id }.to_path();
        for (slot_id, bytes) in &new_slots {
            self.store.create(&slot_path(*slot_id), bytes)?;
        }

        let record = NewEpoch {
            vault_id,
            epoch: next,
            creator: client,
            key_id: keys.key_id,
            recovery_pk_hash,
            cutover: &self.applied,
            chain: Some(ChainWrap {
                chain_key: &keys.chain,
                prev_epoch_key: self
                    .keyring
                    .epoch_key(current)
                    .expect("the current epoch's key is held"),
                nonce: None,
            }),
        }
        .seal(&self.device)?;
        let record_path = FileName::Epoch {
            epoch: next,
            creator: client,
        }
        .to_path();
        // A record this device wrote, whole, can't be in the way: after it, this
        // device would have followed that rotation. A half-written one from a crash
        // can, on storage without atomic renames, and is replaced.
        let own_pk = self.device.public_key();
        let existing = self.create_own(&record_path, &record, epoch::MAX_LEN, |there| {
            if there == record.as_slice() {
                Existing::Same
            } else if EpochRecord::parse(there, &vault_id).is_ok_and(|r| r.signature_valid(&own_pk))
            {
                Existing::Other
            } else {
                Existing::Junk
            }
        })?;
        if matches!(existing, Some(Existing::Other | Existing::Junk)) {
            return Err(CoreError::rejected(
                "epoch record",
                "this device already wrote a different record for this epoch",
            ));
        }

        // Another device may have rotated to the same epoch moments ago (spec §7.2).
        // If its record wins, back out before anything depends on ours: nobody can
        // have pinned it yet, since its slots haven't been usable for long.
        let paths = self.store.list()?;
        self.refresh_epoch_files(&paths)?;
        if self.competing_winner(next, &keys.key_id).is_some() {
            self.delete_if_present(&record_path)?;
            self.epoch_files.remove(&record_path);
            for (slot_id, _) in &new_slots {
                self.delete_if_present(&slot_path(*slot_id))?;
            }
            self.rotated_away = true;
            return Err(CoreError::ConflictingRotation);
        }

        self.keyring.push(&vault_id, ek);
        self.state.pin = Pin {
            epoch: next,
            key_id: keys.key_id,
        };
        // Local slots still wrap the old key, so they open only the old epoch, below
        // the pin: stale. `refresh_local_slots` re-wraps or drops them (spec §7.2, step 5).
        self.save()?;

        for (path, epoch, _) in &old_slots {
            if *epoch <= current {
                self.delete_if_present(path)?;
            }
        }
        Ok(Rotated {
            epoch: next,
            recovery_words,
            recovery_lost,
        })
    }

    /// Changes the password: a rotation whose new password slot uses `new_password`.
    /// The recovery key is kept. Every other device has to unlock with the new
    /// password before it can write again.
    pub fn change_password(&mut self, new_password: &[u8]) -> Result<Rotated> {
        self.rotate(new_password, RecoveryChoice::Keep)
    }

    /// Replaces the recovery key (spec §6.2.1): returns the new words. Removing the
    /// old recovery slot is a slot removal, so this rotates.
    pub fn replace_recovery_key(&mut self, password: &[u8]) -> Result<SecretBytes> {
        let rotated = self.rotate(password, RecoveryChoice::Replace)?;
        Ok(rotated
            .recovery_words
            .expect("a replacing rotation returns the new words"))
    }

    /// Revokes another device (spec §7.2, §9.2): rotates so it can't read anything
    /// new, then retires it at the last event this device had seen from it. Its later
    /// changes are flagged for review. Rotating first means a failure leaves either
    /// nothing done or the important half done, never a device marked retired that
    /// still holds the current key. A thief who also knows the password can still
    /// unlock, so the UI should suggest changing it at the same time.
    pub fn revoke_device(&mut self, client_id: Id, password: &[u8]) -> Result<Rotated> {
        if client_id == self.state.client_id {
            return Err(CoreError::rejected(
                "revocation",
                "a device can't revoke itself",
            ));
        }
        self.check_writable()?;
        self.sync()?;
        if !self.registry.contains_key(&client_id) {
            return Err(CoreError::rejected("revocation", "no such device"));
        }
        let last_seq = self.applied.get(&client_id);
        let rotated = self.rotate(password, RecoveryChoice::Keep)?;
        self.write(vec![Edit::RetireClient {
            client_id,
            last_seq,
        }])?;
        Ok(rotated)
    }

    /// The recovery keys named by verified records for `epoch` whose key ID is this
    /// device's (spec §7.1), without the all-zero "none". Above epoch 0 the record's
    /// chain wrap has to open, which only a holder of the epoch key can arrange.
    /// Epoch 0 relies on its creator's signature.
    fn recovery_named(&self, epoch: u32) -> Vec<[u8; 32]> {
        let Some(keys) = self.keyring.keys(epoch) else {
            return Vec::new();
        };
        let named: BTreeSet<[u8; 32]> = self
            .epoch_records()
            .filter(|r| r.epoch == epoch && r.key_id == keys.key_id)
            .filter(|r| {
                if epoch == 0 {
                    self.registry
                        .get(&r.creator)
                        .is_some_and(|pk| r.signature_valid(pk))
                } else {
                    r.open_chain(&keys.chain).is_ok()
                }
            })
            .map(|r| r.recovery_pk_hash)
            .filter(|hash| *hash != [0; 32])
            .collect();
        named.into_iter().collect()
    }

    /// After losing a concurrent rotation (`SyncReport::lost_rotation`): switches to
    /// the winning key with a credential that opens it, typically the password set on
    /// the winning device (spec §7.2). The winner must chain to the same history as
    /// this device's key. This device then becomes a new client and re-issues the
    /// changes it made under the losing key, which no other device can read.
    ///
    /// The re-issued changes are written on top of the shared history only, so they
    /// stay concurrent with whatever the winning side did since the race: a secret
    /// field both sides changed becomes a conflict, as it would have without the race.
    pub fn rejoin(&mut self, credential: Credential<'_>) -> Result<()> {
        if let Some(kind) = self.alarm {
            return Err(CoreError::Alarm(kind));
        }
        let Some(winner) = self.lost_to() else {
            return Err(CoreError::rejected(
                "rejoin",
                "this device holds the winning key",
            ));
        };
        let epoch = self.keyring.current();
        let below = self
            .keyring
            .keys(epoch - 1)
            .expect("the keyring holds every epoch below its current one")
            .key_id;
        let files = VaultFiles::load(&self.store)?;
        let mut set_aside = Vec::new();
        let records = files.epoch_records(&mut set_aside)?;
        let slots = files.slots(&mut set_aside)?;
        let keyring = open_keyring(&self.vault_id, &records, &slots, credential, epoch, |k| {
            k.keys(epoch).is_some_and(|x| x.key_id == winner)
                && k.keys(epoch - 1).is_some_and(|x| x.key_id == below)
        })?;
        drop(records);
        drop(slots);

        let shared = self.shared_history(epoch);
        let own_shared = shared.get(&self.state.client_id).map_or(0, |&(seq, _)| seq);
        let reissue = self.losing_ops(own_shared)?;
        let base = VectorClock(shared.iter().map(|(&c, &(s, _))| (c, s)).collect());

        self.keyring = keyring;
        let current = self.keyring.current_keys();
        self.state.pin = Pin {
            epoch: self.keyring.current(),
            key_id: current.key_id,
        };
        self.clear_local_slots();
        // Rollback protection carries over for the shared history. Nothing written
        // under the losing key is readable with the new one.
        self.state.record.high_water = shared
            .into_iter()
            .map(|(client, (seq, hash))| (client, seq, hash))
            .collect();
        self.become_new_client()?;
        self.ops = OpSet::new();
        self.applied = Default::default();
        self.events.clear();
        self.registry.clear();
        self.snapshots.clear();
        self.unreadable_snapshot = false;
        self.lost_rotation = false;
        self.rotated_away = false;
        self.save()?;

        self.sync()?;
        if !reissue.is_empty() {
            self.write_event(reissue, base)?;
        }
        Ok(())
    }

    /// What this device learned before a rotation it lost at `epoch`, and so shares
    /// with the winner: per client, the highest seq (and its hash) seen through events
    /// or snapshots sealed below `epoch`.
    fn shared_history(&self, epoch: u32) -> BTreeMap<Id, (u64, [u8; 32])> {
        fn note(marks: &mut BTreeMap<Id, (u64, [u8; 32])>, client: Id, seq: u64, hash: [u8; 32]) {
            let mark = marks.entry(client).or_insert((seq, hash));
            if seq > mark.0 {
                *mark = (seq, hash);
            }
        }
        let mut marks = BTreeMap::new();
        for (&(client, seq), event) in &self.events {
            if event.epoch.is_some_and(|e| e < epoch) {
                note(&mut marks, client, seq, event.hash);
            }
        }
        for (snapshot_epoch, watermark) in self.snapshots.values() {
            if *snapshot_epoch < epoch {
                for &(client, seq, hash) in watermark {
                    note(&mut marks, client, seq, hash);
                }
            }
        }
        marks
    }

    /// This device's ops that only the losing key can read: those past `shared_seq`,
    /// its last event in the shared history, whether still in events or compacted
    /// into its own snapshot, plus those of its pending events. Registrations are
    /// left out, since the device registers again as a new client.
    fn losing_ops(&self, shared_seq: u64) -> Result<Vec<Op>> {
        let client = self.state.client_id;
        let mut records: Vec<_> = self
            .ops
            .iter()
            .filter(|r| r.dot.client_id == client && r.dot.seq > shared_seq)
            .collect();
        records.sort_by_key(|r| r.dot);
        let mut ops: Vec<Op> = records.into_iter().map(|r| r.op.duplicate()).collect();
        for bytes in &self.state.record.pending {
            let sealed = SealedEvent::parse(bytes, &self.vault_id)?;
            let keys = self
                .keyring
                .keys(sealed.header.epoch)
                .ok_or(CoreError::rejected(
                    "pending event",
                    "its epoch key is gone",
                ))?;
            ops.extend(sealed.open(&keys.event)?.ops);
        }
        ops.retain(|op| !matches!(op, Op::RegisterDevice { .. }));
        Ok(ops)
    }

    /// Permanently removes an entry (spec §10.4): rotates, writes a snapshot without
    /// the entry under the new key, then deletes every event file and snapshot that
    /// snapshot makes redundant. Rotating first means devices that haven't caught
    /// up can't write a snapshot that brings the entry back, and nothing
    /// under the new key ever held it.
    pub fn purge(&mut self, entry_id: Id, password: &[u8]) -> Result<PurgeReport> {
        let rotated = self.rotate(password, RecoveryChoice::Keep)?;
        // The entry leaves the session's op set only once the snapshot is written, so
        // a failed purge doesn't look like a finished one.
        let without = self.ops.filtered(|r| r.op.entry_id() != Some(&entry_id));
        let with = std::mem::replace(&mut self.ops, without);
        let snapshot_id = match self.write_snapshot() {
            Ok(id) => id,
            Err(e) => {
                self.ops = with;
                return Err(e);
            }
        };
        let watermark: Watermark = self.snapshots[&snapshot_id].1.clone();
        let mut report = PurgeReport {
            rotated,
            events_deleted: 0,
            snapshots_deleted: 0,
            events_left: 0,
            snapshots_left: 0,
        };
        for path in self.store.list()? {
            match FileName::parse(&path) {
                Some(FileName::Event { client_id, seq }) => {
                    if watermark
                        .iter()
                        .any(|(c, s, _)| *c == client_id && seq <= *s)
                    {
                        if self.delete_if_present(&path)? {
                            report.events_deleted += 1;
                        }
                    } else {
                        report.events_left += 1;
                    }
                }
                Some(FileName::Snapshot { snapshot_id: id }) if id != snapshot_id => {
                    // Every loaded snapshot is covered: its watermark counts as applied.
                    if self.snapshots.remove(&id).is_some() {
                        if self.delete_if_present(&path)? {
                            report.snapshots_deleted += 1;
                        }
                        self.state.record.snapshots.retain(|(s, _)| *s != id);
                    } else {
                        report.snapshots_left += 1;
                    }
                }
                _ => {}
            }
        }
        self.save()?;
        Ok(report)
    }

    /// Reverts the changes `review` flags (spec §9.2): for every entry they touched,
    /// writes ordinary new ops that restore what the vault would hold without them.
    /// Returns the number of edits written. Values that a flagged change replaced
    /// and that compaction has since dropped can't be restored. Such fields end up
    /// absent rather than keeping the flagged value. A conflict without the flagged
    /// change can't be recreated either, so the field is left for the user.
    pub fn revert_flagged(&mut self) -> Result<usize> {
        self.check_writable()?;
        let flagged: HashSet<Dot> = self.review().flagged.into_iter().collect();
        let touched: BTreeSet<Id> = self
            .ops
            .iter()
            .filter(|r| flagged.contains(&r.dot))
            .filter_map(|r| r.op.entry_id().copied())
            .collect();
        if touched.is_empty() {
            return Ok(0);
        }
        let clean = self.ops.filtered(|r| !flagged.contains(&r.dot));
        let (now, want) = (self.ops.view(), clean.view());
        let mut edits = Vec::new();
        for entry_id in touched {
            let Some(current) = now.entries.get(&entry_id) else {
                continue;
            };
            match want.entries.get(&entry_id) {
                // Only flagged changes ever wrote the entry.
                None => {
                    if !current.deleted {
                        edits.push(Edit::DeleteEntry { entry_id });
                    }
                }
                Some(wanted) => revert_entry(entry_id, current, wanted, &mut edits),
            }
        }
        let count = edits.len();
        if count > 0 {
            self.write(edits)?;
        }
        Ok(count)
    }
}

/// Edits that turn `current` into `wanted`. A delete goes last, so it sees (and
/// beats) the writes before it in the same event.
fn revert_entry(
    entry_id: Id,
    current: &EntryView<'_>,
    wanted: &EntryView<'_>,
    edits: &mut Vec<Edit>,
) {
    if current.deleted && !wanted.deleted {
        edits.push(Edit::KeepEntry { entry_id });
    }
    let names: BTreeSet<&str> = current
        .fields
        .keys()
        .chain(wanted.fields.keys())
        .copied()
        .collect();
    for name in names {
        let (have, want) = (current.fields.get(name), wanted.fields.get(name));
        let value = match want {
            Some(Field::Conflict { .. }) => continue,
            Some(Field::Value { value, secret, .. }) => Some((*value, *secret)),
            None => None,
        };
        let had = match have {
            Some(Field::Value { value, secret, .. }) => Some((*value, *secret)),
            _ => None,
        };
        if matches!(have, Some(Field::Value { .. }) | None) && value == had {
            continue;
        }
        let secret = value.map_or_else(
            || {
                matches!(
                    have,
                    Some(Field::Value { secret: true, .. })
                        | Some(Field::Conflict { secret: true, .. })
                )
            },
            |(_, secret)| secret,
        );
        edits.push(Edit::SetField {
            entry_id,
            name: name.to_string(),
            value: value.map(|(v, _)| v.duplicate()),
            secret,
        });
    }
    for tag in wanted.tags.difference(&current.tags) {
        edits.push(Edit::AddTag {
            entry_id,
            tag: tag.to_string(),
        });
    }
    for tag in current.tags.difference(&wanted.tags) {
        edits.push(Edit::RemoveTag {
            entry_id,
            tag: tag.to_string(),
        });
    }
    if wanted.deleted && !current.deleted {
        edits.push(Edit::DeleteEntry { entry_id });
    }
}
