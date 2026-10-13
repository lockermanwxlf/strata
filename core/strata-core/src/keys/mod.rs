//! Key hierarchy and unlock (spec §6, §7.1): epoch keys, slots, the epoch chain,
//! key-ID pinning and the recovery anchor.

#![forbid(unsafe_code)]

pub mod create;
pub mod strength;
pub mod unlock;

use std::collections::BTreeMap;

use subtle::ConstantTimeEq;

use crate::crypto::SecretKey;
use crate::crypto::kdf::EpochKeys;
use crate::error::{CoreError, Result};
use crate::format::Id;
use crate::format::epoch::{self, EpochRecord};
use crate::format::names::FileName;
use crate::format::slot::{self, SlotFile};
use crate::format::vault_info::{self, VaultInfo};
use crate::policy::SlotScope;
use crate::sync::RemoteStore;

/// Every epoch key this device holds, verified against the epoch records.
pub struct Keyring {
    epochs: BTreeMap<u32, (SecretKey, EpochKeys)>,
    current: u32,
}

impl Keyring {
    /// The newest epoch this keyring holds.
    pub fn current(&self) -> u32 {
        self.current
    }

    pub fn keys(&self, epoch: u32) -> Option<&EpochKeys> {
        self.epochs.get(&epoch).map(|(_, keys)| keys)
    }

    pub fn current_keys(&self) -> &EpochKeys {
        &self.epochs[&self.current].1
    }

    /// Adds the next epoch after a rotation this device performed or joined, and makes
    /// it current.
    pub(crate) fn push(&mut self, vault_id: &Id, ek: SecretKey) -> &EpochKeys {
        let keys = EpochKeys::derive(vault_id, &ek);
        self.current += 1;
        self.epochs.insert(self.current, (ek, keys));
        &self.epochs[&self.current].1
    }

    /// The raw epoch key `EK_e`. Only rotation needs it, to wrap it under the next epoch.
    pub fn epoch_key(&self, epoch: u32) -> Option<&SecretKey> {
        self.epochs.get(&epoch).map(|(ek, _)| ek)
    }

    /// Starts from `EK_top` and walks the epoch chain down to epoch 0 (spec §7.1).
    /// Every key must match the `key_id` of an epoch record for its epoch, which is
    /// the slot-substitution check of spec §6.3 step 3 for the top key.
    ///
    /// Key IDs are public, so several records may claim one: a planted copy with a
    /// garbage chain wrap must not hide the real record. Every match is tried, and
    /// only a chain wrap that authenticates under this epoch's chain key counts.
    pub(crate) fn walk(
        vault_id: &Id,
        records: &[EpochRecord<'_>],
        top: u32,
        ek_top: SecretKey,
    ) -> Result<Self> {
        let mut epochs = BTreeMap::new();
        let (mut epoch, mut ek) = (top, ek_top);
        loop {
            let keys = EpochKeys::derive(vault_id, &ek);
            let mut matching = records
                .iter()
                .filter(|r| r.epoch == epoch && bool::from(r.key_id.ct_eq(&keys.key_id)))
                .peekable();
            if matching.peek().is_none() {
                return Err(CoreError::rejected(
                    "key chain",
                    "no epoch record matches the key",
                ));
            }
            let previous = if epoch == 0 {
                None
            } else {
                Some(
                    matching
                        .find_map(|r| r.open_chain(&keys.chain).ok())
                        .ok_or(CoreError::rejected(
                            "key chain",
                            "no matching record's chain wrap opens",
                        ))?,
                )
            };
            epochs.insert(epoch, (ek, keys));
            match previous {
                Some(prev) => {
                    ek = prev;
                    epoch -= 1;
                }
                None => break,
            }
        }
        Ok(Self {
            epochs,
            current: top,
        })
    }
}

/// Epoch records come one per rotation and slots a handful at a time, so more than
/// this many means files were planted. Refusing up front avoids reading them all
/// into memory.
pub const MAX_KEY_FILES: usize = 4096;

/// The key-related files of a vault, read from the store: `strata-vault`, the epoch
/// records and the synced slots. Files that fail to parse are set aside in
/// `rejected`, so one bad file can't block unlocking with the others.
pub struct VaultFiles {
    pub vault_id: Id,
    epochs: Vec<(FileName, Vec<u8>)>,
    slots: Vec<(FileName, Vec<u8>)>,
    pub rejected: Vec<(String, CoreError)>,
}

impl VaultFiles {
    pub fn load(store: &dyn RemoteStore) -> Result<Self> {
        let paths = store.list()?;
        if !paths.iter().any(|p| p == "strata-vault") {
            return Err(CoreError::rejected("vault", "no strata-vault file here"));
        }
        // One byte over the exact length, so a longer file reaches the parser and is
        // rejected there rather than failing the read.
        let vault_id =
            VaultInfo::parse(&store.read("strata-vault", vault_info::LEN + 1)?)?.vault_id;
        let mut files = Self {
            vault_id,
            epochs: Vec::new(),
            slots: Vec::new(),
            rejected: Vec::new(),
        };
        let key_files = paths
            .iter()
            .filter(|p| {
                matches!(
                    FileName::parse(p),
                    Some(FileName::Epoch { .. } | FileName::Slot { .. })
                )
            })
            .count();
        if key_files > MAX_KEY_FILES {
            return Err(CoreError::rejected(
                "vault",
                "too many epoch and slot files",
            ));
        }
        for path in paths {
            let Some(name) = FileName::parse(&path) else {
                continue;
            };
            let (list, max_len) = match name {
                FileName::Epoch { .. } => (&mut files.epochs, epoch::MAX_LEN),
                FileName::Slot { .. } => (&mut files.slots, slot::MAX_FILE_LEN),
                _ => continue,
            };
            match store.read(&path, max_len) {
                Ok(bytes) => list.push((name, bytes)),
                Err(e @ CoreError::Rejected { .. }) => files.rejected.push((path, e)),
                Err(e) => return Err(e),
            }
        }
        Ok(files)
    }

    /// Parses every epoch record. A newer format version stops everything
    /// (`UpdateRequired`); any other problem sets that file aside.
    pub(crate) fn epoch_records(
        &self,
        rejected: &mut Vec<(String, CoreError)>,
    ) -> Result<Vec<EpochRecord<'_>>> {
        let mut out = Vec::new();
        for (name, bytes) in &self.epochs {
            match EpochRecord::parse(bytes, &self.vault_id)
                .and_then(|r| name.expect(r.file_name()).map(|()| r))
            {
                Ok(record) => out.push(record),
                Err(e @ CoreError::UpdateRequired { .. }) => return Err(e),
                Err(e) => rejected.push((name.to_path(), e)),
            }
        }
        Ok(out)
    }

    pub(crate) fn slots(
        &self,
        rejected: &mut Vec<(String, CoreError)>,
    ) -> Result<Vec<SlotFile<'_>>> {
        let mut out = Vec::new();
        for (name, bytes) in &self.slots {
            match SlotFile::parse(bytes, &self.vault_id, SlotScope::Synced)
                .and_then(|s| name.expect(s.file_name()).map(|()| s))
            {
                Ok(slot) => out.push(slot),
                Err(e @ CoreError::UpdateRequired { .. }) => return Err(e),
                Err(e) => rejected.push((name.to_path(), e)),
            }
        }
        Ok(out)
    }
}
