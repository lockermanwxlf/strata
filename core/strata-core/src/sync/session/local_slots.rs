//! Local slots (spec §11): unlocking this device with a platform protector. The
//! protector itself (biometrics, Windows Hello, a TPM) lives outside the core; it
//! only ever sees the slot secret `S`, and the core wraps the epoch key itself.

use super::SessionOf;
use crate::crypto::SecretKey;
use crate::crypto::kdf;
use crate::error::Result;
use crate::format::Id;
use crate::format::slot::{self, SlotFile, SlotParams};
use crate::local::LocalStore;
use crate::policy::{SlotScope, check_platform_policy};
use crate::protector::ProtectorCaps;
use crate::sync::RemoteStore;

/// A local slot as the UI sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSlot {
    pub slot_id: Id,
    pub protector_id: u8,
    /// It wraps the current epoch's key. A stale one only opens an old epoch.
    pub current: bool,
}

impl<R: RemoteStore, L: LocalStore> SessionOf<R, L> {
    /// Adds a local slot for `protector_id`, replacing that protector's earlier one.
    /// `blob` is what the protector returned for wrapping `secret`. The policy is
    /// checked here, in the core, whatever the UI did (spec §6.2).
    pub fn add_local_slot(
        &mut self,
        slot_id: Id,
        protector_id: u8,
        blob: Vec<u8>,
        secret: &SecretKey,
        caps: &ProtectorCaps,
    ) -> Result<()> {
        check_platform_policy(caps)?;
        let bytes = self.seal_local_slot(slot_id, protector_id, blob, secret)?;
        self.remove_where(|s| s.protector_id == protector_id);
        self.state.local_slots.push(bytes);
        self.save()
    }

    /// After the key changed (a rotation here or elsewhere, or a rejoin): re-wraps the
    /// local slots whose secret this process still holds from unlocking or enrolling,
    /// so they open the current epoch without another prompt, and drops the stale
    /// ones it can't re-wrap (spec §7.2).
    pub fn refresh_local_slots(&mut self, secrets: &[(Id, SecretKey)]) -> Result<()> {
        let current = self.keyring.current();
        let mut changed = false;
        let mut kept = Vec::new();
        for bytes in std::mem::take(&mut self.state.local_slots) {
            let Ok(slot) = SlotFile::parse(&bytes, &self.vault_id, SlotScope::Local) else {
                changed = true;
                continue;
            };
            let SlotParams::Platform { protector_id, blob } = slot.params.clone() else {
                changed = true;
                continue;
            };
            match secrets.iter().find(|(id, _)| *id == slot.slot_id) {
                // Re-sealed even when current: after a rejoin the epoch number can be
                // the same while the key is the winner's.
                Some((_, secret)) => {
                    kept.push(self.seal_local_slot(slot.slot_id, protector_id, blob, secret)?);
                    changed = true;
                }
                None if slot.epoch == current => kept.push(bytes),
                None => changed = true,
            }
        }
        self.state.local_slots = kept;
        if changed { self.save() } else { Ok(()) }
    }

    pub fn local_slots(&self) -> Vec<LocalSlot> {
        let current = self.keyring.current();
        self.state
            .local_slots
            .iter()
            .filter_map(|b| SlotFile::parse(b, &self.vault_id, SlotScope::Local).ok())
            .filter_map(|s| match s.params {
                SlotParams::Platform { protector_id, .. } => Some(LocalSlot {
                    slot_id: s.slot_id,
                    protector_id,
                    current: s.epoch == current,
                }),
                _ => None,
            })
            .collect()
    }

    /// Removes every local slot of `protector_id`.
    pub fn remove_local_slots(&mut self, protector_id: u8) -> Result<()> {
        self.remove_where(|s| s.protector_id == protector_id);
        self.save()
    }

    /// Drops every local slot: after a rejoin, the old ones wrap the losing key.
    pub(super) fn clear_local_slots(&mut self) {
        self.state.local_slots.clear();
    }

    fn remove_where(&mut self, matches: impl Fn(&LocalSlot) -> bool) {
        let doomed: Vec<Id> = self
            .local_slots()
            .into_iter()
            .filter(|s| matches(s))
            .map(|s| s.slot_id)
            .collect();
        let vault_id = self.vault_id;
        self.state.local_slots.retain(|b| {
            SlotFile::parse(b, &vault_id, SlotScope::Local)
                .is_ok_and(|s| !doomed.contains(&s.slot_id))
        });
    }

    /// A kind-4 slot wrapping the current epoch key under `KEK(S)` (spec §6.2).
    fn seal_local_slot(
        &self,
        slot_id: Id,
        protector_id: u8,
        blob: Vec<u8>,
        secret: &SecretKey,
    ) -> Result<Vec<u8>> {
        let current = self.keyring.current();
        slot::seal_with_kek(
            &self.vault_id,
            &slot_id,
            current,
            &SlotParams::Platform { protector_id, blob },
            &kdf::slot_kek(&self.vault_id, &slot_id, secret),
            self.keyring
                .epoch_key(current)
                .expect("the current epoch's key is held"),
        )
    }
}
