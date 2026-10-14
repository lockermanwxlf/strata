//! Edits: what the user does, turned into ops (spec §8.2). Causal metadata (dots,
//! the vector clock, the HLC) is added when the ops are written as an event.

use super::{Groups, OpSet};
use crate::crypto::SecretBytes;
use crate::crypto::random_id;
use crate::error::Result;
use crate::format::Id;
use crate::format::body::Op;

/// Well-known fields that are always secret (spec §8.2).
pub const ALWAYS_SECRET: [&str; 2] = ["password", "otp"];

#[derive(Debug)]
pub enum Edit {
    /// Sets a field, or deletes it with `value: None`. Also how a secret-field conflict
    /// is resolved: the new write dominates every candidate the device has seen.
    SetField {
        entry_id: Id,
        name: String,
        value: Option<SecretBytes>,
        secret: bool,
    },
    DeleteEntry {
        entry_id: Id,
    },
    /// "Keep" in answer to an unanswered delete (spec §9.2). Also undoes a delete.
    KeepEntry {
        entry_id: Id,
    },
    AddTag {
        entry_id: Id,
        tag: String,
    },
    /// Removes every add of the tag this device has seen (observed-remove).
    RemoveTag {
        entry_id: Id,
        tag: String,
    },
    RetireClient {
        client_id: Id,
        last_seq: u64,
    },
    SetDeviceName {
        name: String,
    },
}

impl Edit {
    /// The entry the edit touches, if it touches one.
    pub fn entry_id(&self) -> Option<Id> {
        match self {
            Edit::SetField { entry_id, .. }
            | Edit::DeleteEntry { entry_id }
            | Edit::KeepEntry { entry_id }
            | Edit::AddTag { entry_id, .. }
            | Edit::RemoveTag { entry_id, .. } => Some(*entry_id),
            Edit::RetireClient { .. } | Edit::SetDeviceName { .. } => None,
        }
    }
}

/// A fresh entry ID. An entry comes into existence with its first `SetField`.
pub fn new_entry_id() -> Result<Id> {
    random_id()
}

impl OpSet {
    /// The ops for `edits`, as this device would write them now.
    pub fn ops_for(&self, edits: Vec<Edit>) -> Vec<Op> {
        let groups = Groups::of(self);
        edits
            .into_iter()
            .map(|edit| match edit {
                Edit::SetField {
                    entry_id,
                    name,
                    value,
                    secret,
                } => Op::SetField {
                    secret: secret || ALWAYS_SECRET.contains(&name.as_str()),
                    entry_id,
                    name,
                    value,
                },
                Edit::DeleteEntry { entry_id } => Op::DeleteEntry { entry_id },
                Edit::KeepEntry { entry_id } => Op::KeepEntry { entry_id },
                Edit::AddTag { entry_id, tag } => Op::AddTag { entry_id, tag },
                Edit::RemoveTag { entry_id, tag } => {
                    let mut dots: Vec<_> = groups
                        .adds
                        .get(&(entry_id, tag.as_str()))
                        .into_iter()
                        .flatten()
                        .filter(|a| !groups.removed_tag(&entry_id, &tag, &a.dot))
                        .map(|a| a.dot)
                        .collect();
                    dots.sort();
                    Op::RemoveTag {
                        entry_id,
                        tag,
                        dots,
                    }
                }
                Edit::RetireClient {
                    client_id,
                    last_seq,
                } => Op::RetireClient {
                    client_id,
                    last_seq,
                },
                Edit::SetDeviceName { name } => Op::SetDeviceName { name },
            })
            .collect()
    }
}
