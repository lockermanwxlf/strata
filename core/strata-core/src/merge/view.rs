//! The materialized view (spec §9.2): what the vault contains, computed from the
//! op set. Field values are borrowed from the set, never copied.

use std::collections::{BTreeMap, BTreeSet};

use super::{Groups, OpRecord, OpSet, happened_before};
use crate::crypto::SecretBytes;
use crate::format::Id;
use crate::format::body::{Dot, MULTI_VALUE_FIELDS, Op};

#[derive(Debug, PartialEq, Eq)]
pub struct VaultView<'a> {
    /// Every entry with at least one write, deleted ones (trash) included.
    pub entries: BTreeMap<Id, EntryView<'a>>,
    /// Registered devices, by client ID.
    pub devices: BTreeMap<Id, DeviceView<'a>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct EntryView<'a> {
    /// Present fields. A field whose resolved value is null is absent.
    pub fields: BTreeMap<&'a str, Field<'a>>,
    pub tags: BTreeSet<&'a str>,
    /// Some delete saw every write: the entry is in the trash.
    pub deleted: bool,
    /// A delete that no later write answered, on an entry that isn't deleted. The UI
    /// asks "deleted on another device: keep or delete?".
    pub unanswered_delete: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Field<'a> {
    Value {
        value: &'a SecretBytes,
        secret: bool,
        /// The write that set it, for attribution and history.
        dot: Dot,
    },
    /// Concurrent writes to a secret field or a multi-value field such as `notes`
    /// (spec §9.2). Sorted by dot.
    Conflict {
        candidates: Vec<Candidate<'a>>,
        /// Some candidate is secret.
        secret: bool,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct Candidate<'a> {
    /// `None`: this side deleted the field.
    pub value: Option<&'a SecretBytes>,
    pub dot: Dot,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DeviceView<'a> {
    pub dev_pk: [u8; 32],
    pub name: &'a str,
    /// Set if the device was retired: its events after this seq are rejected.
    pub retired_after: Option<u64>,
}

impl OpSet {
    pub fn view(&self) -> VaultView<'_> {
        let groups = Groups::of(self);
        // An entry exists iff it has a write (spec §9.2).
        let mut entries: BTreeMap<Id, EntryView<'_>> = groups
            .writes
            .iter()
            .map(|(entry_id, writes)| (*entry_id, entry_status(&groups, entry_id, writes)))
            .collect();
        for ((entry_id, name), writes) in &groups.fields {
            if let (Some(entry), Some(field)) =
                (entries.get_mut(entry_id), resolve_field(name, writes))
            {
                entry.fields.insert(*name, field);
            }
        }
        for ((entry_id, tag), adds) in &groups.adds {
            if let Some(entry) = entries.get_mut(entry_id)
                && adds
                    .iter()
                    .any(|a| !groups.removed_tag(entry_id, tag, &a.dot))
            {
                entry.tags.insert(*tag);
            }
        }
        VaultView {
            entries,
            devices: devices(self, &groups),
        }
    }
}

/// An entry's deleted and unanswered-delete flags, with no fields or tags yet.
fn entry_status<'a>(groups: &Groups<'a>, entry_id: &Id, writes: &[&'a OpRecord]) -> EntryView<'a> {
    let deletes = groups.deletes(entry_id);
    let deleted = deletes
        .iter()
        .any(|d| writes.iter().all(|w| happened_before(w, d)));
    let unanswered_delete = !deleted
        && deletes
            .iter()
            .any(|d| !writes.iter().any(|w| happened_before(d, w)));
    EntryView {
        fields: BTreeMap::new(),
        tags: BTreeSet::new(),
        deleted,
        unanswered_delete,
    }
}

/// One field register (spec §9.2).
fn resolve_field<'a>(name: &str, writes: &[&'a OpRecord]) -> Option<Field<'a>> {
    let mut candidates: Vec<&OpRecord> = writes
        .iter()
        .filter(|w| !writes.iter().any(|other| happened_before(w, other)))
        .copied()
        .collect();
    let set_field = |r: &'a OpRecord| match &r.op {
        Op::SetField { value, secret, .. } => (value.as_ref(), *secret),
        _ => unreachable!("field groups hold only SetField"),
    };
    let secret = candidates.iter().any(|c| set_field(c).1);
    if (secret || MULTI_VALUE_FIELDS.contains(&name)) && candidates.len() > 1 {
        if candidates.iter().all(|c| set_field(c).0.is_none()) {
            return None;
        }
        candidates.sort_by_key(|c| c.dot);
        return Some(Field::Conflict {
            candidates: candidates
                .iter()
                .map(|c| Candidate {
                    value: set_field(c).0,
                    dot: c.dot,
                })
                .collect(),
            secret,
        });
    }
    // One candidate, or last-writer-wins among concurrent writes to other fields.
    let winner = candidates.iter().max_by_key(|c| c.lww_key())?;
    let (value, _) = set_field(winner);
    value.map(|value| Field::Value {
        value,
        secret,
        dot: winner.dot,
    })
}

fn devices<'a>(set: &'a OpSet, groups: &Groups<'a>) -> BTreeMap<Id, DeviceView<'a>> {
    let mut retired: BTreeMap<Id, u64> = BTreeMap::new();
    for r in set.iter() {
        if let Op::RetireClient {
            client_id,
            last_seq,
        } = &r.op
        {
            let limit = retired.entry(*client_id).or_insert(*last_seq);
            *limit = (*limit).min(*last_seq);
        }
    }
    let mut devices = BTreeMap::new();
    // Every registered device is listed, retired ones included.
    for r in set.iter() {
        if let Op::RegisterDevice {
            client_id,
            dev_pk,
            name: registered_name,
        } = &r.op
        {
            let name = match groups.latest_name.get(client_id).map(|l| &l.op) {
                Some(Op::SetDeviceName { name } | Op::RegisterDevice { name, .. }) => name.as_str(),
                _ => registered_name.as_str(),
            };
            devices.insert(
                *client_id,
                DeviceView {
                    dev_pk: *dev_pk,
                    name,
                    retired_after: retired.get(client_id).copied(),
                },
            );
        }
    }
    devices
}
