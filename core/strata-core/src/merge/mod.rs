//! Merge (spec §9.2–9.3): the vault's state is a pure function of the set of
//! applied ops. This module holds that set, the happened-before relation, and the
//! reduction that drops ops without changing any result.

#![forbid(unsafe_code)]

pub mod edit;
pub mod view;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use crate::format::Id;
use crate::format::body::{Dot, EventBody, Op, VectorClock};

/// One applied op, with the causal metadata merging needs.
#[derive(Debug)]
pub struct OpRecord {
    pub dot: Dot,
    /// The HLC of the op's event.
    pub hlc: u64,
    /// The vector clock of the op's event (shared by all its ops).
    pub clock: Arc<VectorClock>,
    pub op: Op,
}

impl OpRecord {
    /// The order of concurrent non-secret writes: `(hlc, client_id, seq, op_index)`.
    fn lww_key(&self) -> (u64, Id, u64, u32) {
        (
            self.hlc,
            self.dot.client_id,
            self.dot.seq,
            self.dot.op_index,
        )
    }
}

/// `a → b` (spec §9.2): within an event by op index, otherwise through `b`'s
/// vector clock.
pub fn happened_before(a: &OpRecord, b: &OpRecord) -> bool {
    if a.dot.client_id == b.dot.client_id && a.dot.seq == b.dot.seq {
        a.dot.op_index < b.dot.op_index
    } else {
        b.clock.get(&a.dot.client_id) >= a.dot.seq
    }
}

/// The set of applied ops, keyed by dot. Adding an op that is already there changes
/// nothing, so applying events is idempotent and order doesn't matter.
#[derive(Debug, Default)]
pub struct OpSet {
    ops: BTreeMap<Dot, OpRecord>,
}

impl OpSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the ops of event `(client_id, seq)`. The body is consumed: its field
    /// values move into the set rather than being copied.
    pub fn apply_event(&mut self, client_id: Id, seq: u64, body: EventBody) {
        let clock = Arc::new(body.clock);
        for (i, op) in body.ops.into_iter().enumerate() {
            let dot = Dot {
                client_id,
                seq,
                op_index: i as u32,
            };
            self.insert(OpRecord {
                dot,
                hlc: body.hlc,
                clock: Arc::clone(&clock),
                op,
            });
        }
    }

    /// Adds one op (from an event or a snapshot). Keeps the existing record if the
    /// dot is already present.
    pub fn insert(&mut self, record: OpRecord) {
        self.ops.entry(record.dot).or_insert(record);
    }

    /// Takes every op of `other` (spec §9.3: union is always safe).
    pub fn union(&mut self, other: OpSet) {
        for (_, record) in other.ops {
            self.insert(record);
        }
    }

    /// A copy holding duplicates of the ops `keep` accepts. Purge and revert build
    /// the vault without some ops this way; the merge itself only drops ops in
    /// `reduce`.
    pub(crate) fn filtered(&self, mut keep: impl FnMut(&OpRecord) -> bool) -> OpSet {
        let mut out = OpSet::new();
        for record in self.ops.values().filter(|r| keep(r)) {
            out.insert(OpRecord {
                dot: record.dot,
                hlc: record.hlc,
                clock: Arc::clone(&record.clock),
                op: record.op.duplicate(),
            });
        }
        out
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn contains(&self, dot: &Dot) -> bool {
        self.ops.contains_key(dot)
    }

    pub fn iter(&self) -> impl Iterator<Item = &OpRecord> {
        self.ops.values()
    }

    /// Drops every op spec §9.3 allows dropping. Doesn't change `view()`, now or
    /// after any later op arrives. One pass is enough: an op that survives isn't
    /// dominated by anything, and removing others can't change that.
    pub fn reduce(&mut self) {
        let drop = self.droppable();
        self.ops.retain(|dot, _| !drop.contains(dot));
    }

    fn droppable(&self) -> HashSet<Dot> {
        let groups = Groups::of(self);
        let mut drop = HashSet::new();
        for record in self.ops.values() {
            let dominated_by =
                |others: &[&OpRecord]| others.iter().any(|o| happened_before(record, o));
            let droppable = match &record.op {
                Op::SetField { entry_id, name, .. } => dominated_by(groups.field(entry_id, name)),
                Op::KeepEntry { entry_id } => dominated_by(groups.writes(entry_id)),
                Op::DeleteEntry { entry_id } => {
                    dominated_by(groups.writes(entry_id)) || dominated_by(groups.deletes(entry_id))
                }
                Op::AddTag { entry_id, tag } => groups.removed_tag(entry_id, tag, &record.dot),
                Op::SetDeviceName { .. } => groups.renamed_later(&record.dot),
                Op::RemoveTag { .. } | Op::RetireClient { .. } | Op::RegisterDevice { .. } => false,
            };
            if droppable {
                drop.insert(record.dot);
            }
        }
        drop
    }
}

/// Ops grouped the ways §9.2 and §9.3 look them up.
#[derive(Default)]
struct Groups<'a> {
    fields: HashMap<(Id, &'a str), Vec<&'a OpRecord>>,
    writes: HashMap<Id, Vec<&'a OpRecord>>,
    deletes: HashMap<Id, Vec<&'a OpRecord>>,
    adds: HashMap<(Id, &'a str), Vec<&'a OpRecord>>,
    removed: HashSet<(Id, &'a str, Dot)>,
    /// Per client, the latest of its `RegisterDevice` and `SetDeviceName` ops.
    latest_name: HashMap<Id, &'a OpRecord>,
}

impl<'a> Groups<'a> {
    fn of(set: &'a OpSet) -> Self {
        let mut g = Groups::default();
        for r in set.ops.values() {
            match &r.op {
                Op::SetField { entry_id, name, .. } => {
                    g.fields
                        .entry((*entry_id, name.as_str()))
                        .or_default()
                        .push(r);
                    g.writes.entry(*entry_id).or_default().push(r);
                }
                Op::KeepEntry { entry_id } => g.writes.entry(*entry_id).or_default().push(r),
                Op::DeleteEntry { entry_id } => g.deletes.entry(*entry_id).or_default().push(r),
                Op::AddTag { entry_id, tag } => {
                    g.adds.entry((*entry_id, tag.as_str())).or_default().push(r)
                }
                Op::RemoveTag {
                    entry_id,
                    tag,
                    dots,
                } => {
                    for dot in dots {
                        g.removed.insert((*entry_id, tag.as_str(), *dot));
                    }
                }
                Op::RegisterDevice { .. } | Op::SetDeviceName { .. } => {
                    let latest = g.latest_name.entry(r.dot.client_id).or_insert(r);
                    if (r.dot.seq, r.dot.op_index) > (latest.dot.seq, latest.dot.op_index) {
                        *latest = r;
                    }
                }
                Op::RetireClient { .. } => {}
            }
        }
        g
    }

    fn field(&self, entry: &Id, name: &'a str) -> &[&'a OpRecord] {
        self.fields.get(&(*entry, name)).map_or(&[], Vec::as_slice)
    }

    fn writes(&self, entry: &Id) -> &[&'a OpRecord] {
        self.writes.get(entry).map_or(&[], Vec::as_slice)
    }

    fn deletes(&self, entry: &Id) -> &[&'a OpRecord] {
        self.deletes.get(entry).map_or(&[], Vec::as_slice)
    }

    fn removed_tag(&self, entry: &Id, tag: &str, dot: &Dot) -> bool {
        self.removed.contains(&(*entry, tag, *dot))
    }

    fn renamed_later(&self, dot: &Dot) -> bool {
        self.latest_name
            .get(&dot.client_id)
            .is_some_and(|latest| latest.dot != *dot)
    }
}

#[cfg(test)]
mod tests;
