//! Merge tests (spec §9.2–9.3, §14.2): one scenario per rule, then convergence
//! property tests over simulated devices that edit and sync at random.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use zeroize::Zeroizing;

use super::edit::Edit;
use super::view::{Candidate, Field};
use super::*;
use crate::crypto::SecretBytes;
use crate::encoding::cbor;
use crate::model::hlc;

const A: Id = [0xa0; 16];
const B: Id = [0xb0; 16];
const C: Id = [0xc0; 16];
const X: Id = [0xe1; 16];

fn bytes(v: &[u8]) -> Option<SecretBytes> {
    Some(SecretBytes::from_slice(v))
}

fn set_field(entry: Id, name: &str, value: Option<&[u8]>, secret: bool) -> Op {
    Op::SetField {
        entry_id: entry,
        name: name.into(),
        value: value.and_then(bytes),
        secret,
    }
}

fn register(client: Id, name: &str) -> Op {
    Op::RegisterDevice {
        client_id: client,
        dev_pk: [client[0]; 32],
        name: name.into(),
    }
}

/// `(client, seq, hlc, clock, ops)`: one event, written out by hand.
type TestEvent = (Id, u64, u64, Vec<(Id, u64)>, Vec<Op>);

/// Builds an op set from hand-written events.
fn set_of(events: Vec<TestEvent>) -> OpSet {
    let mut set = OpSet::new();
    for (client, seq, hlc, clock, ops) in events {
        set.apply_event(
            client,
            seq,
            EventBody {
                hlc,
                clock: VectorClock(clock),
                prev_hash: [0; 32],
                ops,
            },
        );
    }
    set
}

fn value(field: Option<&Field<'_>>) -> Option<Vec<u8>> {
    match field? {
        Field::Value { value, .. } => Some(value.expose().to_vec()),
        Field::Conflict { .. } => panic!("unexpected conflict"),
    }
}

/// The view as a string that, unlike `Debug`, includes the field values: two views
/// with the same structure but different secrets must not compare equal.
fn summary(view: &super::view::VaultView<'_>) -> String {
    let mut out = format!("{view:?}");
    for (id, entry) in &view.entries {
        for (name, field) in &entry.fields {
            match field {
                Field::Value { value, .. } => {
                    out += &format!(
                        "|{}:{name}={}",
                        hex::encode(id),
                        hex::encode(value.expose())
                    );
                }
                Field::Conflict { candidates } => {
                    for c in candidates {
                        let v = c
                            .value
                            .map_or("deleted".into(), |v| hex::encode(v.expose()));
                        out += &format!("|{}:{name}?{v}", hex::encode(id));
                    }
                }
            }
        }
    }
    out
}

/// Every scenario must give the same view after reduction.
fn assert_reduction_keeps_view(set: &mut OpSet) {
    let before = summary(&set.view());
    set.reduce();
    assert_eq!(before, summary(&set.view()));
}

#[test]
fn concurrent_secret_writes_conflict_until_resolved() {
    let base = vec![
        (
            A,
            1,
            1,
            vec![(A, 1)],
            vec![
                register(A, "A"),
                set_field(X, "password", Some(b"p0"), true),
            ],
        ),
        (
            A,
            2,
            2,
            vec![(A, 2)],
            vec![set_field(X, "password", Some(b"from A"), true)],
        ),
        (
            B,
            1,
            3,
            vec![(A, 1), (B, 1)],
            vec![
                register(B, "B"),
                set_field(X, "password", Some(b"from B"), true),
            ],
        ),
    ];
    let mut set = set_of(base);
    let view = set.view();
    let Field::Conflict { candidates } = &view.entries[&X].fields["password"] else {
        panic!("expected a conflict");
    };
    let values: Vec<_> = candidates
        .iter()
        .map(|c| c.value.unwrap().expose().to_vec())
        .collect();
    assert_eq!(values, vec![b"from A".to_vec(), b"from B".to_vec()]);
    drop(view);
    assert_reduction_keeps_view(&mut set);

    // A write that saw both candidates resolves it.
    set.apply_event(
        B,
        2,
        EventBody {
            hlc: 4,
            clock: VectorClock(vec![(A, 2), (B, 2)]),
            prev_hash: [0; 32],
            ops: vec![set_field(X, "password", Some(b"agreed"), true)],
        },
    );
    assert_eq!(
        value(set.view().entries[&X].fields.get("password")),
        Some(b"agreed".to_vec())
    );
    assert_reduction_keeps_view(&mut set);
}

#[test]
fn concurrent_non_secret_writes_are_last_writer_wins() {
    let mut set = set_of(vec![
        (
            A,
            1,
            10,
            vec![(A, 1)],
            vec![register(A, "A"), set_field(X, "title", Some(b"A's"), false)],
        ),
        (
            B,
            1,
            9,
            vec![(B, 1)],
            vec![register(B, "B"), set_field(X, "title", Some(b"B's"), false)],
        ),
        // Same HLC as A: the higher client ID breaks the tie.
        (
            C,
            1,
            10,
            vec![(C, 1)],
            vec![register(C, "C"), set_field(X, "title", Some(b"C's"), false)],
        ),
    ]);
    assert_eq!(
        value(set.view().entries[&X].fields.get("title")),
        Some(b"C's".to_vec())
    );
    assert_reduction_keeps_view(&mut set);
}

#[test]
fn a_delete_wins_only_over_the_writes_it_saw() {
    // B deletes X having seen A's first write, while A concurrently edits it again.
    let mut set = set_of(vec![
        (
            A,
            1,
            1,
            vec![(A, 1)],
            vec![register(A, "A"), set_field(X, "title", Some(b"t"), false)],
        ),
        (
            A,
            2,
            2,
            vec![(A, 2)],
            vec![set_field(X, "notes", Some(b"n"), false)],
        ),
        (
            B,
            1,
            3,
            vec![(A, 1), (B, 1)],
            vec![register(B, "B"), Op::DeleteEntry { entry_id: X }],
        ),
    ]);
    let view = set.view();
    let x = &view.entries[&X];
    assert!(!x.deleted);
    assert!(x.unanswered_delete);
    assert_eq!(
        x.fields.len(),
        2,
        "every field survives, not just the concurrent one"
    );
    drop(view);
    assert_reduction_keeps_view(&mut set);

    // "Keep" answers the delete.
    let mut kept = set_of(vec![]);
    kept.union(set_of(vec![
        (
            A,
            1,
            1,
            vec![(A, 1)],
            vec![register(A, "A"), set_field(X, "title", Some(b"t"), false)],
        ),
        (
            A,
            2,
            2,
            vec![(A, 2)],
            vec![set_field(X, "notes", Some(b"n"), false)],
        ),
        (
            B,
            1,
            3,
            vec![(A, 1), (B, 1)],
            vec![register(B, "B"), Op::DeleteEntry { entry_id: X }],
        ),
        (
            A,
            3,
            4,
            vec![(A, 3), (B, 1)],
            vec![Op::KeepEntry { entry_id: X }],
        ),
    ]));
    let x = &kept.view().entries[&X];
    assert!(!x.deleted && !x.unanswered_delete);

    // A delete that saw everything puts the entry in the trash, fields still readable.
    set.apply_event(
        A,
        3,
        EventBody {
            hlc: 5,
            clock: VectorClock(vec![(A, 3), (B, 1)]),
            prev_hash: [0; 32],
            ops: vec![Op::DeleteEntry { entry_id: X }],
        },
    );
    let view = set.view();
    assert!(view.entries[&X].deleted);
    assert!(!view.entries[&X].unanswered_delete);
    assert_eq!(
        value(view.entries[&X].fields.get("title")),
        Some(b"t".to_vec())
    );
    drop(view);
    assert_reduction_keeps_view(&mut set);
}

#[test]
fn tags_are_an_observed_remove_set() {
    let a_add = Dot {
        client_id: A,
        seq: 1,
        op_index: 2,
    };
    let mut set = set_of(vec![
        (
            A,
            1,
            1,
            vec![(A, 1)],
            vec![
                register(A, "A"),
                set_field(X, "title", Some(b"t"), false),
                Op::AddTag {
                    entry_id: X,
                    tag: "work".into(),
                },
            ],
        ),
        // B removes the add it saw, while C concurrently adds the same tag again.
        (
            B,
            1,
            2,
            vec![(A, 1), (B, 1)],
            vec![
                register(B, "B"),
                Op::RemoveTag {
                    entry_id: X,
                    tag: "work".into(),
                    dots: vec![a_add],
                },
            ],
        ),
        (
            C,
            1,
            3,
            vec![(A, 1), (C, 1)],
            vec![
                register(C, "C"),
                Op::AddTag {
                    entry_id: X,
                    tag: "work".into(),
                },
            ],
        ),
    ]);
    assert!(
        set.view().entries[&X].tags.contains("work"),
        "the concurrent add wins"
    );
    assert_reduction_keeps_view(&mut set);
    assert!(!set.contains(&a_add), "the removed add was dropped");

    // A remove for a different tag or entry doesn't remove anything.
    let mut other = set_of(vec![(
        A,
        1,
        1,
        vec![(A, 1)],
        vec![
            register(A, "A"),
            set_field(X, "title", Some(b"t"), false),
            Op::AddTag {
                entry_id: X,
                tag: "work".into(),
            },
            Op::RemoveTag {
                entry_id: X,
                tag: "home".into(),
                dots: vec![a_add],
            },
        ],
    )]);
    assert!(other.view().entries[&X].tags.contains("work"));
    assert_reduction_keeps_view(&mut other);
}

#[test]
fn device_registry_names_and_retirement() {
    let mut set = set_of(vec![
        (
            A,
            1,
            1,
            vec![(A, 1)],
            vec![
                register(A, "Laptop"),
                Op::SetDeviceName {
                    name: "Old laptop".into(),
                },
            ],
        ),
        (
            A,
            2,
            2,
            vec![(A, 2)],
            vec![Op::SetDeviceName {
                name: "Work laptop".into(),
            }],
        ),
        (
            B,
            1,
            3,
            vec![(A, 2), (B, 1)],
            vec![
                register(B, "Phone"),
                Op::RetireClient {
                    client_id: A,
                    last_seq: 9,
                },
            ],
        ),
        (
            C,
            1,
            4,
            vec![(C, 1)],
            vec![
                register(C, "Tablet"),
                Op::RetireClient {
                    client_id: A,
                    last_seq: 5,
                },
            ],
        ),
    ]);
    let view = set.view();
    assert_eq!(view.devices[&A].name, "Work laptop");
    assert_eq!(
        view.devices[&A].retired_after,
        Some(5),
        "the lowest last_seq applies"
    );
    assert_eq!(view.devices[&B].name, "Phone");
    assert_eq!(view.devices[&C].retired_after, None);
    drop(view);
    assert_reduction_keeps_view(&mut set);
    assert_eq!(
        set.iter()
            .filter(|r| matches!(r.op, Op::SetDeviceName { .. }))
            .count(),
        1
    );
}

#[test]
fn a_conflict_between_deletions_is_no_conflict() {
    let mut set = set_of(vec![
        (
            A,
            1,
            1,
            vec![(A, 1)],
            vec![
                register(A, "A"),
                set_field(X, "password", Some(b"p"), true),
                set_field(X, "title", Some(b"t"), false),
            ],
        ),
        (
            A,
            2,
            2,
            vec![(A, 2)],
            vec![set_field(X, "password", None, true)],
        ),
        (
            B,
            1,
            3,
            vec![(A, 1), (B, 1)],
            vec![register(B, "B"), set_field(X, "password", None, true)],
        ),
    ]);
    assert!(!set.view().entries[&X].fields.contains_key("password"));
    assert_reduction_keeps_view(&mut set);

    // A deletion against a value is a real conflict, shown with "deleted".
    let set = set_of(vec![
        (
            A,
            1,
            1,
            vec![(A, 1)],
            vec![register(A, "A"), set_field(X, "password", Some(b"p"), true)],
        ),
        (
            A,
            2,
            2,
            vec![(A, 2)],
            vec![set_field(X, "password", None, true)],
        ),
        (
            B,
            1,
            3,
            vec![(A, 1), (B, 1)],
            vec![register(B, "B"), set_field(X, "password", Some(b"q"), true)],
        ),
    ]);
    let view = set.view();
    let Field::Conflict { candidates } = &view.entries[&X].fields["password"] else {
        panic!("expected a conflict");
    };
    assert!(matches!(
        candidates.as_slice(),
        [
            Candidate { value: None, .. },
            Candidate { value: Some(_), .. }
        ]
    ));
}

#[test]
fn remove_tag_edits_list_what_was_seen() {
    let set = set_of(vec![(
        A,
        1,
        1,
        vec![(A, 1)],
        vec![
            register(A, "A"),
            set_field(X, "title", Some(b"t"), false),
            Op::AddTag {
                entry_id: X,
                tag: "work".into(),
            },
        ],
    )]);
    let ops = set.ops_for(vec![
        Edit::RemoveTag {
            entry_id: X,
            tag: "work".into(),
        },
        Edit::SetField {
            entry_id: X,
            name: "otp".into(),
            value: bytes(b"secret"),
            secret: false,
        },
    ]);
    assert!(
        matches!(&ops[0], Op::RemoveTag { dots, .. } if dots == &[Dot { client_id: A, seq: 1, op_index: 2 }])
    );
    assert!(
        matches!(&ops[1], Op::SetField { secret: true, .. }),
        "otp is always secret"
    );
}

// ---- Convergence (spec §14.2) ------------------------------------------------

const CLIENTS: [Id; 3] = [A, B, C];
const ENTRIES: [Id; 2] = [[0xe1; 16], [0xe2; 16]];
const FIELDS: [&str; 3] = ["title", "password", "notes"];
const TAGS: [&str; 2] = ["t1", "t2"];

#[derive(Debug, Clone)]
enum EditSpec {
    Set {
        entry: usize,
        field: usize,
        value: Option<u8>,
        secret: bool,
    },
    Delete(usize),
    Keep(usize),
    AddTag(usize, usize),
    RemoveTag(usize, usize),
    Rename(u8),
}

#[derive(Debug, Clone)]
enum Action {
    Write { client: usize, edits: Vec<EditSpec> },
    Sync { to: usize, from: usize },
    Reduce { client: usize },
}

fn edit_spec() -> impl Strategy<Value = EditSpec> {
    prop_oneof![
        4 => (0..2usize, 0..3usize, proptest::option::weighted(0.8, 0..4u8), any::<bool>())
            .prop_map(|(entry, field, value, secret)| EditSpec::Set { entry, field, value, secret }),
        1 => (0..2usize).prop_map(EditSpec::Delete),
        1 => (0..2usize).prop_map(EditSpec::Keep),
        1 => (0..2usize, 0..2usize).prop_map(|(e, t)| EditSpec::AddTag(e, t)),
        1 => (0..2usize, 0..2usize).prop_map(|(e, t)| EditSpec::RemoveTag(e, t)),
        1 => any::<u8>().prop_map(EditSpec::Rename),
    ]
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        3 => (0..3usize, proptest::collection::vec(edit_spec(), 0..4))
            .prop_map(|(client, edits)| Action::Write { client, edits }),
        3 => (0..3usize, 0..3usize).prop_map(|(to, from)| Action::Sync { to, from }),
        1 => (0..3usize).prop_map(|client| Action::Reduce { client }),
    ]
}

impl EditSpec {
    fn to_edit(&self) -> Edit {
        match *self {
            EditSpec::Set {
                entry,
                field,
                value,
                secret,
            } => Edit::SetField {
                entry_id: ENTRIES[entry],
                name: FIELDS[field].into(),
                value: value.and_then(|v| bytes(&[v])),
                secret,
            },
            EditSpec::Delete(e) => Edit::DeleteEntry {
                entry_id: ENTRIES[e],
            },
            EditSpec::Keep(e) => Edit::KeepEntry {
                entry_id: ENTRIES[e],
            },
            EditSpec::AddTag(e, t) => Edit::AddTag {
                entry_id: ENTRIES[e],
                tag: TAGS[t].into(),
            },
            EditSpec::RemoveTag(e, t) => Edit::RemoveTag {
                entry_id: ENTRIES[e],
                tag: TAGS[t].into(),
            },
            EditSpec::Rename(n) => Edit::SetDeviceName {
                name: format!("device {n}"),
            },
        }
    }
}

/// A simulated device: what it has applied, and its own op set.
struct Device {
    id: Id,
    next_seq: u64,
    clock: VectorClock,
    latest_hlc: u64,
    known: BTreeSet<(Id, u64)>,
    set: OpSet,
}

/// Every event ever written, encoded, as the shared storage would hold them.
type Log = BTreeMap<(Id, u64), Zeroizing<Vec<u8>>>;

fn decode(log: &Log, key: &(Id, u64)) -> EventBody {
    cbor::decode_strict(&log[key], "event body").unwrap()
}

impl Device {
    fn new(id: Id, log: &mut Log) -> Self {
        let mut device = Device {
            id,
            next_seq: 1,
            clock: VectorClock::default(),
            latest_hlc: 0,
            known: BTreeSet::new(),
            set: OpSet::new(),
        };
        device.write(vec![register(id, "new")], log);
        device
    }

    fn write(&mut self, ops: Vec<Op>, log: &mut Log) {
        let seq = self.next_seq;
        let mut clock = self.clock.clone();
        clock.observe(self.id, seq);
        let body = EventBody {
            // A frozen wall clock: HLCs advance by counter alone, so concurrent writes
            // often tie and the client-ID tiebreak gets exercised.
            hlc: hlc::next(self.latest_hlc, 0).unwrap(),
            clock,
            prev_hash: if seq == 1 { [0; 32] } else { [1; 32] },
            ops,
        };
        body.validate(&self.id, seq).unwrap();
        log.insert((self.id, seq), cbor::encode(&body));
        self.next_seq += 1;
        self.receive(log, (self.id, seq));
    }

    fn receive(&mut self, log: &Log, key: (Id, u64)) {
        if self.known.insert(key) {
            let body = decode(log, &key);
            self.latest_hlc = self.latest_hlc.max(body.hlc);
            self.clock.observe(key.0, key.1);
            self.set.apply_event(key.0, key.1, body);
        }
    }
}

fn run(actions: &[Action]) -> (Vec<Device>, Log) {
    let mut log = Log::new();
    let mut devices: Vec<Device> = CLIENTS
        .iter()
        .map(|&id| Device::new(id, &mut log))
        .collect();
    for action in actions {
        match action {
            Action::Write { client, edits } => {
                let device = &mut devices[*client];
                let ops = device
                    .set
                    .ops_for(edits.iter().map(EditSpec::to_edit).collect());
                device.write(ops, &mut log);
            }
            Action::Sync { to, from } => {
                let missing: Vec<_> = devices[*from]
                    .known
                    .difference(&devices[*to].known)
                    .copied()
                    .collect();
                for key in missing {
                    devices[*to].receive(&log, key);
                }
            }
            Action::Reduce { client } => devices[*client].set.reduce(),
        }
    }
    (devices, log)
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// Devices that end up with the same events end up with the same vault, however
    /// they got there and whatever they compacted along the way.
    #[test]
    fn devices_converge(actions in proptest::collection::vec(action(), 0..40),
                        order in any::<u64>()) {
        let (mut devices, log) = run(&actions);
        for _ in 0..2 {
            for to in 0..3 {
                for from in 0..3 {
                    let missing: Vec<_> = devices[from].known.difference(&devices[to].known).copied().collect();
                    for key in missing {
                        devices[to].receive(&log, key);
                    }
                }
            }
        }
        let views: Vec<String> = devices.iter().map(|d| summary(&d.set.view())).collect();
        prop_assert_eq!(&views[0], &views[1]);
        prop_assert_eq!(&views[1], &views[2]);

        // The full log applied in a shuffled order, never reduced, gives the same view.
        let mut keys: Vec<_> = log.keys().copied().collect();
        let mut state = order;
        for i in (1..keys.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            keys.swap(i, (state >> 33) as usize % (i + 1));
        }
        let mut full = OpSet::new();
        for key in &keys {
            full.apply_event(key.0, key.1, decode(&log, key));
        }
        prop_assert_eq!(&summary(&full.view()), &views[0]);
    }

    /// Reducing any two parts of the log separately and taking their union gives the
    /// same vault as the whole log (spec §9.3: snapshots combine freely).
    #[test]
    fn reduced_parts_union_to_the_whole(actions in proptest::collection::vec(action(), 0..40),
                                        mask in any::<u64>()) {
        let (_, log) = run(&actions);
        let mut whole = OpSet::new();
        let (mut left, mut right) = (OpSet::new(), OpSet::new());
        for (i, key) in log.keys().enumerate() {
            whole.apply_event(key.0, key.1, decode(&log, key));
            // Some events go to both parts, as overlapping snapshots would.
            let part = (mask >> (i % 64)) & 3;
            if part != 1 { left.apply_event(key.0, key.1, decode(&log, key)); }
            if part != 2 { right.apply_event(key.0, key.1, decode(&log, key)); }
        }
        let expected = summary(&whole.view());
        left.reduce();
        right.reduce();
        left.union(right);
        prop_assert_eq!(&summary(&left.view()), &expected);
        left.reduce();
        prop_assert_eq!(&summary(&left.view()), &expected);
        whole.reduce();
        prop_assert_eq!(&summary(&whole.view()), &expected);
    }
}
