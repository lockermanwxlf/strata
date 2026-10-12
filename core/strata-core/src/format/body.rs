//! CBOR schemas for authenticated bodies (spec §8.2, §10.1) and their validation.
//!
//! Encoding is written out by hand rather than derived: ops are flat arrays whose
//! first element is the op type (spec §8.2), and doing it by hand keeps the byte
//! layout exactly what the spec says. Decoding is always followed by the strict
//! re-encode check in `encoding::cbor`.

use minicbor::data::Type;
use minicbor::decode::{self, Decoder};
use minicbor::encode::{self, Encoder, Write};
use minicbor::{Decode, Encode};
use unicode_normalization::is_nfc;

use super::Id;
use crate::crypto::SecretBytes;
use crate::error::{CoreError, Result};

pub const MAX_OPS_PER_EVENT: usize = 4096;
pub const MAX_CLOCK_ENTRIES: usize = 4096;
pub const MAX_FIELD_VALUE_LEN: usize = 64 * 1024;
pub const MAX_NAME_LEN: usize = 128;

/// Well-known fields that MUST be secret (spec §8.2).
const ALWAYS_SECRET_FIELDS: [&str; 2] = ["password", "otp"];

/// Identifies one op: event `(client_id, seq)`, position `op_index` in its ops array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dot {
    pub client_id: Id,
    pub seq: u64,
    pub op_index: u32,
}

/// `(client_id, seq)` pairs, sorted by client ID, no duplicates, no zero seqs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VectorClock(pub Vec<(Id, u64)>);

impl VectorClock {
    /// The highest seq of `client` this clock has seen (0 if none).
    pub fn get(&self, client: &Id) -> u64 {
        self.0
            .binary_search_by(|(c, _)| c.cmp(client))
            .map_or(0, |i| self.0[i].1)
    }

    pub fn validate(&self, what: &'static str) -> Result<()> {
        if self.0.len() > MAX_CLOCK_ENTRIES {
            return Err(CoreError::rejected(what, "too many vector clock entries"));
        }
        if self.0.iter().any(|&(_, seq)| seq == 0) {
            return Err(CoreError::rejected(what, "zero seq in vector clock"));
        }
        if !self.0.windows(2).all(|w| w[0].0 < w[1].0) {
            return Err(CoreError::rejected(
                what,
                "vector clock not sorted or has duplicates",
            ));
        }
        Ok(())
    }
}

/// One change (spec §8.2). Field values are `SecretBytes`, so they are wiped when
/// the op is dropped, and never printed.
#[derive(Debug, PartialEq, Eq)]
pub enum Op {
    SetField {
        entry_id: Id,
        name: String,
        value: Option<SecretBytes>,
        secret: bool,
    },
    DeleteEntry {
        entry_id: Id,
    },
    KeepEntry {
        entry_id: Id,
    },
    AddTag {
        entry_id: Id,
        tag: String,
    },
    RemoveTag {
        entry_id: Id,
        tag: String,
        dots: Vec<Dot>,
    },
    RetireClient {
        client_id: Id,
        last_seq: u64,
    },
    RegisterDevice {
        client_id: Id,
        dev_pk: [u8; 32],
        name: String,
    },
    SetDeviceName {
        name: String,
    },
}

impl Op {
    pub const SET_FIELD: u8 = 1;
    pub const DELETE_ENTRY: u8 = 2;
    pub const KEEP_ENTRY: u8 = 3;
    pub const ADD_TAG: u8 = 4;
    pub const REMOVE_TAG: u8 = 5;
    pub const RETIRE_CLIENT: u8 = 6;
    pub const REGISTER_DEVICE: u8 = 7;
    pub const SET_DEVICE_NAME: u8 = 8;

    /// Checks everything about the op that doesn't depend on where it appears.
    /// `RegisterDevice` placement is checked by the caller, which knows the dot.
    pub fn validate(&self, what: &'static str) -> Result<()> {
        match self {
            Op::SetField {
                name,
                value,
                secret,
                ..
            } => {
                check_name(name, what)?;
                if value
                    .as_ref()
                    .is_some_and(|v| v.len() > MAX_FIELD_VALUE_LEN)
                {
                    return Err(CoreError::rejected(what, "field value too large"));
                }
                if !secret && ALWAYS_SECRET_FIELDS.contains(&name.as_str()) {
                    return Err(CoreError::rejected(what, "field must be secret"));
                }
            }
            Op::AddTag { tag, .. } => check_name(tag, what)?,
            Op::RemoveTag { tag, dots, .. } => {
                check_name(tag, what)?;
                for dot in dots {
                    check_dot(dot, what)?;
                }
            }
            Op::RegisterDevice { name, .. } | Op::SetDeviceName { name } => check_name(name, what)?,
            Op::DeleteEntry { .. } | Op::KeepEntry { .. } | Op::RetireClient { .. } => {}
        }
        Ok(())
    }

    /// `RegisterDevice` is valid only as op 0 of the client's first event, naming
    /// that client (spec §6.4); and that op must be there.
    fn check_registration(&self, dot: &Dot, what: &'static str) -> Result<()> {
        let first_op_of_first_event = dot.seq == 1 && dot.op_index == 0;
        match self {
            Op::RegisterDevice { client_id, .. } => {
                if !first_op_of_first_event || *client_id != dot.client_id {
                    return Err(CoreError::rejected(what, "misplaced device registration"));
                }
            }
            _ if first_op_of_first_event => {
                return Err(CoreError::rejected(
                    what,
                    "first event must register the device",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

/// Field names, tags and device names: 1..=128 bytes of NFC UTF-8 (spec §4).
fn check_name(name: &str, what: &'static str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(CoreError::rejected(what, "name length out of range"));
    }
    if !is_nfc(name) {
        return Err(CoreError::rejected(what, "name is not NFC"));
    }
    Ok(())
}

fn check_dot(dot: &Dot, what: &'static str) -> Result<()> {
    if dot.seq == 0 || dot.op_index as usize >= MAX_OPS_PER_EVENT {
        return Err(CoreError::rejected(what, "invalid dot"));
    }
    Ok(())
}

/// An event's plaintext (spec §8.2).
#[derive(Debug, PartialEq, Eq)]
pub struct EventBody {
    pub hlc: u64,
    pub clock: VectorClock,
    pub prev_hash: [u8; 32],
    pub ops: Vec<Op>,
}

impl EventBody {
    /// Everything spec §8.2 and §9.1 require that can be checked from the event alone.
    pub fn validate(&self, client_id: &Id, seq: u64) -> Result<()> {
        const WHAT: &str = "event body";
        self.clock.validate(WHAT)?;
        if self.clock.get(client_id) != seq {
            return Err(CoreError::rejected(WHAT, "vector clock doesn't match seq"));
        }
        if seq == 1 && self.prev_hash != [0; 32] {
            return Err(CoreError::rejected(WHAT, "first event has a prev_hash"));
        }
        if self.ops.len() > MAX_OPS_PER_EVENT {
            return Err(CoreError::rejected(WHAT, "too many ops"));
        }
        if seq == 1 && self.ops.is_empty() {
            return Err(CoreError::rejected(
                WHAT,
                "first event must register the device",
            ));
        }
        for (i, op) in self.ops.iter().enumerate() {
            op.validate(WHAT)?;
            let dot = Dot {
                client_id: *client_id,
                seq,
                op_index: i as u32,
            };
            op.check_registration(&dot, WHAT)?;
        }
        Ok(())
    }
}

/// One op kept in a snapshot, with the causal metadata merging needs (spec §10.1).
#[derive(Debug, PartialEq, Eq)]
pub struct RetainedOp {
    pub dot: Dot,
    pub hlc: u64,
    pub vc_index: u32,
    pub op: Op,
}

/// A snapshot's plaintext (spec §10.1).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SnapshotBody {
    /// `(client_id, seq, H(c, seq))`, sorted by client ID.
    pub watermark: Vec<(Id, u64, [u8; 32])>,
    pub clocks: Vec<VectorClock>,
    pub ops: Vec<RetainedOp>,
}

impl SnapshotBody {
    pub fn validate(&self) -> Result<()> {
        const WHAT: &str = "snapshot body";
        if self.watermark.iter().any(|&(_, seq, _)| seq == 0)
            || !self.watermark.windows(2).all(|w| w[0].0 < w[1].0)
        {
            return Err(CoreError::rejected(WHAT, "invalid watermark"));
        }
        for clock in &self.clocks {
            clock.validate(WHAT)?;
        }
        for r in &self.ops {
            check_dot(&r.dot, WHAT)?;
            if r.vc_index as usize >= self.clocks.len() {
                return Err(CoreError::rejected(WHAT, "vector clock index out of range"));
            }
            r.op.validate(WHAT)?;
            r.op.check_registration(&r.dot, WHAT)?;
        }
        Ok(())
    }
}

// ---- CBOR encoding ----------------------------------------------------------

type EncResult<W> = core::result::Result<(), encode::Error<<W as Write>::Error>>;

fn expect_array(d: &mut Decoder<'_>, len: u64) -> core::result::Result<(), decode::Error> {
    match d.array()? {
        Some(n) if n == len => Ok(()),
        _ => Err(decode::Error::message("wrong array length")),
    }
}

fn expect_key(d: &mut Decoder<'_>, key: u64) -> core::result::Result<(), decode::Error> {
    if d.u64()? != key {
        return Err(decode::Error::message("unexpected map key"));
    }
    Ok(())
}

fn decode_array_len(d: &mut Decoder<'_>, max: usize) -> core::result::Result<usize, decode::Error> {
    match d.array()? {
        Some(n) if n <= max as u64 => Ok(n as usize),
        _ => Err(decode::Error::message("array too long or indefinite")),
    }
}

fn decode_bytes<const N: usize>(
    d: &mut Decoder<'_>,
) -> core::result::Result<[u8; N], decode::Error> {
    d.bytes()?
        .try_into()
        .map_err(|_| decode::Error::message("wrong byte string length"))
}

impl<C> Encode<C> for Dot {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, _: &mut C) -> EncResult<W> {
        e.array(3)?
            .bytes(&self.client_id)?
            .u64(self.seq)?
            .u32(self.op_index)?;
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for Dot {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> core::result::Result<Self, decode::Error> {
        expect_array(d, 3)?;
        Ok(Dot {
            client_id: decode_bytes(d)?,
            seq: d.u64()?,
            op_index: d.u32()?,
        })
    }
}

impl<C> Encode<C> for VectorClock {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, _: &mut C) -> EncResult<W> {
        e.array(self.0.len() as u64)?;
        for (client, seq) in &self.0 {
            e.array(2)?.bytes(client)?.u64(*seq)?;
        }
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for VectorClock {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> core::result::Result<Self, decode::Error> {
        let n = decode_array_len(d, MAX_CLOCK_ENTRIES)?;
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            expect_array(d, 2)?;
            entries.push((decode_bytes(d)?, d.u64()?));
        }
        Ok(VectorClock(entries))
    }
}

impl<C> Encode<C> for Op {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, ctx: &mut C) -> EncResult<W> {
        match self {
            Op::SetField {
                entry_id,
                name,
                value,
                secret,
            } => {
                e.array(5)?.u8(Op::SET_FIELD)?.bytes(entry_id)?.str(name)?;
                match value {
                    Some(v) => e.bytes(v.expose())?,
                    None => e.null()?,
                };
                e.bool(*secret)?;
            }
            Op::DeleteEntry { entry_id } => {
                e.array(2)?.u8(Op::DELETE_ENTRY)?.bytes(entry_id)?;
            }
            Op::KeepEntry { entry_id } => {
                e.array(2)?.u8(Op::KEEP_ENTRY)?.bytes(entry_id)?;
            }
            Op::AddTag { entry_id, tag } => {
                e.array(3)?.u8(Op::ADD_TAG)?.bytes(entry_id)?.str(tag)?;
            }
            Op::RemoveTag {
                entry_id,
                tag,
                dots,
            } => {
                e.array(4)?.u8(Op::REMOVE_TAG)?.bytes(entry_id)?.str(tag)?;
                e.array(dots.len() as u64)?;
                for dot in dots {
                    dot.encode(e, ctx)?;
                }
            }
            Op::RetireClient {
                client_id,
                last_seq,
            } => {
                e.array(3)?
                    .u8(Op::RETIRE_CLIENT)?
                    .bytes(client_id)?
                    .u64(*last_seq)?;
            }
            Op::RegisterDevice {
                client_id,
                dev_pk,
                name,
            } => {
                e.array(4)?
                    .u8(Op::REGISTER_DEVICE)?
                    .bytes(client_id)?
                    .bytes(dev_pk)?
                    .str(name)?;
            }
            Op::SetDeviceName { name } => {
                e.array(2)?.u8(Op::SET_DEVICE_NAME)?.str(name)?;
            }
        }
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for Op {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> core::result::Result<Self, decode::Error> {
        let len = d
            .array()?
            .ok_or_else(|| decode::Error::message("indefinite op"))?;
        let ty = d.u8()?;
        let want = match ty {
            Op::SET_FIELD => 5,
            Op::DELETE_ENTRY | Op::KEEP_ENTRY | Op::SET_DEVICE_NAME => 2,
            Op::ADD_TAG | Op::RETIRE_CLIENT => 3,
            Op::REMOVE_TAG | Op::REGISTER_DEVICE => 4,
            _ => return Err(decode::Error::message("unknown op type")),
        };
        if len != want {
            return Err(decode::Error::message("wrong op length"));
        }
        Ok(match ty {
            Op::SET_FIELD => Op::SetField {
                entry_id: decode_bytes(d)?,
                name: d.str()?.to_owned(),
                value: if d.datatype()? == Type::Null {
                    d.null()?;
                    None
                } else {
                    let v = d.bytes()?;
                    if v.len() > MAX_FIELD_VALUE_LEN {
                        return Err(decode::Error::message("field value too large"));
                    }
                    Some(SecretBytes::from_slice(v))
                },
                secret: d.bool()?,
            },
            Op::DELETE_ENTRY => Op::DeleteEntry {
                entry_id: decode_bytes(d)?,
            },
            Op::KEEP_ENTRY => Op::KeepEntry {
                entry_id: decode_bytes(d)?,
            },
            Op::ADD_TAG => Op::AddTag {
                entry_id: decode_bytes(d)?,
                tag: d.str()?.to_owned(),
            },
            Op::REMOVE_TAG => {
                let entry_id = decode_bytes(d)?;
                let tag = d.str()?.to_owned();
                let n = decode_array_len(d, usize::MAX)?;
                let mut dots = Vec::new();
                for _ in 0..n {
                    dots.push(Dot::decode(d, ctx)?);
                }
                Op::RemoveTag {
                    entry_id,
                    tag,
                    dots,
                }
            }
            Op::RETIRE_CLIENT => Op::RetireClient {
                client_id: decode_bytes(d)?,
                last_seq: d.u64()?,
            },
            Op::REGISTER_DEVICE => Op::RegisterDevice {
                client_id: decode_bytes(d)?,
                dev_pk: decode_bytes(d)?,
                name: d.str()?.to_owned(),
            },
            _ => Op::SetDeviceName {
                name: d.str()?.to_owned(),
            },
        })
    }
}

impl<C> Encode<C> for EventBody {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, ctx: &mut C) -> EncResult<W> {
        e.map(4)?.u8(1)?.u64(self.hlc)?.u8(2)?;
        self.clock.encode(e, ctx)?;
        e.u8(3)?.bytes(&self.prev_hash)?.u8(4)?;
        e.array(self.ops.len() as u64)?;
        for op in &self.ops {
            op.encode(e, ctx)?;
        }
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for EventBody {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> core::result::Result<Self, decode::Error> {
        if d.map()? != Some(4) {
            return Err(decode::Error::message("event body must be a 4-entry map"));
        }
        expect_key(d, 1)?;
        let hlc = d.u64()?;
        expect_key(d, 2)?;
        let clock = VectorClock::decode(d, ctx)?;
        expect_key(d, 3)?;
        let prev_hash = decode_bytes(d)?;
        expect_key(d, 4)?;
        let n = decode_array_len(d, MAX_OPS_PER_EVENT)?;
        let mut ops = Vec::with_capacity(n);
        for _ in 0..n {
            ops.push(Op::decode(d, ctx)?);
        }
        Ok(EventBody {
            hlc,
            clock,
            prev_hash,
            ops,
        })
    }
}

impl<C> Encode<C> for SnapshotBody {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, ctx: &mut C) -> EncResult<W> {
        e.map(3)?.u8(1)?.array(self.watermark.len() as u64)?;
        for (client, seq, hash) in &self.watermark {
            e.array(3)?.bytes(client)?.u64(*seq)?.bytes(hash)?;
        }
        e.u8(2)?.array(self.clocks.len() as u64)?;
        for clock in &self.clocks {
            clock.encode(e, ctx)?;
        }
        e.u8(3)?.array(self.ops.len() as u64)?;
        for r in &self.ops {
            e.array(6)?
                .bytes(&r.dot.client_id)?
                .u64(r.dot.seq)?
                .u32(r.dot.op_index)?
                .u64(r.hlc)?
                .u32(r.vc_index)?;
            r.op.encode(e, ctx)?;
        }
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for SnapshotBody {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> core::result::Result<Self, decode::Error> {
        if d.map()? != Some(3) {
            return Err(decode::Error::message(
                "snapshot body must be a 3-entry map",
            ));
        }
        // Element counts aren't capped here (the 64 MiB file limit bounds them), so
        // nothing is preallocated from a length the input declares.
        expect_key(d, 1)?;
        let mut watermark = Vec::new();
        for _ in 0..decode_array_len(d, usize::MAX)? {
            expect_array(d, 3)?;
            watermark.push((decode_bytes(d)?, d.u64()?, decode_bytes(d)?));
        }
        expect_key(d, 2)?;
        let mut clocks = Vec::new();
        for _ in 0..decode_array_len(d, usize::MAX)? {
            clocks.push(VectorClock::decode(d, ctx)?);
        }
        expect_key(d, 3)?;
        let mut ops = Vec::new();
        for _ in 0..decode_array_len(d, usize::MAX)? {
            expect_array(d, 6)?;
            let dot = Dot {
                client_id: decode_bytes(d)?,
                seq: d.u64()?,
                op_index: d.u32()?,
            };
            ops.push(RetainedOp {
                dot,
                hlc: d.u64()?,
                vc_index: d.u32()?,
                op: Op::decode(d, ctx)?,
            });
        }
        Ok(SnapshotBody {
            watermark,
            clocks,
            ops,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::encoding::cbor::{decode_strict, encode};

    pub(crate) const ALICE: Id = [0xa1; 16];
    pub(crate) const BOB: Id = [0xb0; 16];
    pub(crate) const ENTRY: Id = [0xe0; 16];

    /// A first event that uses every op type.
    pub(crate) fn sample_first_event() -> EventBody {
        EventBody {
            hlc: 0x0001_8f00_0000_0001,
            clock: VectorClock(vec![(ALICE, 1)]),
            prev_hash: [0; 32],
            ops: vec![
                Op::RegisterDevice {
                    client_id: ALICE,
                    dev_pk: [0x11; 32],
                    name: "Laptop".into(),
                },
                Op::SetField {
                    entry_id: ENTRY,
                    name: "title".into(),
                    value: Some(SecretBytes::from_slice(b"Example")),
                    secret: false,
                },
                Op::SetField {
                    entry_id: ENTRY,
                    name: "password".into(),
                    value: Some(SecretBytes::from_slice(b"hunter2")),
                    secret: true,
                },
                Op::SetField {
                    entry_id: ENTRY,
                    name: "notes".into(),
                    value: None,
                    secret: false,
                },
                Op::AddTag {
                    entry_id: ENTRY,
                    tag: "work".into(),
                },
                Op::RemoveTag {
                    entry_id: ENTRY,
                    tag: "work".into(),
                    dots: vec![Dot {
                        client_id: ALICE,
                        seq: 1,
                        op_index: 4,
                    }],
                },
                Op::KeepEntry { entry_id: ENTRY },
                Op::DeleteEntry { entry_id: ENTRY },
                Op::RetireClient {
                    client_id: BOB,
                    last_seq: 7,
                },
                Op::SetDeviceName {
                    name: "Work laptop".into(),
                },
            ],
        }
    }

    #[test]
    fn event_body_round_trip_and_validation() {
        let body = sample_first_event();
        body.validate(&ALICE, 1).unwrap();
        let bytes = encode(&body);
        assert_eq!(decode_strict::<EventBody>(&bytes, "t").unwrap(), body);
    }

    #[test]
    fn op_wire_format_is_flat() {
        let op = Op::AddTag {
            entry_id: [0; 16],
            tag: "a".into(),
        };
        let mut expected = vec![0x83, 0x04, 0x50];
        expected.extend_from_slice(&[0; 16]);
        expected.extend_from_slice(&[0x61, b'a']);
        assert_eq!(encode(&op).as_slice(), expected);
    }

    #[test]
    fn rejects_bad_bodies() {
        let validate = |f: &dyn Fn(&mut EventBody), client: Id, seq: u64| {
            let mut body = sample_first_event();
            f(&mut body);
            body.validate(&client, seq)
        };
        type Case<'a> = (&'a str, &'a dyn Fn(&mut EventBody), Id, u64);
        let cases: &[Case] = &[
            ("seq mismatch", &|_| {}, ALICE, 2),
            ("prev_hash on first", &|b| b.prev_hash = [1; 32], ALICE, 1),
            (
                "unsorted clock",
                &|b| b.clock = VectorClock(vec![(BOB, 1), (ALICE, 1)]),
                ALICE,
                1,
            ),
            (
                "zero seq in clock",
                &|b| b.clock.0.push(([0xff; 16], 0)),
                ALICE,
                1,
            ),
            (
                "missing registration",
                &|b| {
                    b.ops.remove(0);
                },
                ALICE,
                1,
            ),
            (
                "registration for another client",
                &|b| {
                    b.ops[0] = Op::RegisterDevice {
                        client_id: BOB,
                        dev_pk: [0; 32],
                        name: "x".into(),
                    }
                },
                ALICE,
                1,
            ),
            (
                "second registration",
                &|b| {
                    b.ops.push(Op::RegisterDevice {
                        client_id: ALICE,
                        dev_pk: [0; 32],
                        name: "x".into(),
                    })
                },
                ALICE,
                1,
            ),
            (
                "password not secret",
                &|b| {
                    b.ops[2] = Op::SetField {
                        entry_id: ENTRY,
                        name: "password".into(),
                        value: None,
                        secret: false,
                    }
                },
                ALICE,
                1,
            ),
            (
                "empty name",
                &|b| {
                    b.ops.push(Op::AddTag {
                        entry_id: ENTRY,
                        tag: String::new(),
                    })
                },
                ALICE,
                1,
            ),
            (
                "long name",
                &|b| {
                    b.ops.push(Op::AddTag {
                        entry_id: ENTRY,
                        tag: "x".repeat(129),
                    })
                },
                ALICE,
                1,
            ),
            (
                "non-NFC name",
                &|b| {
                    b.ops.push(Op::AddTag {
                        entry_id: ENTRY,
                        tag: "cafe\u{301}".into(),
                    })
                },
                ALICE,
                1,
            ),
            (
                "zero-seq dot",
                &|b| {
                    b.ops.push(Op::RemoveTag {
                        entry_id: ENTRY,
                        tag: "t".into(),
                        dots: vec![Dot {
                            client_id: ALICE,
                            seq: 0,
                            op_index: 0,
                        }],
                    })
                },
                ALICE,
                1,
            ),
        ];
        for (name, f, client, seq) in cases {
            assert!(validate(f, *client, *seq).is_err(), "{name} was accepted");
        }
        // A later event must not register again.
        let mut later = sample_first_event();
        later.clock = VectorClock(vec![(ALICE, 2)]);
        later.prev_hash = [9; 32];
        assert!(later.validate(&ALICE, 2).is_err());
        later.ops.remove(0);
        later.validate(&ALICE, 2).unwrap();
    }

    #[test]
    fn rejects_unknown_ops_and_wrong_shapes() {
        // [9, h'00'] — unknown op type 9
        assert!(decode_strict::<Op>(&[0x82, 0x09, 0x41, 0x00], "t").is_err());
        // DeleteEntry with an extra element
        let mut bad = vec![0x83, 0x02, 0x50];
        bad.extend_from_slice(&[0; 16]);
        bad.push(0x00);
        assert!(decode_strict::<Op>(&bad, "t").is_err());
        // DeleteEntry with a 15-byte entry ID
        let mut short = vec![0x82, 0x02, 0x4f];
        short.extend_from_slice(&[0; 15]);
        assert!(decode_strict::<Op>(&short, "t").is_err());
    }

    #[test]
    fn snapshot_body_round_trip_and_validation() {
        let body = SnapshotBody {
            watermark: vec![(ALICE, 3, [1; 32]), (BOB, 1, [2; 32])],
            clocks: vec![VectorClock(vec![(ALICE, 3), (BOB, 1)])],
            ops: vec![RetainedOp {
                dot: Dot {
                    client_id: ALICE,
                    seq: 1,
                    op_index: 0,
                },
                hlc: 5,
                vc_index: 0,
                op: Op::RegisterDevice {
                    client_id: ALICE,
                    dev_pk: [3; 32],
                    name: "Laptop".into(),
                },
            }],
        };
        body.validate().unwrap();
        let bytes = encode(&body);
        assert_eq!(decode_strict::<SnapshotBody>(&bytes, "t").unwrap(), body);

        let mut bad_index = body;
        bad_index.ops[0].vc_index = 1;
        assert!(bad_index.validate().is_err());
    }
}
