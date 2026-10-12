//! `decode_strict` on arbitrary bytes, for a body shaped like the spec's (an
//! integer-keyed map holding integers, byte strings, text, arrays and nested maps).
//! It must never panic, and anything it accepts must re-encode to the same bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use minicbor::{Decode, Encode};
use strata_core::encoding::cbor::{decode_strict, encode};

#[derive(Encode, Decode)]
#[cbor(map)]
struct Body {
    #[n(1)]
    hlc: u64,
    #[n(2)]
    clock: Vec<(minicbor::bytes::ByteVec, u64)>,
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    prev: Vec<u8>,
    #[n(4)]
    ops: Vec<Op>,
}

#[derive(Encode, Decode)]
#[cbor(map)]
struct Op {
    #[n(0)]
    kind: u8,
    #[n(1)]
    name: Option<String>,
    #[n(2)]
    secret: Option<bool>,
}

fuzz_target!(|data: &[u8]| {
    if let Ok(body) = decode_strict::<Body>(data, "fuzz") {
        assert_eq!(encode(&body), data);
    }
});
