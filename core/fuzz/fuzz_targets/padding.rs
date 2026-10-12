//! `unpad` on arbitrary bytes: it must never panic, and anything it accepts must be
//! exactly the canonical padding of the body it returns.

#![no_main]

use libfuzzer_sys::fuzz_target;
use strata_core::encoding::padding::{pad, unpad};

fuzz_target!(|data: &[u8]| {
    if let Ok(body) = unpad(data) {
        assert_eq!(pad(body).unwrap().as_slice(), data);
    }
});
