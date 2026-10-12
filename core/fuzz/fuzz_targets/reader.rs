//! Drives `Reader` with an arbitrary sequence of reads over arbitrary bytes.
//! The first input byte says how many of the following bytes are read ops; the
//! rest is the buffer being parsed. Any panic is a bug.

#![no_main]

use libfuzzer_sys::fuzz_target;
use strata_core::encoding::Reader;

fuzz_target!(|data: &[u8]| {
    let Some((&n_ops, rest)) = data.split_first() else {
        return;
    };
    let (ops, buf) = rest.split_at((n_ops as usize).min(rest.len()));
    let mut r = Reader::new(buf, "fuzz");
    for &op in ops {
        let before = r.position();
        let ok = match op % 7 {
            0 => r.u8().is_ok(),
            1 => r.u16_le().is_ok(),
            2 => r.u32_le().is_ok(),
            3 => r.u64_le().is_ok(),
            4 => r.array::<16>().is_ok(),
            5 => r.magic(b"STEV").is_ok(),
            _ => r.take((op >> 3) as usize).is_ok(),
        };
        assert!(r.position() <= buf.len());
        assert!(ok || r.position() == before);
    }
    let _ = r.finish();
});
