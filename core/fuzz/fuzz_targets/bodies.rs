//! The CBOR body decoders and validators (spec §8.2, §10.1) on arbitrary bytes,
//! as if they had just been decrypted. The first input byte picks the body type.
//! Must never panic, and anything accepted must re-encode to the same bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use strata_core::encoding::cbor::{decode_strict, encode};
use strata_core::format::body::{EventBody, SnapshotBody};

fuzz_target!(|data: &[u8]| {
    let Some((&which, bytes)) = data.split_first() else {
        return;
    };
    if which % 2 == 0 {
        if let Ok(body) = decode_strict::<EventBody>(bytes, "fuzz") {
            assert_eq!(encode(&body).as_slice(), bytes);
            let client = body.clock.0.first().map_or([0; 16], |(c, _)| *c);
            let _ = body.validate(&client, body.clock.get(&client));
        }
    } else if let Ok(body) = decode_strict::<SnapshotBody>(bytes, "fuzz") {
        assert_eq!(encode(&body).as_slice(), bytes);
        let _ = body.validate();
    }
});
