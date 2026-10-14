//! This device's local state file (spec §11), as someone with access to the device
//! could rewrite it. The first input byte picks the sealed file, opened with a fixed
//! key, or the bare state record, as if just decrypted. Must never panic, and a
//! record that decodes must re-encode to the same bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use strata_core::crypto::SecretKey;
use strata_core::encoding::cbor::{decode_strict, encode};
use strata_core::local::{SealedLocalState, StateRecord};

fuzz_target!(|data: &[u8]| {
    let Some((&which, bytes)) = data.split_first() else {
        return;
    };
    if which % 2 == 0 {
        if let Ok(sealed) = SealedLocalState::parse(bytes) {
            let _ = sealed.open(&SecretKey::from_slice(&[0; 32]).unwrap());
        }
    } else if let Ok(record) = decode_strict::<StateRecord>(bytes, "fuzz") {
        assert_eq!(encode(&record).as_slice(), bytes);
    }
});
