//! Strata's own KeePass parsing (spec §8.2.1): the header check that runs before
//! the `keepass` crate sees a file, and the `kdbx:entry` decoder. The first input
//! byte picks one. Must never panic; a `kdbx:entry` that decodes must survive a
//! round trip. (The `keepass` crate's own parser isn't fuzzed here: every run would
//! pay for a key derivation.)

#![no_main]

use libfuzzer_sys::fuzz_target;
use strata_core::kdbx::{Extras, header};

fuzz_target!(|data: &[u8]| {
    let Some((&which, bytes)) = data.split_first() else {
        return;
    };
    if which % 2 == 0 {
        let _ = header::check(bytes);
    } else if let Some(extras) = Extras::decode(bytes) {
        assert_eq!(Extras::decode(&extras.encode()), Some(extras));
    }
});
