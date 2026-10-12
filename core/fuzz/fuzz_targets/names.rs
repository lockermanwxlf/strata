//! File-name parsing (spec §5) on arbitrary strings: never panics, and every name
//! it accepts is canonical (formatting it again gives back the same path).

#![no_main]

use libfuzzer_sys::fuzz_target;
use strata_core::format::names::FileName;

fuzz_target!(|data: &[u8]| {
    let Ok(path) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(name) = FileName::parse(path) {
        assert_eq!(name.to_path(), path);
    }
});
