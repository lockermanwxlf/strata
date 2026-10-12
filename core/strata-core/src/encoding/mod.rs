//! Byte-level encodings (spec §4): envelope reading, deterministic CBOR, padding.

#![forbid(unsafe_code)]

pub mod cbor;
pub mod padding;
pub mod reader;

pub use reader::Reader;
