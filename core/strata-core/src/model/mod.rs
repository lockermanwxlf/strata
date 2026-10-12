//! Data model (spec §8.2–8.3): hybrid logical clocks and vector-clock operations.
//! The op and body types themselves live in `format::body`, next to their encoding.

#![forbid(unsafe_code)]

pub mod clock;
pub mod hlc;
