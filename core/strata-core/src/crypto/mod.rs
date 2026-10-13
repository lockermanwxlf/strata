//! Cryptographic building blocks (spec §3, §6.1, §6.2.1, §6.4).
//!
//! Only the primitives listed in spec §3, used only in the ways the spec
//! describes. Nothing here does I/O.

#![forbid(unsafe_code)]

pub mod aead;
pub mod generate;
pub mod kdf;
pub mod recovery;
pub mod secret;
pub mod sign;

pub use secret::{SecretBytes, SecretKey};

use crate::error::{CoreError, Result};

/// Fills `buf` from the OS CSPRNG (spec §2: there are no user-space RNGs).
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| CoreError::Rng)
}

/// A fresh random 16-byte identifier (vault, client, slot, entry or snapshot ID).
pub fn random_id() -> Result<[u8; 16]> {
    let mut id = [0u8; 16];
    fill_random(&mut id)?;
    Ok(id)
}
