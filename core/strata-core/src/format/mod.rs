//! File formats (spec §5, §6.2, §7.1, §8.1–8.2, §10.1): parsing and writing every
//! file in a vault directory, and checking that file names match their contents.
//!
//! Parsers are strict. Every length is checked before anything is allocated, and
//! anything the spec doesn't allow is `Rejected`. A newer `format_version` is
//! `UpdateRequired` instead, which is not an alarm (spec §12).

#![forbid(unsafe_code)]

pub mod body;
pub mod epoch;
pub mod event;
pub mod names;
pub mod slot;
pub mod snapshot;
pub mod vault_info;

use crate::crypto::aead::{self, NONCE_LEN};
use crate::crypto::sign::{DeviceKey, SIGNATURE_LEN};
use crate::crypto::{SecretBytes, SecretKey};
use crate::encoding::{Reader, padding};
use crate::error::{CoreError, Result};

/// The only version this build reads and writes.
pub const FORMAT_VERSION: u16 = 1;

/// A 16-byte random identifier: vault, client, slot, entry or snapshot.
pub type Id = [u8; 16];

/// Reads `magic || LE16 version || LE16 flags`, the first 8 bytes of every file.
fn read_preamble(r: &mut Reader<'_>, magic: &[u8; 4], what: &'static str) -> Result<()> {
    r.magic(magic)?;
    let version = r.u16_le()?;
    if version > FORMAT_VERSION {
        return Err(CoreError::UpdateRequired { found: version });
    }
    if version != FORMAT_VERSION {
        return Err(CoreError::rejected(what, "unsupported format version"));
    }
    if r.u16_le()? != 0 {
        return Err(CoreError::rejected(what, "nonzero flags"));
    }
    Ok(())
}

fn write_preamble(out: &mut Vec<u8>, magic: &[u8; 4]) {
    out.extend_from_slice(magic);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
}

/// Splits off the trailing device signature (spec §2, signature rule).
/// Returns `(signed_bytes, signature)`.
fn split_signature<'a>(
    bytes: &'a [u8],
    what: &'static str,
) -> Result<(&'a [u8], [u8; SIGNATURE_LEN])> {
    let (signed, signature) = bytes
        .split_last_chunk::<SIGNATURE_LEN>()
        .ok_or(CoreError::rejected(what, "truncated"))?;
    Ok((signed, *signature))
}

fn check_vault_id(found: &Id, expected: &Id, what: &'static str) -> Result<()> {
    if found != expected {
        return Err(CoreError::rejected(what, "belongs to a different vault"));
    }
    Ok(())
}

/// Appends `Seal(key, nonce, padded(body), aad = everything so far)` and then the
/// device signature over everything (spec §8.1, §10.1). `out` holds the header.
fn seal_body_and_sign(
    mut out: Vec<u8>,
    nonce_offset: usize,
    body: &[u8],
    key: &SecretKey,
    device: &DeviceKey,
) -> Result<Vec<u8>> {
    let nonce: [u8; NONCE_LEN] = out[nonce_offset..nonce_offset + NONCE_LEN]
        .try_into()
        .expect("caller wrote the nonce");
    let padded = padding::pad(body)?;
    let ct = aead::seal(key, &nonce, &padded, &out);
    out.reserve_exact(ct.len() + SIGNATURE_LEN);
    out.extend_from_slice(&ct);
    let signature = device.sign(&out);
    out.extend_from_slice(&signature);
    Ok(out)
}

/// Decrypts and unpads a body. Returns the padded plaintext (zeroized on drop) and
/// the body's range inside it.
fn open_body(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
    what: &'static str,
) -> Result<(SecretBytes, std::ops::Range<usize>)> {
    let plaintext = aead::open(key, nonce, ciphertext, aad, what)?;
    let body_len = padding::unpad(plaintext.expose())?.len();
    Ok((plaintext, 4..4 + body_len))
}

fn check_max_len(bytes: &[u8], max: usize, what: &'static str) -> Result<()> {
    if bytes.len() > max {
        return Err(CoreError::rejected(what, "file too large"));
    }
    Ok(())
}
