//! XChaCha20-Poly1305 with explicit associated data (spec §3).
//!
//! Every caller passes the AAD the spec defines for its file type; there is no
//! default. Nonces are 24 random bytes, so random nonces never need coordinating.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use super::{SecretBytes, SecretKey, fill_random};
use crate::error::{CoreError, Result};

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

pub fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    Ok(nonce)
}

/// Returns `ciphertext || tag`.
pub fn seal(key: &SecretKey, nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    cipher(key)
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption only fails for messages over 256 GiB")
}

/// Opens `ciphertext || tag`. Any failure, whether a wrong key, tampering, or the
/// wrong AAD, is the same `Rejected` error: callers can't distinguish them.
pub fn open(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
    what: &'static str,
) -> Result<SecretBytes> {
    cipher(key)
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(SecretBytes::new)
        .map_err(|_| CoreError::rejected(what, "authentication failed"))
}

fn cipher(key: &SecretKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.expose().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }

    #[test]
    fn round_trip() {
        let nonce = random_nonce().unwrap();
        let ct = seal(&key(1), &nonce, b"secret", b"aad");
        assert_eq!(ct.len(), 6 + TAG_LEN);
        let pt = open(&key(1), &nonce, &ct, b"aad", "test").unwrap();
        assert_eq!(pt.expose(), b"secret");
    }

    #[test]
    fn rejects_wrong_key_nonce_aad_or_tampering() {
        let nonce = [3; NONCE_LEN];
        let ct = seal(&key(1), &nonce, b"secret", b"aad");
        assert!(open(&key(2), &nonce, &ct, b"aad", "t").is_err());
        assert!(open(&key(1), &[4; NONCE_LEN], &ct, b"aad", "t").is_err());
        assert!(open(&key(1), &nonce, &ct, b"aae", "t").is_err());
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 1;
            assert!(
                open(&key(1), &nonce, &bad, b"aad", "t").is_err(),
                "byte {i}"
            );
        }
        assert!(open(&key(1), &nonce, &ct[..ct.len() - 1], b"aad", "t").is_err());
    }
}
