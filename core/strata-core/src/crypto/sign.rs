//! Device signing keys (spec §6.4): Ed25519 over `"strata v1 signature" || bytes`,
//! verified strictly.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::SecretKey;
use crate::error::Result;

pub const SIGNATURE_PREFIX: &[u8] = b"strata v1 signature";
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// A device's signing key. `ed25519-dalek` zeroizes it on drop.
pub struct DeviceKey(SigningKey);

impl DeviceKey {
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(&SecretKey::generate()?))
    }

    /// Rebuilds the key from its 32-byte seed, as stored in local state (spec §11).
    pub fn from_seed(seed: &SecretKey) -> Self {
        Self(SigningKey::from_bytes(seed.expose()))
    }

    pub fn seed(&self) -> SecretKey {
        let mut seed = self.0.to_bytes();
        let key = SecretKey::from_slice(&seed).expect("seeds are 32 bytes");
        zeroize::Zeroize::zeroize(&mut seed);
        key
    }

    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.verifying_key().to_bytes()
    }

    /// Signs `signed_bytes`: every byte of the file before the signature.
    pub fn sign(&self, signed_bytes: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(&prefixed(signed_bytes)).to_bytes()
    }
}

/// Strict verification: rejects non-canonical encodings and small-order keys, so a
/// signature has exactly one valid form.
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    signed_bytes: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    key.verify_strict(&prefixed(signed_bytes), &Signature::from_bytes(signature))
        .is_ok()
}

fn prefixed(signed_bytes: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIGNATURE_PREFIX.len() + signed_bytes.len());
    msg.extend_from_slice(SIGNATURE_PREFIX);
    msg.extend_from_slice(signed_bytes);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip() {
        let key = DeviceKey::generate().unwrap();
        let sig = key.sign(b"file bytes");
        assert!(verify(&key.public_key(), b"file bytes", &sig));
        assert!(!verify(&key.public_key(), b"file bytez", &sig));
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!verify(&key.public_key(), b"file bytes", &bad));
        let other = DeviceKey::generate().unwrap();
        assert!(!verify(&other.public_key(), b"file bytes", &sig));
    }

    #[test]
    fn signature_covers_the_prefix() {
        let key = DeviceKey::from_seed(&SecretKey::from_slice(&[1; 32]).unwrap());
        // A plain Ed25519 signature over the same bytes, without our prefix, must not verify.
        let unprefixed = key.0.sign(b"file bytes").to_bytes();
        assert!(!verify(&key.public_key(), b"file bytes", &unprefixed));
    }

    #[test]
    fn seed_round_trip() {
        let key = DeviceKey::generate().unwrap();
        let again = DeviceKey::from_seed(&key.seed());
        assert_eq!(key.public_key(), again.public_key());
    }

    #[test]
    fn rejects_small_order_public_key() {
        // The identity point is small-order; strict verification must refuse it.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(!verify(&identity, b"x", &[0; 64]));
    }
}
