//! Containers for secret material.
//!
//! - Contents are zeroized on drop.
//! - `Debug` never prints them.
//! - There is no `Clone`: copying a secret has to be explicit.
//! - Equality is constant-time.
//!
//! Keys live behind a `Box` so moving a `SecretKey` moves a pointer, not the key
//! bytes, which would otherwise leave stray copies on the stack.

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::fill_random;
use crate::error::{CoreError, Result};

/// A 256-bit symmetric key: an epoch key, a derived subkey, or a KEK.
pub struct SecretKey(Box<[u8; 32]>);

impl SecretKey {
    pub const LEN: usize = 32;

    /// A fresh random key from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut key = Self(Box::new([0u8; 32]));
        fill_random(key.0.as_mut_slice())?;
        Ok(key)
    }

    /// Copies a key out of `bytes`. The caller still owns `bytes` and must zeroize it.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::LEN {
            return Err(CoreError::rejected("key", "wrong length"));
        }
        let mut key = Self(Box::new([0u8; 32]));
        key.0.copy_from_slice(bytes);
        Ok(key)
    }

    /// Builds a key in place: `fill` writes the bytes straight into the key's
    /// own storage, e.g. as the output buffer of a KDF.
    pub fn from_fn(fill: impl FnOnce(&mut [u8; 32]) -> Result<()>) -> Result<Self> {
        let mut key = Self(Box::new([0u8; 32]));
        fill(&mut key.0)?;
        Ok(key)
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([redacted])")
    }
}

impl ConstantTimeEq for SecretKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.as_slice().ct_eq(other.0.as_slice())
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SecretKey {}

/// Variable-length secret bytes: passwords, field values, slot secrets from a protector.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// An explicit copy, also zeroized on drop. There's no `Clone`, so every copy
    /// of a secret is visible where it happens.
    pub fn duplicate(&self) -> Self {
        Self::from_slice(self.expose())
    }

    /// Takes ownership of `bytes`. Callers should build the `Vec` at its final size,
    /// because a reallocation would leave an unzeroized copy behind.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Copies `bytes` into an exactly sized buffer. The caller still owns `bytes`.
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut v = Vec::with_capacity(bytes.len());
        v.extend_from_slice(bytes);
        Self::new(v)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl ZeroizeOnDrop for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([redacted; {}])", self.0.len())
    }
}

impl ConstantTimeEq for SecretBytes {
    /// Constant-time in the contents. Lengths are not secret and may short-circuit.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.expose().ct_eq(other.expose())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SecretBytes {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_contents() {
        let key = SecretKey::from_slice(&[0xAB; 32]).unwrap();
        let bytes = SecretBytes::from_slice(b"hunter2");
        let printed = format!("{key:?} {bytes:?}");
        assert!(!printed.contains("ab") && !printed.contains("AB") && !printed.contains("171"));
        assert!(!printed.contains("hunter2"));
        assert_eq!(printed, "SecretKey([redacted]) SecretBytes([redacted; 7])");
    }

    #[test]
    fn generated_keys_differ() {
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::generate().unwrap();
        assert_ne!(a, b);
        assert_ne!(a.expose(), &[0u8; 32]);
    }

    #[test]
    fn from_slice_checks_length() {
        assert!(SecretKey::from_slice(&[0; 31]).is_err());
        assert!(SecretKey::from_slice(&[0; 33]).is_err());
        assert_eq!(
            SecretKey::from_slice(&[7; 32]).unwrap(),
            SecretKey::from_slice(&[7; 32]).unwrap()
        );
    }

    #[test]
    fn from_fn_writes_in_place() {
        let key = SecretKey::from_fn(|k| {
            k.fill(9);
            Ok(())
        })
        .unwrap();
        assert_eq!(key.expose(), &[9; 32]);
    }

    #[test]
    fn secret_bytes_equality() {
        assert_eq!(
            SecretBytes::from_slice(b"abc"),
            SecretBytes::from_slice(b"abc")
        );
        assert_ne!(
            SecretBytes::from_slice(b"abc"),
            SecretBytes::from_slice(b"abd")
        );
        assert_ne!(
            SecretBytes::from_slice(b"abc"),
            SecretBytes::from_slice(b"ab")
        );
    }
}
