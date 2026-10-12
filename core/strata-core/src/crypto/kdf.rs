//! Key derivation (spec §6.1, §6.2): HKDF-SHA256 subkeys, the slot KEK, and
//! Argon2id for password slots.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use unicode_normalization::{IsNormalized, UnicodeNormalization, is_nfc_quick};
use zeroize::Zeroizing;

use super::SecretKey;
use crate::error::{CoreError, Result};

/// HKDF `info` labels (spec §6.1, §6.2, §6.2.1). Never reuse one for a different purpose.
pub mod label {
    pub const KEY_ID: &[u8] = b"strata v1 key-id";
    pub const EVENT_KEY: &[u8] = b"strata v1 event-key";
    pub const SNAPSHOT_KEY: &[u8] = b"strata v1 snapshot-key";
    pub const EPOCH_CHAIN_KEY: &[u8] = b"strata v1 epoch-chain-key";
    pub const LOCAL_STATE_KEY: &[u8] = b"strata v1 local-state-key";
    pub const SLOT_KEK: &[u8] = b"strata v1 slot-kek";
    pub const RECOVERY_ANCHOR_KEY: &[u8] = b"strata v1 recovery-anchor-key";
}

/// `HKDF(salt, ikm, info, 32)`: Extract with `salt`, then Expand with `info` (spec §3).
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8]) -> SecretKey {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    SecretKey::from_fn(|okm| {
        hk.expand(info, okm)
            .expect("32 bytes is within HKDF-SHA256's output limit");
        Ok(())
    })
    .expect("filling a key from HKDF cannot fail")
}

/// Everything derived from one epoch key `EK_e` (spec §6.1).
pub struct EpochKeys {
    /// Key commitment. Public: stored in the epoch record and pinned locally.
    pub key_id: [u8; 32],
    pub event: SecretKey,
    pub snapshot: SecretKey,
    pub chain: SecretKey,
    pub local_state: SecretKey,
}

impl EpochKeys {
    pub fn derive(vault_id: &[u8; 16], ek: &SecretKey) -> Self {
        let ikm = ek.expose();
        Self {
            key_id: *hkdf(vault_id, ikm, label::KEY_ID).expose(),
            event: hkdf(vault_id, ikm, label::EVENT_KEY),
            snapshot: hkdf(vault_id, ikm, label::SNAPSHOT_KEY),
            chain: hkdf(vault_id, ikm, label::EPOCH_CHAIN_KEY),
            local_state: hkdf(vault_id, ikm, label::LOCAL_STATE_KEY),
        }
    }
}

/// `KEK = HKDF(vault_id || slot_id, S, "strata v1 slot-kek")` (spec §6.2).
pub fn slot_kek(vault_id: &[u8; 16], slot_id: &[u8; 16], slot_secret: &SecretKey) -> SecretKey {
    let mut salt = [0u8; 32];
    salt[..16].copy_from_slice(vault_id);
    salt[16..].copy_from_slice(slot_id);
    hkdf(&salt, slot_secret.expose(), label::SLOT_KEK)
}

/// Argon2id parameters for a password slot (spec §6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Argon2Params {
    /// RFC 9106 §4, second recommended option.
    pub const DEFAULT: Self = Self {
        m_kib: 65536,
        t: 3,
        p: 4,
    };
    pub const MIN_M_KIB: u32 = 65536;
    pub const MAX_M_KIB: u32 = 1_048_576;
    pub const MIN_T: u32 = 3;
    pub const MAX_T: u32 = 10;
    pub const MIN_P: u32 = 1;
    pub const MAX_P: u32 = 16;

    /// Readers reject parameters outside these bounds: the maximums stop a malicious
    /// slot from exhausting memory or CPU, the minimums enforce policy.
    pub fn validate(&self) -> Result<()> {
        let ok = (Self::MIN_M_KIB..=Self::MAX_M_KIB).contains(&self.m_kib)
            && (Self::MIN_T..=Self::MAX_T).contains(&self.t)
            && (Self::MIN_P..=Self::MAX_P).contains(&self.p);
        if ok {
            Ok(())
        } else {
            Err(CoreError::rejected(
                "password slot",
                "Argon2 parameters out of bounds",
            ))
        }
    }
}

/// The password slot's secret: `Argon2id(NFC(password), salt, m, t, p, 32)` (spec §6.2).
///
/// `password` is UTF-8. It is NFC-normalized here, in the core, so every platform
/// derives the same key however its keyboard composes characters. It isn't trimmed.
pub fn password_slot_secret(
    password: &[u8],
    salt: &[u8; 16],
    params: Argon2Params,
) -> Result<SecretKey> {
    params.validate()?;
    let text = std::str::from_utf8(password)
        .map_err(|_| CoreError::rejected("password", "not valid UTF-8"))?;

    // Most passwords (all ASCII ones, for a start) are already NFC, and the quick
    // check proves it without buffering. Only the rest go through the normalizer,
    // whose internal buffers we can't wipe.
    let normalized: Zeroizing<String>;
    let nfc_bytes = if is_nfc_quick(text.chars()) == IsNormalized::Yes {
        password
    } else {
        // NFC can expand a string up to 3x. Reserving that up front means the buffer
        // never reallocates, which would leave an unzeroized copy of the password behind.
        let mut buf = Zeroizing::new(String::with_capacity(text.len() * 3));
        buf.extend(text.nfc());
        normalized = buf;
        normalized.as_bytes()
    };

    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m_kib, params.t, params.p, Some(SecretKey::LEN))
            .map_err(|_| CoreError::rejected("password slot", "Argon2 parameters invalid"))?,
    );
    SecretKey::from_fn(|out| {
        argon
            .hash_password_into(nfc_bytes, salt, out)
            .map_err(|_| CoreError::rejected("password slot", "Argon2 failed"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subkeys_are_distinct_and_bound_to_vault() {
        let ek = SecretKey::from_slice(&[7; 32]).unwrap();
        let a = EpochKeys::derive(&[1; 16], &ek);
        let b = EpochKeys::derive(&[2; 16], &ek);
        assert_ne!(a.key_id, b.key_id);
        assert_ne!(a.event, b.event);
        let all = [
            &a.key_id,
            a.event.expose(),
            a.snapshot.expose(),
            a.chain.expose(),
            a.local_state.expose(),
        ];
        for i in 0..all.len() {
            for j in i + 1..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
    }

    #[test]
    fn slot_kek_binds_vault_and_slot() {
        let s = SecretKey::from_slice(&[9; 32]).unwrap();
        let base = slot_kek(&[1; 16], &[2; 16], &s);
        assert_ne!(base, slot_kek(&[3; 16], &[2; 16], &s));
        assert_ne!(base, slot_kek(&[1; 16], &[3; 16], &s));
    }

    #[test]
    fn argon2_bounds() {
        assert!(Argon2Params::DEFAULT.validate().is_ok());
        let bad = [
            Argon2Params {
                m_kib: 65535,
                ..Argon2Params::DEFAULT
            },
            Argon2Params {
                m_kib: 1_048_577,
                ..Argon2Params::DEFAULT
            },
            Argon2Params {
                t: 2,
                ..Argon2Params::DEFAULT
            },
            Argon2Params {
                t: 11,
                ..Argon2Params::DEFAULT
            },
            Argon2Params {
                p: 0,
                ..Argon2Params::DEFAULT
            },
            Argon2Params {
                p: 17,
                ..Argon2Params::DEFAULT
            },
        ];
        for params in bad {
            assert!(params.validate().is_err(), "{params:?}");
            assert!(password_slot_secret(b"x", &[0; 16], params).is_err());
        }
    }

    #[test]
    fn password_is_nfc_normalized_and_must_be_utf8() {
        let salt = [5; 16];
        let composed = password_slot_secret("caf\u{e9}".as_bytes(), &salt, Argon2Params::DEFAULT);
        let decomposed =
            password_slot_secret("cafe\u{301}".as_bytes(), &salt, Argon2Params::DEFAULT);
        assert_eq!(composed.unwrap(), decomposed.unwrap());
        assert!(password_slot_secret(&[0xff, 0xfe], &salt, Argon2Params::DEFAULT).is_err());
    }
}
