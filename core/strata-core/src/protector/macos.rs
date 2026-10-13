//! macOS Secure Enclave as a platform protector (CLAUDE.md "Platform protectors").
//!
//! One P-256 key for the app lives in the Secure Enclave and never leaves it. Slot
//! secrets are encrypted to its public key with ECIES (X9.63 KDF, AES-GCM), which
//! needs no prompt; decrypting needs the user (Touch ID or the login password). ECIES
//! here takes no associated data, so the slot ID is prefixed to the plaintext and
//! checked on the way out; AES-GCM authenticates it with the rest.
//!
//! Secure Enclave keys live in the data protection keychain, which only a signed app
//! with a keychain access group entitlement may use. Unsigned builds fail to create
//! the key and report the protector unavailable. Not yet run on a Mac (implementation
//! plan, Phase 10): it compiles in CI and against the macOS target.

use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlPrivateKeyUsage, kSecAccessControlUserPresence,
};
use zeroize::Zeroizing;

use super::{PlatformProtector, ProtectorCaps, ProtectorError};

const LABEL: &str = "dev.lockermanwxlf.strata.device-unlock";
const ALGORITHM: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;
/// `errSecUserCanceled`.
const USER_CANCELED: isize = -128;

pub struct SecureEnclave;

impl SecureEnclave {
    fn find() -> Option<SecKey> {
        let results = ItemSearchOptions::new()
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(LABEL)
            .ignore_legacy_keychains()
            .load_refs(true)
            .search()
            .ok()?;
        results.into_iter().find_map(|r| match r {
            SearchResult::Ref(Reference::Key(key)) => Some(key),
            _ => None,
        })
    }

    fn create() -> Result<SecKey, ProtectorError> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence,
        )
        .map_err(|e| unavailable(e.to_string()))?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_label(LABEL)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_access_control(access);
        SecKey::new(&options).map_err(|e| unavailable(e.to_string()))
    }
}

#[async_trait::async_trait]
impl PlatformProtector for SecureEnclave {
    fn capabilities(&self) -> ProtectorCaps {
        // The Secure Enclave rate-limits Touch ID and the login password itself.
        ProtectorCaps {
            hardware_backed: true,
            rate_limited: true,
            user_presence: true,
        }
    }

    async fn wrap(&self, slot_id: String, secret: Vec<u8>) -> Result<Vec<u8>, ProtectorError> {
        let secret = Zeroizing::new(secret);
        let key = match Self::find() {
            Some(key) => key,
            None => Self::create()?,
        };
        let public = key
            .public_key()
            .ok_or_else(|| unavailable("no public key".into()))?;
        let plaintext = Zeroizing::new([slot_id.as_bytes(), &secret].concat());
        public
            .encrypt_data(ALGORITHM, &plaintext)
            .map_err(|e| ProtectorError::Platform {
                detail: e.to_string(),
            })
    }

    async fn unwrap(&self, slot_id: String, blob: Vec<u8>) -> Result<Vec<u8>, ProtectorError> {
        let key = Self::find().ok_or(ProtectorError::KeyInvalidated)?;
        let plaintext = Zeroizing::new(key.decrypt_data(ALGORITHM, &blob).map_err(|e| {
            if e.code() == USER_CANCELED {
                ProtectorError::Cancelled
            } else {
                ProtectorError::Platform {
                    detail: e.to_string(),
                }
            }
        })?);
        plaintext
            .strip_prefix(slot_id.as_bytes())
            .map(<[u8]>::to_vec)
            .ok_or(ProtectorError::KeyInvalidated)
    }

    /// The key is shared by every slot, so removing one slot leaves it.
    fn delete(&self, _slot_id: String) -> Result<(), ProtectorError> {
        Ok(())
    }
}

fn unavailable(reason: String) -> ProtectorError {
    ProtectorError::Unavailable { reason }
}
