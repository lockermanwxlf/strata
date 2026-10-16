//! macOS Secure Enclave as a platform protector (CLAUDE.md "Platform protectors").
//!
//! Each slot gets its own P-256 key in the Secure Enclave, made outside the keychain
//! the way CryptoKit's `SecureEnclave` keys are: the enclave hands back the private
//! key sealed under its own device key (the token object), and the slot's blob keeps
//! it. So there is no keychain item, which would need a keychain access group
//! entitlement and with it a provisioning profile from a paid Apple developer account.
//! Removing a slot leaves nothing behind, and the token object opens only in this
//! Mac's enclave.
//!
//! Slot secrets are encrypted to the key with ECIES (X9.63 KDF, AES-GCM), which needs no
//! prompt; decrypting needs the user (Touch ID or the login password). ECIES here takes
//! no associated data, so the slot ID is prefixed to the plaintext and checked on the way
//! out; AES-GCM authenticates it with the rest.
//!
//! Blob: `LE16 len || token object[len] || ECIES ciphertext`.

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::CFError;
use core_foundation::string::CFString;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlPrivateKeyUsage, kSecAccessControlUserPresence,
};
use security_framework_sys::item::{
    kSecAttrIsPermanent, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID,
    kSecAttrTokenIDSecureEnclave,
};
use security_framework_sys::key::SecKeyCreateRandomKey;
use zeroize::Zeroizing;

use super::{PlatformProtector, ProtectorCaps, ProtectorError};

const ALGORITHM: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;
/// `errSecUserCanceled`.
const USER_CANCELED: isize = -128;
/// `kSecAttrTokenOID`, which the SDK doesn't export: a token key's sealed private key.
/// Passing it back when creating a key loads that key instead of generating one.
const TOKEN_OBJECT: &str = "toid";

pub struct SecureEnclave;

impl SecureEnclave {
    /// A new enclave key, stored nowhere, and its token object.
    fn create() -> Result<(SecKey, Vec<u8>), ProtectorError> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence,
        )
        .map_err(|e| unavailable(e.to_string()))?;
        let mut options = GenerateKeyOptions::default();
        // No location: the key isn't permanent, so it never goes into a keychain.
        options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_access_control(access);
        let key = SecKey::new(&options).map_err(|e| unavailable(e.to_string()))?;
        let token_object = key
            .attributes()
            .find(CFString::from_static_string(TOKEN_OBJECT).as_CFTypeRef())
            .map(|v| unsafe { CFType::wrap_under_get_rule(*v) })
            .and_then(|v| v.downcast::<CFData>())
            .ok_or_else(|| unavailable("no token object".into()))?;
        Ok((key, token_object.bytes().to_vec()))
    }

    /// The key a token object stands for, or `None` if this Mac's enclave can't open it.
    fn load(token_object: &[u8]) -> Option<SecKey> {
        let attributes = unsafe {
            CFDictionary::from_CFType_pairs(&[
                (
                    CFString::wrap_under_get_rule(kSecAttrKeyType).as_CFType(),
                    CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrTokenID).as_CFType(),
                    CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrIsPermanent).as_CFType(),
                    CFBoolean::false_value().as_CFType(),
                ),
                (
                    CFString::from_static_string(TOKEN_OBJECT).as_CFType(),
                    CFData::from_buffer(token_object).as_CFType(),
                ),
            ])
        };
        let mut error = std::ptr::null_mut();
        let key = unsafe { SecKeyCreateRandomKey(attributes.as_concrete_TypeRef(), &mut error) };
        if key.is_null() {
            // Release the error; the caller only needs to know the key is gone.
            if !error.is_null() {
                drop(unsafe { CFError::wrap_under_create_rule(error) });
            }
            return None;
        }
        Some(unsafe { SecKey::wrap_under_create_rule(key) })
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
        let (key, token_object) = Self::create()?;
        let public = key
            .public_key()
            .ok_or_else(|| unavailable("no public key".into()))?;
        let plaintext = Zeroizing::new([slot_id.as_bytes(), &secret].concat());
        let ciphertext =
            public
                .encrypt_data(ALGORITHM, &plaintext)
                .map_err(|e| ProtectorError::Platform {
                    detail: e.to_string(),
                })?;
        let len = u16::try_from(token_object.len())
            .map_err(|_| unavailable("token object too large".into()))?;
        Ok([&len.to_le_bytes()[..], &token_object, &ciphertext].concat())
    }

    async fn unwrap(&self, slot_id: String, blob: Vec<u8>) -> Result<Vec<u8>, ProtectorError> {
        let (token_object, ciphertext) = split(&blob).ok_or(ProtectorError::KeyInvalidated)?;
        let key = Self::load(token_object).ok_or(ProtectorError::KeyInvalidated)?;
        let plaintext = Zeroizing::new(key.decrypt_data(ALGORITHM, ciphertext).map_err(|e| {
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

    /// The key lives only in the slot's blob, so removing the slot removes it.
    fn delete(&self, _slot_id: String) -> Result<(), ProtectorError> {
        Ok(())
    }
}

/// A blob's token object and ciphertext.
fn split(blob: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = blob.split_first_chunk::<2>()?;
    rest.split_at_checked(usize::from(u16::from_le_bytes(*len)))
}

fn unavailable(reason: String) -> ProtectorError {
    ProtectorError::Unavailable { reason }
}

#[cfg(test)]
mod tests {
    use super::split;

    #[test]
    fn blob_framing() {
        assert_eq!(split(&[2, 0, 7, 8, 9]), Some((&[7, 8][..], &[9][..])));
        assert_eq!(split(&[0, 0, 9]), Some((&[][..], &[9][..])));
        assert_eq!(split(&[3, 0, 7, 8]), None);
        assert_eq!(split(&[2]), None);
    }
}
