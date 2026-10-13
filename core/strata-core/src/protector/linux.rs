//! Linux platform protectors (CLAUDE.md "Platform protectors").
//!
//! - **TPM 2.0 with a PIN** (`protector_id` 4): each slot secret is sealed into a TPM
//!   object whose authorization is the PIN. The TPM's dictionary-attack lockout limits
//!   guesses, so it counts as rate-limited.
//! - **Secret Service** (`protector_id` 5): GNOME Keyring or KWallet hold one app key,
//!   which wraps each slot secret. The login session unlocks it without a prompt, so
//!   it is neither hardware-backed nor rate-limited, and the policy allows it only as
//!   a strong (non-PIN) protector.

use std::str::FromStr;

use sha2::{Digest, Sha256};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    Auth, Digest as TpmDigest, EccPoint, KeyedHashScheme, Private, Public, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData,
    SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::{Context, Error as TpmError};
use zeroize::Zeroizing;

use super::{PlatformProtector, ProtectorCaps, ProtectorError};
use crate::crypto::SecretKey;
use crate::crypto::aead::{self, NONCE_LEN};

// ---- TPM 2.0 ------------------------------------------------------------------------

/// Overrides the TPM connection, e.g. `swtpm:port=2321` for a software TPM in tests.
/// A TPM reached this way isn't reported as hardware.
const TCTI_VARIABLE: &str = "STRATA_TPM_TCTI";
const TPM_DEVICE: &str = "/dev/tpmrm0";

pub struct Tpm {
    /// The PIN's hash, the sealed objects' authorization value.
    auth: Zeroizing<[u8; 32]>,
}

impl Tpm {
    /// Whether a TPM is reachable at all (no PIN needed to ask).
    pub fn available() -> bool {
        std::env::var_os(TCTI_VARIABLE).is_some() || std::path::Path::new(TPM_DEVICE).exists()
    }

    /// A protector for one operation with `pin`.
    pub fn with_pin(pin: &[u8]) -> Option<Self> {
        Self::available().then(|| Self {
            auth: Zeroizing::new(Sha256::digest(pin).into()),
        })
    }

    fn context() -> Result<Context, ProtectorError> {
        let tcti = match std::env::var(TCTI_VARIABLE) {
            Ok(conf) => TctiNameConf::from_str(&conf).map_err(tpm)?,
            Err(_) => TctiNameConf::Device(DeviceConfig::from_str(TPM_DEVICE).map_err(tpm)?),
        };
        Context::new(tcti).map_err(tpm)
    }

    /// The parent for sealed objects: an ECC P-256 storage key in the owner
    /// hierarchy. The template is fixed, so the TPM derives the same key every time
    /// and nothing has to be stored for it.
    fn storage_key(ctx: &mut Context) -> Result<tss_esapi::handles::KeyHandle, ProtectorError> {
        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .map_err(tpm)?;
        let template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attributes)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new_restricted_decryption_key(
                    SymmetricDefinitionObject::AES_128_CFB,
                    EccCurve::NistP256,
                )
                .build()
                .map_err(tpm)?,
            )
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(tpm)?;
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .map(|primary| primary.key_handle)
        .map_err(tpm)
    }

    /// A sealed data object: only unsealing with the PIN gets the data out. No `noDA`
    /// attribute, so wrong PINs count towards the TPM's lockout.
    fn sealed_template() -> Result<Public, ProtectorError> {
        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(true)
            .build()
            .map_err(tpm)?;
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(TpmDigest::default())
            .build()
            .map_err(tpm)
    }
}

#[async_trait::async_trait]
impl PlatformProtector for Tpm {
    fn capabilities(&self) -> ProtectorCaps {
        let hardware = std::env::var_os(TCTI_VARIABLE).is_none();
        ProtectorCaps {
            hardware_backed: hardware,
            rate_limited: hardware,
            user_presence: true,
        }
    }

    /// Blob: `LE16 len || public || private` of the sealed object. The slot ID needs
    /// no binding here: the object holds this slot's own secret.
    async fn wrap(&self, _slot_id: String, secret: Vec<u8>) -> Result<Vec<u8>, ProtectorError> {
        let secret = Zeroizing::new(secret);
        let mut ctx = Self::context()?;
        let parent = Self::storage_key(&mut ctx)?;
        let auth = Auth::try_from(self.auth.to_vec()).map_err(tpm)?;
        let data = SensitiveData::try_from(secret.to_vec()).map_err(tpm)?;
        let template = Self::sealed_template()?;
        let created = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create(parent, template, Some(auth), Some(data), None, None)
            })
            .map_err(tpm);
        let _ = ctx.flush_context(parent.into());
        let created = created?;
        let public = created.out_public.marshall().map_err(tpm)?;
        let mut blob = (public.len() as u16).to_le_bytes().to_vec();
        blob.extend_from_slice(&public);
        blob.extend_from_slice(created.out_private.value());
        Ok(blob)
    }

    async fn unwrap(&self, _slot_id: String, blob: Vec<u8>) -> Result<Vec<u8>, ProtectorError> {
        let (public, private) = split_blob(&blob).ok_or(ProtectorError::KeyInvalidated)?;
        let public = Public::unmarshall(public).map_err(|_| ProtectorError::KeyInvalidated)?;
        let private =
            Private::try_from(private.to_vec()).map_err(|_| ProtectorError::KeyInvalidated)?;
        let mut ctx = Self::context()?;
        let parent = Self::storage_key(&mut ctx)?;
        let unsealed = (|| {
            // A different TPM (or a cleared one) can't load it: the slot is gone.
            let object = ctx
                .execute_with_nullauth_session(|ctx| ctx.load(parent, private, public))
                .map_err(|_| ProtectorError::KeyInvalidated)?;
            ctx.tr_set_auth(
                object.into(),
                Auth::try_from(self.auth.to_vec()).map_err(tpm)?,
            )
            .map_err(tpm)?;
            let result = ctx.execute_with_session(
                Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
                |ctx| ctx.unseal(object.into()),
            );
            let _ = ctx.flush_context(object.into());
            result.map_err(unseal_error)
        })();
        let _ = ctx.flush_context(parent.into());
        Ok(unsealed?.value().to_vec())
    }

    /// Sealed objects live only in the blob; there's nothing in the TPM to remove.
    fn delete(&self, _slot_id: String) -> Result<(), ProtectorError> {
        Ok(())
    }
}

fn split_blob(blob: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u16::from_le_bytes(blob.get(..2)?.try_into().ok()?) as usize;
    let rest = blob.get(2..)?;
    (rest.len() > len).then(|| rest.split_at(len))
}

/// A wrong PIN and a locked-out TPM are what users meet; everything else is a fault.
fn unseal_error(e: TpmError) -> ProtectorError {
    use tss_esapi::constants::response_code::Tss2ResponseCodeKind as Kind;

    if let TpmError::Tss2Error(rc) = e {
        match rc.kind() {
            Some(Kind::AuthFail | Kind::BadAuth) => return ProtectorError::WrongPin,
            Some(Kind::Lockout) => {
                return ProtectorError::Unavailable {
                    reason: "the TPM is locked after too many wrong PINs; try again later".into(),
                };
            }
            _ => {}
        }
    }
    tpm(e)
}

fn tpm(e: impl ToString) -> ProtectorError {
    ProtectorError::Platform {
        detail: format!("TPM: {}", e.to_string()),
    }
}

// ---- Secret Service -----------------------------------------------------------------

const SERVICE: &str = "Strata";
const ACCOUNT: &str = "device unlock key";

pub struct SecretService;

impl SecretService {
    /// `None` when no Secret Service daemon answers (no desktop session).
    pub fn new() -> Option<Self> {
        let entry = keyring::Entry::new(SERVICE, ACCOUNT).ok()?;
        match entry.get_secret() {
            Ok(_) | Err(keyring::Error::NoEntry) => Some(Self),
            Err(_) => None,
        }
    }

    /// The app key in the keyring; created on first enrollment.
    fn app_key(create: bool) -> Result<SecretKey, ProtectorError> {
        let entry = keyring::Entry::new(SERVICE, ACCOUNT).map_err(keyring_error)?;
        match entry.get_secret() {
            Ok(bytes) => SecretKey::from_slice(&Zeroizing::new(bytes))
                .map_err(|_| ProtectorError::KeyInvalidated),
            Err(keyring::Error::NoEntry) if create => {
                let key = SecretKey::generate().map_err(|e| ProtectorError::Platform {
                    detail: e.to_string(),
                })?;
                entry.set_secret(key.expose()).map_err(keyring_error)?;
                Ok(key)
            }
            Err(keyring::Error::NoEntry) => Err(ProtectorError::KeyInvalidated),
            Err(e) => Err(keyring_error(e)),
        }
    }
}

#[async_trait::async_trait]
impl PlatformProtector for SecretService {
    fn capabilities(&self) -> ProtectorCaps {
        ProtectorCaps {
            hardware_backed: false,
            rate_limited: false,
            user_presence: false,
        }
    }

    async fn wrap(&self, slot_id: String, secret: Vec<u8>) -> Result<Vec<u8>, ProtectorError> {
        let secret = Zeroizing::new(secret);
        let key = Self::app_key(true)?;
        let nonce = aead::random_nonce().map_err(|e| ProtectorError::Platform {
            detail: e.to_string(),
        })?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&aead::seal(&key, &nonce, &secret, slot_id.as_bytes()));
        Ok(blob)
    }

    async fn unwrap(&self, slot_id: String, blob: Vec<u8>) -> Result<Vec<u8>, ProtectorError> {
        if blob.len() < NONCE_LEN {
            return Err(ProtectorError::KeyInvalidated);
        }
        let key = Self::app_key(false)?;
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let opened = aead::open(
            &key,
            nonce.try_into().unwrap(),
            ct,
            slot_id.as_bytes(),
            "keyring blob",
        )
        .map_err(|_| ProtectorError::KeyInvalidated)?;
        Ok(opened.expose().to_vec())
    }

    /// The app key is shared by every slot, so removing one slot leaves it.
    fn delete(&self, _slot_id: String) -> Result<(), ProtectorError> {
        Ok(())
    }
}

fn keyring_error(e: keyring::Error) -> ProtectorError {
    ProtectorError::Unavailable {
        reason: format!("Secret Service: {e}"),
    }
}

#[cfg(test)]
mod tests;
