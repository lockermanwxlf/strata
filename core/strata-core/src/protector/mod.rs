//! Interface to platform keystores (Windows Hello, Secure Enclave, Android
//! StrongBox/TEE, TPM, Secret Service).
//!
//! Platform keystores never hand out keys; they perform wrap/unwrap with keys
//! that stay in hardware. A protector therefore only ever sees a per-slot
//! random *slot secret*. The core derives the slot KEK from that secret and
//! wraps the vault key itself, so the vault key never crosses the FFI boundary.
//!
//! Desktop implementations live in Rust behind `cfg(target_os)`; the Android
//! implementation is Kotlin (Keystore has no NDK API) and is passed in through
//! UniFFI's foreign-trait support. Implementations must stay thin: wrap,
//! unwrap, delete. No format logic or policy belongs in them.
//!
//! An implementation may keep one hardware key for the whole app and bind the slot
//! ID into each wrap (as associated data, or in a signed challenge). Then dropping a
//! slot leaves nothing behind in the keystore, and `delete` does nothing. When the
//! platform invalidates that key, every slot using it goes together.
//!
//! `protector_id`s (spec §11): 1 Android Keystore, 2 Windows Hello, 3 macOS Secure
//! Enclave, 4 Linux TPM 2.0, 5 Linux Secret Service.

use std::sync::Arc;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows_hello;

/// What a protector's backing store actually guarantees. The core uses this to
/// enforce slot policy (see `policy`), so implementations must report honestly:
/// e.g. Android must check `KeyInfo.securityLevel`, not assume StrongBox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct ProtectorCaps {
    /// Key material is non-exportable and held in a TPM / Secure Enclave / TEE / StrongBox.
    pub hardware_backed: bool,
    /// Hardware enforces attempt limits (TPM anti-hammering, StrongBox, Hello PIN lockout).
    pub rate_limited: bool,
    /// Each unwrap requires a biometric or device-credential prompt.
    pub user_presence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum ProtectorError {
    #[error("the user cancelled the prompt")]
    Cancelled,
    /// The platform key is gone or was invalidated (e.g. biometric enrollment
    /// changed). Callers treat this as "slot gone": fall back to the master
    /// password and offer to re-enroll. It is not a hard error.
    #[error("the platform key was invalidated")]
    KeyInvalidated,
    #[error("protector unavailable: {reason}")]
    Unavailable { reason: String },
    /// A PIN the protector checks itself (a TPM PIN) was wrong.
    #[error("wrong PIN")]
    WrongPin,
    #[error("platform error: {detail}")]
    /// Not `message`: that would clash with `Throwable.message` in the generated Kotlin.
    Platform { detail: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for ProtectorError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        ProtectorError::Platform { detail: e.reason }
    }
}

/// A platform keystore adapter. Methods that can show a biometric prompt are
/// async; UniFFI maps them to Kotlin `suspend` functions.
///
/// Implementations must zero `secret` and any returned plaintext buffers they
/// copy on their side as soon as they are done with them.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait PlatformProtector: Send + Sync {
    fn capabilities(&self) -> ProtectorCaps;

    /// Encrypt `secret` under the hardware-bound key for `slot_id`, creating
    /// that key if needed. Returns an opaque blob the core stores locally.
    async fn wrap(&self, slot_id: String, secret: Vec<u8>) -> Result<Vec<u8>, ProtectorError>;

    /// Reverse of `wrap`. May prompt the user.
    async fn unwrap(&self, slot_id: String, blob: Vec<u8>) -> Result<Vec<u8>, ProtectorError>;

    /// Destroy the hardware-bound key for `slot_id`.
    fn delete(&self, slot_id: String) -> Result<(), ProtectorError>;
}

/// Windows Hello (`protector_id` 2), if it's set up on this machine. `None` elsewhere.
#[uniffi::export]
pub fn windows_hello() -> Option<Arc<dyn PlatformProtector>> {
    #[cfg(windows)]
    {
        windows_hello::WindowsHello::new().map(|h| Arc::new(h) as Arc<dyn PlatformProtector>)
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Whether a TPM 2.0 is reachable here (Linux), for offering TPM unlock.
#[uniffi::export]
pub fn linux_tpm_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::Tpm::available()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// The TPM with `pin` (`protector_id` 4), for one enable or unlock. A wrong PIN fails
/// with `WrongPin`, and the TPM's lockout limits retries. `None` without a TPM.
#[uniffi::export]
pub fn linux_tpm(pin: Vec<u8>) -> Option<Arc<dyn PlatformProtector>> {
    let pin = zeroize::Zeroizing::new(pin);
    #[cfg(target_os = "linux")]
    {
        linux::Tpm::with_pin(&pin).map(|t| Arc::new(t) as Arc<dyn PlatformProtector>)
    }
    #[cfg(not(target_os = "linux"))]
    {
        drop(pin);
        None
    }
}

/// The desktop keyring through Secret Service (`protector_id` 5), if a daemon answers.
#[uniffi::export]
pub fn linux_secret_service() -> Option<Arc<dyn PlatformProtector>> {
    #[cfg(target_os = "linux")]
    {
        linux::SecretService::new().map(|s| Arc::new(s) as Arc<dyn PlatformProtector>)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The Secure Enclave (`protector_id` 3) on macOS. Its keys stay out of the keychain,
/// so it needs no entitlement: any signed build can use it, ad-hoc included.
#[uniffi::export]
pub fn secure_enclave() -> Option<Arc<dyn PlatformProtector>> {
    #[cfg(target_os = "macos")]
    {
        Some(Arc::new(macos::SecureEnclave) as Arc<dyn PlatformProtector>)
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}
