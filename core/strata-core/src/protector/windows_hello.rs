//! Windows Hello as a platform protector (CLAUDE.md "Platform protectors").
//!
//! One Hello key credential for the app signs a fixed challenge per slot. Hello keys
//! are RSA with PKCS#1 v1.5 signatures, which are deterministic, so the same slot
//! always yields the same signature, and a hash of it is the key that wraps the
//! slot secret. Every unwrap needs the user's PIN or biometric. The private key stays
//! in the TPM when the machine has one.
//!
//! The calls block on WinRT operations; they run off the UI thread (the Kotlin side
//! calls the core on `Dispatchers.IO`).

use std::time::{Duration, Instant};

use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::System::TpmBaseServices::{
    TPM_DEVICE_INFO, TPM_VERSION_20, Tbsi_GetDeviceInfo,
};
use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow};
use windows::core::{HSTRING, w};
use zeroize::Zeroizing;

use super::{PlatformProtector, ProtectorCaps, ProtectorError};
use crate::crypto::aead::{self, NONCE_LEN};
use crate::crypto::kdf::hkdf;

/// The app's one Hello credential. Slots share it; each binds its own challenge.
const CREDENTIAL_NAME: &str = "Strata vault unlock";
const CHALLENGE_PREFIX: &[u8] = b"strata v1 windows-hello challenge ";
const KEK_LABEL: &[u8] = b"strata v1 windows-hello-kek";

pub struct WindowsHello;

impl WindowsHello {
    /// `None` when Windows Hello isn't set up on this machine.
    pub fn new() -> Option<Self> {
        let supported = KeyCredentialManager::IsSupportedAsync().ok()?.join().ok()?;
        supported.then_some(Self)
    }

    /// Opens the credential, creating it (with a prompt) if `create` and it's missing.
    fn credential(create: bool) -> Result<KeyCredential, ProtectorError> {
        let name = HSTRING::from(CREDENTIAL_NAME);
        let opened = KeyCredentialManager::OpenAsync(&name)
            .and_then(|op| op.join())
            .map_err(platform)?;
        let result = match opened.Status().map_err(platform)? {
            KeyCredentialStatus::NotFound if create => {
                let op = KeyCredentialManager::RequestCreateAsync(
                    &name,
                    KeyCredentialCreationOption::FailIfExists,
                )
                .map_err(platform)?;
                bring_prompt_forward();
                op.join().map_err(platform)?
            }
            _ => opened,
        };
        match result.Status().map_err(platform)? {
            KeyCredentialStatus::Success => result.Credential().map_err(platform),
            status => Err(from_status(status)),
        }
    }

    /// The key that wraps `slot_id`'s secret: a hash of the credential's signature
    /// over the slot's challenge. Prompts the user.
    fn kek(
        credential: &KeyCredential,
        slot_id: &str,
    ) -> Result<crate::crypto::SecretKey, ProtectorError> {
        let challenge = [CHALLENGE_PREFIX, slot_id.as_bytes()].concat();
        let buffer = CryptographicBuffer::CreateFromByteArray(&challenge).map_err(platform)?;
        let op = credential.RequestSignAsync(&buffer).map_err(platform)?;
        bring_prompt_forward();
        let signed = op.join().map_err(platform)?;
        match signed.Status().map_err(platform)? {
            KeyCredentialStatus::Success => {}
            status => return Err(from_status(status)),
        }
        let mut signature = windows::core::Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&signed.Result().map_err(platform)?, &mut signature)
            .map_err(platform)?;
        let signature = Zeroizing::new(signature.to_vec());
        Ok(hkdf(slot_id.as_bytes(), &signature, KEK_LABEL))
    }
}

#[async_trait::async_trait]
impl PlatformProtector for WindowsHello {
    fn capabilities(&self) -> ProtectorCaps {
        // Hello keeps the key in the TPM when there is one, and the TPM's
        // anti-hammering limits PIN guesses. Without one, it's software.
        let tpm = tpm2_present();
        ProtectorCaps {
            hardware_backed: tpm,
            rate_limited: tpm,
            user_presence: true,
        }
    }

    async fn wrap(&self, slot_id: String, secret: Vec<u8>) -> Result<Vec<u8>, ProtectorError> {
        let secret = Zeroizing::new(secret);
        let credential = Self::credential(true)?;
        let kek = Self::kek(&credential, &slot_id)?;
        let nonce = aead::random_nonce().map_err(|e| platform(e.to_string()))?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&aead::seal(&kek, &nonce, &secret, slot_id.as_bytes()));
        Ok(blob)
    }

    async fn unwrap(&self, slot_id: String, blob: Vec<u8>) -> Result<Vec<u8>, ProtectorError> {
        if blob.len() < NONCE_LEN {
            return Err(ProtectorError::KeyInvalidated);
        }
        // A missing credential, or one that signs differently (recreated since), means
        // the slot is gone; the user falls back to the password.
        let credential = match Self::credential(false) {
            Err(ProtectorError::Unavailable { .. }) => return Err(ProtectorError::KeyInvalidated),
            other => other?,
        };
        let kek = Self::kek(&credential, &slot_id)?;
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let opened = aead::open(
            &kek,
            nonce.try_into().unwrap(),
            ct,
            slot_id.as_bytes(),
            "hello blob",
        )
        .map_err(|_| ProtectorError::KeyInvalidated)?;
        Ok(opened.expose().to_vec())
    }

    /// The credential is shared by every slot and vault, so removing one slot leaves it.
    fn delete(&self, _slot_id: String) -> Result<(), ProtectorError> {
        Ok(())
    }
}

fn from_status(status: KeyCredentialStatus) -> ProtectorError {
    match status {
        KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => {
            ProtectorError::Cancelled
        }
        KeyCredentialStatus::NotFound => ProtectorError::Unavailable {
            reason: "no Windows Hello credential".into(),
        },
        KeyCredentialStatus::SecurityDeviceLocked => ProtectorError::Unavailable {
            reason: "Windows Hello is locked out after too many attempts".into(),
        },
        other => ProtectorError::Platform {
            detail: format!("Windows Hello status {}", other.0),
        },
    }
}

fn platform(e: impl ToString) -> ProtectorError {
    ProtectorError::Platform {
        detail: e.to_string(),
    }
}

fn tpm2_present() -> bool {
    let mut info = TPM_DEVICE_INFO::default();
    // SAFETY: `info` is a live, correctly sized TPM_DEVICE_INFO for the call to fill.
    let rc = unsafe {
        Tbsi_GetDeviceInfo(
            size_of::<TPM_DEVICE_INFO>() as u32,
            (&mut info as *mut TPM_DEVICE_INFO).cast(),
        )
    };
    rc == 0 && info.tpmVersion == TPM_VERSION_20
}

/// The Hello prompt for a desktop app opens without an owner window and often lands
/// behind the app. While it opens, find it and bring it to the front. Best effort:
/// if it can't be found in a few seconds, the user can still click it in the taskbar.
fn bring_prompt_forward() {
    std::thread::spawn(|| {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            // SAFETY: FindWindowW and SetForegroundWindow take only these values; a
            // stale window handle makes SetForegroundWindow fail, nothing worse.
            unsafe {
                if let Ok(hwnd) = FindWindowW(w!("Credential Dialog Xaml Host"), None) {
                    let _ = SetForegroundWindow(hwnd);
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
}
