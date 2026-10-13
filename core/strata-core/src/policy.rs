//! Slot policy: which protectors may be used where.
//!
//! Rule: weak protectors (PINs) are local-only, and even locally they need
//! hardware-enforced rate limiting, because a PIN-wrapped key in an ordinary
//! file falls to offline guessing the moment the device is stolen.
//!
//! Passwords are the user's choice and count as Strong whatever their
//! entropy. The UI warns about weak ones (docs/spec.md §6.2) but doesn't block
//! them.
//!
//! The UI may pre-filter options with this, but the core must also call it
//! when creating a slot, so an unsafe combination cannot be produced.

use crate::protector::ProtectorCaps;

/// Strength of the secret behind a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProtectorStrength {
    /// Password (any strength), recovery key, FIDO2 hmac-secret, hardware token.
    Strong,
    /// PIN.
    Weak,
}

/// Where a slot record lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SlotScope {
    /// Stored in the vault header and uploaded to the remote.
    Synced,
    /// Stored only on this device (keystore or local sidecar). Never uploaded.
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum PolicyError {
    #[error("weak protectors cannot be synced to the remote")]
    WeakProtectorCannotSync,
    #[error("weak protectors require a hardware-backed, rate-limited keystore on this device")]
    WeakProtectorNeedsHardwareRateLimit,
}

/// Check whether a slot with this strength and scope may be created.
/// `caps` describes the local protector backing a `Local` slot, if any.
#[uniffi::export]
pub fn check_slot_policy(
    strength: ProtectorStrength,
    scope: SlotScope,
    caps: Option<ProtectorCaps>,
) -> Result<(), PolicyError> {
    match (strength, scope) {
        (ProtectorStrength::Strong, _) => Ok(()),
        (ProtectorStrength::Weak, SlotScope::Synced) => Err(PolicyError::WeakProtectorCannotSync),
        (ProtectorStrength::Weak, SlotScope::Local) => match caps {
            Some(c) if c.hardware_backed && c.rate_limited => Ok(()),
            _ => Err(PolicyError::WeakProtectorNeedsHardwareRateLimit),
        },
    }
}

/// The strength of a platform protector's secret. One that prompts the user at
/// unlock may accept a PIN (Windows Hello, the Android device credential), so it
/// counts as Weak and needs hardware-backed rate limiting. One that unlocks with the
/// OS session instead (Secret Service) is as strong as the login password: Strong.
pub fn platform_strength(caps: &ProtectorCaps) -> ProtectorStrength {
    if caps.user_presence {
        ProtectorStrength::Weak
    } else {
        ProtectorStrength::Strong
    }
}

/// Whether a local slot may be created with this protector (spec §6.2 "Policy").
pub fn check_platform_policy(caps: &ProtectorCaps) -> Result<(), PolicyError> {
    check_slot_policy(platform_strength(caps), SlotScope::Local, Some(*caps))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HW: ProtectorCaps = ProtectorCaps {
        hardware_backed: true,
        rate_limited: true,
        user_presence: true,
    };
    const HW_NO_LIMIT: ProtectorCaps = ProtectorCaps {
        hardware_backed: true,
        rate_limited: false,
        user_presence: false,
    };
    const SOFTWARE: ProtectorCaps = ProtectorCaps {
        hardware_backed: false,
        rate_limited: false,
        user_presence: false,
    };

    #[test]
    fn strong_is_allowed_everywhere() {
        for scope in [SlotScope::Synced, SlotScope::Local] {
            for caps in [None, Some(SOFTWARE), Some(HW)] {
                assert_eq!(
                    check_slot_policy(ProtectorStrength::Strong, scope, caps),
                    Ok(())
                );
            }
        }
    }

    #[test]
    fn weak_never_syncs_even_with_hardware() {
        assert_eq!(
            check_slot_policy(ProtectorStrength::Weak, SlotScope::Synced, Some(HW)),
            Err(PolicyError::WeakProtectorCannotSync)
        );
    }

    #[test]
    fn weak_local_requires_hardware_rate_limiting() {
        assert_eq!(
            check_slot_policy(ProtectorStrength::Weak, SlotScope::Local, Some(HW)),
            Ok(())
        );
        for caps in [None, Some(SOFTWARE), Some(HW_NO_LIMIT)] {
            assert_eq!(
                check_slot_policy(ProtectorStrength::Weak, SlotScope::Local, caps),
                Err(PolicyError::WeakProtectorNeedsHardwareRateLimit)
            );
        }
    }
}
