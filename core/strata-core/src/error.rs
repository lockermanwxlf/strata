//! Errors for the whole core.
//!
//! Messages are built only from static strings and non-secret values, so an
//! error can never carry key material or vault contents into logs or the UI.

#![forbid(unsafe_code)]

use crate::policy::PolicyError;

pub type Result<T, E = CoreError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Malformed, unauthenticated or out-of-bounds input (spec §2 "Reject").
    /// `what` names the structure, `why` the failed check.
    #[error("rejected {what}: {why}")]
    Rejected {
        what: &'static str,
        why: &'static str,
    },

    /// Evidence of tampering or a misbehaving device (spec §9.4). The vault stops
    /// writing to the remote until the user decides what to do.
    #[error("security alarm: {0}")]
    Alarm(AlarmKind),

    /// The vault was written with a newer format version (spec §12). Not an alarm.
    #[error("this vault needs a newer version of Strata (format {found})")]
    UpdateRequired { found: u16 },

    #[error("the vault is locked")]
    Locked,

    /// Another device rotated the vault key and this device doesn't hold the new
    /// one yet. Unlocking again with the password or recovery key catches it up.
    #[error("the vault's key was changed on another device; unlock again to keep editing")]
    KeyRotated,

    /// No slot opened with the password or recovery key given.
    #[error("that password or recovery key doesn't unlock this vault")]
    WrongCredential,

    /// The recovery words couldn't be read. Says which way, so the UI can help.
    #[error(transparent)]
    RecoveryWords(#[from] crate::crypto::recovery::WordsError),

    #[error(transparent)]
    Policy(#[from] PolicyError),

    /// The OS random number generator failed. Nothing secret is generated without it.
    #[error("the system random number generator is unavailable")]
    Rng,

    #[error("storage error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AlarmKind {
    #[error("rollback: files the vault already had have disappeared or gone back in time")]
    Rollback,
    #[error("fork: two different versions of the same history exist")]
    Fork,
    #[error("slot substitution: a slot unlocks a different key than this vault's")]
    SlotSubstitution,
    #[error("forgery: a file carries an invalid device signature")]
    Forgery,
}

impl CoreError {
    pub(crate) const fn rejected(what: &'static str, why: &'static str) -> Self {
        CoreError::Rejected { what, why }
    }
}
