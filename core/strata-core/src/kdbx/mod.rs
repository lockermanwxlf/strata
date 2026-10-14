//! KDBX (KeePass) import and export (spec §8.2.1), on top of the `keepass` crate.
//!
//! Import turns a KeePass file into ordinary edits, in batches that fit the event
//! limits; export builds a KeePass file from the merged view. What KeePass has and
//! Strata doesn't travels in `kdbx:` fields, so a round trip keeps it. The crate's
//! own crypto is KDBX's (AES, ChaCha20, Argon2 for the file key) and touches only
//! the KeePass file, never the vault.

mod export;
mod extras;
pub mod header;
mod import;

pub use export::{ExportReport, export};
pub use extras::{AutoType, Extras};
pub use import::{ImportReport, Imported, import, open_file};

/// Fields that carry KeePass data (spec §8.2.1).
pub const GROUP_FIELD: &str = "kdbx:group";
pub const EXTRAS_FIELD: &str = "kdbx:entry";
pub const ATTACHMENT_PREFIX: &str = "kdbx:attachment:";
pub const FIELD_PREFIX: &str = "kdbx:field:";
pub const PREFIX: &str = "kdbx:";

/// KeePass's names for the fields Strata knows, and Strata's.
const STANDARD_FIELDS: [(&str, &str); 6] = [
    ("Title", "title"),
    ("UserName", "username"),
    ("Password", "password"),
    ("URL", "url"),
    ("Notes", "notes"),
    ("otp", "otp"),
];

#[derive(Debug, thiserror::Error)]
pub enum KdbxError {
    #[error("the password or key file doesn't open this KeePass file")]
    WrongKey,
    #[error("can't read this KeePass file: {0}")]
    Unreadable(String),
    #[error("can't write the KeePass file: {0}")]
    Write(String),
    #[error(transparent)]
    Core(#[from] crate::error::CoreError),
}

#[cfg(test)]
mod tests;
