//! Sync engine (spec §9.1, §9.4): the remote store, validating and applying
//! events, causal delivery, and rollback, fork and forgery detection.

#![forbid(unsafe_code)]

pub mod fs_store;
pub mod session;
pub mod store;

pub use fs_store::FsStore;
pub use session::{Session, SyncReport};
pub use store::{MemoryStore, RemoteStore};
