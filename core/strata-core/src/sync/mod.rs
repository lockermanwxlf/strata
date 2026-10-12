//! Sync engine (spec §9.1, §9.4): the remote store, validating and applying
//! events, causal delivery, and rollback, fork and forgery detection.

#![forbid(unsafe_code)]

pub mod store;

pub use store::{MemoryStore, RemoteStore};
