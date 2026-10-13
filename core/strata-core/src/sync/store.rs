//! Where vault files live (spec §5): a directory the user syncs with some other
//! tool. Clients only create files, never modify them, so the interface has no
//! "write": `create` fails if the file already exists.
//!
//! This is the minimal interface vault creation and unlock need. The filesystem
//! implementation with crash-safe, no-overwrite renames comes with the sync engine
//! (implementation plan, Phase 5).

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::error::{CoreError, Result};

pub trait RemoteStore: Send + Sync {
    /// Every file in the vault, as `/`-separated paths relative to the vault root.
    /// Sorted.
    fn list(&self) -> Result<Vec<String>>;

    /// The files in one top-level directory (`epochs`, `slots`, ...), as `list` would
    /// name them. Sorted. Cheaper than `list` when only one kind of file matters.
    fn list_dir(&self, dir: &str) -> Result<Vec<String>> {
        let prefix = format!("{dir}/");
        Ok(self
            .list()?
            .into_iter()
            .filter(|p| p.starts_with(&prefix))
            .collect())
    }

    /// Reads `path`, refusing files larger than `max_len` without reading them in
    /// full: a planted multi-gigabyte file must not exhaust memory.
    fn read(&self, path: &str, max_len: usize) -> Result<Vec<u8>>;

    /// Creates `path` with `bytes`. Fails with `io::ErrorKind::AlreadyExists` if the
    /// path exists, and never overwrites.
    fn create(&self, path: &str, bytes: &[u8]) -> Result<()>;

    fn delete(&self, path: &str) -> Result<()>;
}

/// An in-memory vault directory. Tests use `put` and `remove` to act as an attacker
/// who controls the storage.
#[derive(Debug, Default)]
pub struct MemoryStore {
    files: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Writes `path` whether or not it exists, as an attacker could.
    pub fn put(&self, path: &str, bytes: Vec<u8>) {
        self.files.lock().unwrap().insert(path.to_string(), bytes);
    }

    pub fn get(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().unwrap().get(path).cloned()
    }

    pub fn remove(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().unwrap().remove(path)
    }

    /// Paths under `dir/`.
    pub fn paths_in(&self, dir: &str) -> Vec<String> {
        let prefix = format!("{dir}/");
        self.files
            .lock()
            .unwrap()
            .keys()
            .filter(|p| p.starts_with(&prefix))
            .cloned()
            .collect()
    }
}

impl RemoteStore for MemoryStore {
    fn list(&self) -> Result<Vec<String>> {
        Ok(self.files.lock().unwrap().keys().cloned().collect())
    }

    fn read(&self, path: &str, max_len: usize) -> Result<Vec<u8>> {
        let bytes = self.get(path).ok_or_else(|| {
            CoreError::from(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no such file",
            ))
        })?;
        if bytes.len() > max_len {
            return Err(CoreError::rejected("vault file", "file too large"));
        }
        Ok(bytes)
    }

    fn create(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let mut files = self.files.lock().unwrap();
        if files.contains_key(path) {
            return Err(
                std::io::Error::new(std::io::ErrorKind::AlreadyExists, "file exists").into(),
            );
        }
        files.insert(path.to_string(), bytes.to_vec());
        Ok(())
    }

    fn delete(&self, path: &str) -> Result<()> {
        self.remove(path)
            .map(|_| ())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such file").into())
    }
}
