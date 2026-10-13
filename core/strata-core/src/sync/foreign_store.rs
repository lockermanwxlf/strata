//! A vault folder the app reaches through a platform API instead of the filesystem:
//! on Android a folder picked through the Storage Access Framework is a content URI,
//! not a path (implementation plan, Phase 11). The platform implements
//! `ForeignFolder`, a UniFFI foreign trait, and `ForeignStore` adapts it to
//! `RemoteStore`.
//!
//! The adapter trusts the implementation with nothing it can check itself: it
//! validates every path before passing it on, hides temporary and malformed names,
//! drops duplicate names (some providers let two files share one), and enforces the
//! read limit again on what comes back. That keeps implementations thin.

use std::collections::BTreeSet;
use std::io::{self, ErrorKind};
use std::sync::Arc;

use super::RemoteStore;
use super::store::{DIRS, is_plain_name, split_path};
use crate::error::{CoreError, Result};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FolderError {
    #[error("file exists")]
    AlreadyExists,
    #[error("no such file")]
    NotFound,
    #[error("file too large")]
    TooLarge,
    /// Not `message`: that would clash with `Throwable.message` in the generated Kotlin.
    #[error("{detail}")]
    Failed { detail: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for FolderError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        FolderError::Failed { detail: e.reason }
    }
}

/// A vault folder, with paths relative to it: `strata-vault`, or `<dir>/<name>` with
/// `dir` one of `epochs`, `slots`, `events`, `snapshots`. The core checks every path
/// before calling. Files are never modified, only created and deleted (spec §5).
#[uniffi::export(with_foreign)]
pub trait ForeignFolder: Send + Sync {
    /// The names of the files (not folders) directly in `dir`: `""` for the vault
    /// root, otherwise one of the vault's directories. Empty if `dir` doesn't exist.
    fn list(&self, dir: String) -> Result<Vec<String>, FolderError>;

    /// The file's bytes, or `TooLarge` if it holds more than `max_len`. Never reads
    /// more than `max_len + 1` bytes.
    fn read(&self, path: String, max_len: u64) -> Result<Vec<u8>, FolderError>;

    /// Creates the file holding `bytes`, and its directory if needed. `AlreadyExists`
    /// if the name is taken: never overwrites, never picks another name, and never
    /// leaves a second file with the same name behind.
    fn create(&self, path: String, bytes: Vec<u8>) -> Result<(), FolderError>;

    fn delete(&self, path: String) -> Result<(), FolderError>;
}

pub struct ForeignStore {
    folder: Arc<dyn ForeignFolder>,
}

impl ForeignStore {
    pub fn new(folder: Arc<dyn ForeignFolder>) -> Self {
        Self { folder }
    }

    /// The visible, well-formed file names in `dir` as vault paths, sorted, once each.
    fn paths_in(&self, dir: &str) -> Result<Vec<String>> {
        let names: BTreeSet<String> = self
            .folder
            .list(dir.to_string())
            .map_err(io_error)?
            .into_iter()
            .filter(|name| is_plain_name(name) && !name.starts_with('.'))
            .collect();
        Ok(names
            .into_iter()
            .map(|name| match dir {
                "" => name,
                dir => format!("{dir}/{name}"),
            })
            .collect())
    }
}

impl RemoteStore for ForeignStore {
    fn list(&self) -> Result<Vec<String>> {
        let mut out = self.paths_in("")?;
        for dir in DIRS {
            out.extend(self.paths_in(dir)?);
        }
        out.sort();
        Ok(out)
    }

    fn list_dir(&self, dir: &str) -> Result<Vec<String>> {
        if !DIRS.contains(&dir) {
            return Err(CoreError::rejected("vault path", "not a vault directory"));
        }
        self.paths_in(dir)
    }

    fn read(&self, path: &str, max_len: usize) -> Result<Vec<u8>> {
        split_path(path)?;
        let too_large = || CoreError::rejected("vault file", "file too large");
        let bytes = match self.folder.read(path.to_string(), max_len as u64) {
            Ok(bytes) => bytes,
            Err(FolderError::TooLarge) => return Err(too_large()),
            Err(e) => return Err(io_error(e)),
        };
        if bytes.len() > max_len {
            return Err(too_large());
        }
        Ok(bytes)
    }

    fn create(&self, path: &str, bytes: &[u8]) -> Result<()> {
        split_path(path)?;
        self.folder
            .create(path.to_string(), bytes.to_vec())
            .map_err(io_error)
    }

    fn delete(&self, path: &str) -> Result<()> {
        split_path(path)?;
        self.folder.delete(path.to_string()).map_err(io_error)
    }
}

/// As the filesystem would report it, so callers can match on `ErrorKind`.
fn io_error(e: FolderError) -> CoreError {
    let kind = match e {
        FolderError::AlreadyExists => ErrorKind::AlreadyExists,
        FolderError::NotFound => ErrorKind::NotFound,
        FolderError::TooLarge | FolderError::Failed { .. } => ErrorKind::Other,
    };
    io::Error::new(kind, e.to_string()).into()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::sync::MemoryStore;

    /// A folder over a `MemoryStore` that records the paths it was asked for and can
    /// misbehave the way a careless implementation might.
    #[derive(Default)]
    struct Folder {
        files: MemoryStore,
        asked: Mutex<Vec<String>>,
        extra_names: Vec<String>,
        ignore_limit: bool,
    }

    impl ForeignFolder for Folder {
        fn list(&self, dir: String) -> Result<Vec<String>, FolderError> {
            self.asked.lock().unwrap().push(dir.clone());
            let prefix = if dir.is_empty() {
                String::new()
            } else {
                format!("{dir}/")
            };
            let mut names: Vec<String> = self
                .files
                .list()
                .unwrap()
                .into_iter()
                .filter_map(|p| p.strip_prefix(&prefix).map(str::to_string))
                .filter(|n| !n.contains('/'))
                .collect();
            names.extend(self.extra_names.iter().cloned());
            Ok(names)
        }

        fn read(&self, path: String, max_len: u64) -> Result<Vec<u8>, FolderError> {
            self.asked.lock().unwrap().push(path.clone());
            let bytes = self.files.get(&path).ok_or(FolderError::NotFound)?;
            if bytes.len() as u64 > max_len && !self.ignore_limit {
                return Err(FolderError::TooLarge);
            }
            Ok(bytes)
        }

        fn create(&self, path: String, bytes: Vec<u8>) -> Result<(), FolderError> {
            self.asked.lock().unwrap().push(path.clone());
            self.files.create(&path, &bytes).map_err(|e| match e {
                CoreError::Io(e) if e.kind() == ErrorKind::AlreadyExists => {
                    FolderError::AlreadyExists
                }
                e => FolderError::Failed {
                    detail: e.to_string(),
                },
            })
        }

        fn delete(&self, path: String) -> Result<(), FolderError> {
            self.asked.lock().unwrap().push(path.clone());
            self.files
                .remove(&path)
                .map(|_| ())
                .ok_or(FolderError::NotFound)
        }
    }

    fn store(folder: Folder) -> (Arc<Folder>, ForeignStore) {
        let folder = Arc::new(folder);
        (Arc::clone(&folder) as _, ForeignStore::new(folder))
    }

    fn kind(e: CoreError) -> ErrorKind {
        match e {
            CoreError::Io(e) => e.kind(),
            e => panic!("not an I/O error: {e}"),
        }
    }

    #[test]
    fn behaves_like_a_store() {
        let (_, store) = store(Folder::default());
        store.create("strata-vault", b"v").unwrap();
        store.create("events/a.evt", b"first").unwrap();
        store.create("slots/s.slot", b"slot").unwrap();
        assert_eq!(
            kind(store.create("events/a.evt", b"second").unwrap_err()),
            ErrorKind::AlreadyExists
        );
        assert_eq!(store.read("events/a.evt", 100).unwrap(), b"first");
        assert_eq!(
            store.list().unwrap(),
            vec!["events/a.evt", "slots/s.slot", "strata-vault"]
        );
        assert_eq!(store.list_dir("events").unwrap(), vec!["events/a.evt"]);
        store.delete("events/a.evt").unwrap();
        assert_eq!(
            kind(store.read("events/a.evt", 100).unwrap_err()),
            ErrorKind::NotFound
        );
        assert_eq!(
            kind(store.delete("events/a.evt").unwrap_err()),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn bad_paths_never_reach_the_folder() {
        let (folder, store) = store(Folder::default());
        for bad in [
            "../x",
            "events/../x",
            "events/a/b",
            "nowhere/x",
            "",
            "events/",
            "a\\b",
            "c:x",
        ] {
            assert!(store.create(bad, b"x").is_err(), "{bad}");
            assert!(store.read(bad, 10).is_err(), "{bad}");
            assert!(store.delete(bad).is_err(), "{bad}");
        }
        assert!(store.list_dir("..").is_err());
        assert!(folder.asked.lock().unwrap().is_empty());
    }

    #[test]
    fn hides_odd_names_and_duplicates() {
        let extra = [".strata-1.tmp", "a.evt", "x/y", "..", "c:d", ""];
        let (_, store) = store(Folder {
            extra_names: extra.iter().map(|s| s.to_string()).collect(),
            ..Folder::default()
        });
        store.create("events/a.evt", b"x").unwrap();
        assert_eq!(store.list_dir("events").unwrap(), vec!["events/a.evt"]);
        // Every directory (and the root) gets the same extra names.
        assert_eq!(
            store.list().unwrap(),
            vec![
                "a.evt",
                "epochs/a.evt",
                "events/a.evt",
                "slots/a.evt",
                "snapshots/a.evt"
            ]
        );
    }

    #[test]
    fn read_limit_holds_even_if_the_folder_ignores_it() {
        for ignore_limit in [false, true] {
            let (_, store) = store(Folder {
                ignore_limit,
                ..Folder::default()
            });
            store.create("slots/s.slot", &[0; 100]).unwrap();
            let err = store.read("slots/s.slot", 99).unwrap_err();
            assert!(matches!(err, CoreError::Rejected { .. }), "{err}");
            assert_eq!(store.read("slots/s.slot", 100).unwrap().len(), 100);
        }
    }
}
