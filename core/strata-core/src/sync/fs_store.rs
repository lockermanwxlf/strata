//! A vault in a local folder, typically one another tool syncs (spec §5).
//!
//! Files are published without ever overwriting. The bytes go to a temporary file
//! (a name starting with `.`, which readers ignore), which is synced and then
//! hard-linked to its final name. Creating a hard link fails if the name exists, on
//! every platform, so a file appears whole or not at all and nothing is replaced.
//! Filesystems without hard links (FAT, exFAT, some network shares) fall back to
//! `create_new`, which is still exclusive but lets a reader see a partly written
//! file. Readers reject those as malformed and pick them up complete on the next sync.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use super::RemoteStore;
use crate::crypto::fill_random;
use crate::error::{CoreError, Result};

/// The directories that hold vault files (spec §5). Nothing else is listed.
const DIRS: [&str; 4] = ["epochs", "slots", "events", "snapshots"];

#[derive(Debug, Clone)]
pub struct FsStore {
    root: PathBuf,
}

impl FsStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The real path of a vault-relative path. Only plain names and the known
    /// directories are accepted, so a path can never point outside the vault.
    fn resolve(&self, path: &str) -> Result<PathBuf> {
        let invalid = || CoreError::rejected("vault path", "not a vault file path");
        let mut parts = path.split('/');
        let (dir, name) = match (parts.next(), parts.next(), parts.next()) {
            (Some(name), None, None) => (None, name),
            (Some(dir), Some(name), None) if DIRS.contains(&dir) => (Some(dir), name),
            _ => return Err(invalid()),
        };
        let safe =
            !name.is_empty() && name != "." && name != ".." && !name.contains(['\\', ':', '\0']);
        if !safe {
            return Err(invalid());
        }
        Ok(match dir {
            Some(dir) => self.root.join(dir).join(name),
            None => self.root.join(name),
        })
    }
}

impl RemoteStore for FsStore {
    fn list(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let visible = |name: &str| !name.starts_with('.');
        for entry in read_dir_if_exists(&self.root)? {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && let Some(name) = entry.file_name().to_str()
                && visible(name)
            {
                out.push(name.to_string());
            }
        }
        for dir in DIRS {
            out.extend(self.list_dir(dir)?);
        }
        out.sort();
        Ok(out)
    }

    fn list_dir(&self, dir: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for entry in read_dir_if_exists(&self.root.join(dir))? {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && let Some(name) = entry.file_name().to_str()
                && !name.starts_with('.')
            {
                out.push(format!("{dir}/{name}"));
            }
        }
        out.sort();
        Ok(out)
    }

    fn read(&self, path: &str, max_len: usize) -> Result<Vec<u8>> {
        let file = File::open(self.resolve(path)?)?;
        if file.metadata()?.len() > max_len as u64 {
            return Err(CoreError::rejected("vault file", "file too large"));
        }
        // The file may grow between the length check and the read; never read more.
        let mut bytes = Vec::new();
        file.take(max_len as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > max_len {
            return Err(CoreError::rejected("vault file", "file too large"));
        }
        Ok(bytes)
    }

    fn create(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let target = self.resolve(path)?;
        let dir = target.parent().expect("resolved paths have a parent");
        fs::create_dir_all(dir)?;

        let mut suffix = [0u8; 8];
        fill_random(&mut suffix)?;
        let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = dir.join(format!(".strata-{suffix}.tmp"));
        write_synced(&tmp, bytes)?;

        let linked = fs::hard_link(&tmp, &target);
        let _ = fs::remove_file(&tmp);
        match linked {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => return Err(e.into()),
            // No hard links here: still exclusive, just not atomic.
            Err(_) => {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)?;
                file.write_all(bytes)?;
                file.sync_all()?;
            }
        }
        sync_dir(dir)?;
        Ok(())
    }

    fn delete(&self, path: &str) -> Result<()> {
        let target = self.resolve(path)?;
        fs::remove_file(&target)?;
        sync_dir(target.parent().expect("resolved paths have a parent"))?;
        Ok(())
    }
}

fn read_dir_if_exists(dir: &Path) -> Result<Vec<std::io::Result<fs::DirEntry>>> {
    match fs::read_dir(dir) {
        Ok(entries) => Ok(entries.collect()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Makes a new or removed name durable (Unix; Windows needs nothing extra).
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_never_overwrites_and_list_skips_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsStore::new(dir.path());
        store.create("strata-vault", b"v").unwrap();
        store.create("events/a.evt", b"first").unwrap();
        let again = store.create("events/a.evt", b"second").unwrap_err();
        assert!(matches!(again, CoreError::Io(e) if e.kind() == ErrorKind::AlreadyExists));
        assert_eq!(store.read("events/a.evt", 100).unwrap(), b"first");

        std::fs::write(dir.path().join("events/.partial.tmp"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("events/sub")).unwrap();
        std::fs::write(dir.path().join("other.txt"), b"x").unwrap();
        assert_eq!(
            store.list().unwrap(),
            vec!["events/a.evt", "other.txt", "strata-vault"]
        );

        store.delete("events/a.evt").unwrap();
        assert!(store.read("events/a.evt", 100).is_err());
    }

    #[test]
    fn reads_are_capped_and_paths_stay_inside() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsStore::new(dir.path());
        store.create("slots/s.slot", &[0; 100]).unwrap();
        assert!(store.read("slots/s.slot", 99).is_err());
        assert_eq!(store.read("slots/s.slot", 100).unwrap().len(), 100);
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
        }
    }
}
