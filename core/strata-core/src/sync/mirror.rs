//! This device's own copy of the vault folder (spec §9.5).
//!
//! The vault folder is the only place a vault's contents live: local state holds
//! keys and bookkeeping, not entries. If a sync tool wipes or rolls back the folder,
//! every device follows it. So each device keeps a copy of the vault files, in its
//! private state directory, and can put back what went missing.
//!
//! The files are encrypted and immutable, so the copy is cheap and never conflicts:
//! - Every file this device writes goes into the copy at once (`MirroredStore`).
//! - After every sync that found the folder healthy (no alarm), the copy is made to
//!   match the folder (`update`). Files the vault removed on purpose (covered events,
//!   replaced snapshots, slots of past epochs, a purge) then leave the copy too, so a
//!   restore can't undo a purge. Two kinds of file are kept even when the folder no
//!   longer has them, because their loss raises no alarm: `strata-vault`, and slots
//!   of the current epoch.
//! - After an alarm, the copy is left alone: it holds the last healthy state, and
//!   `restore` puts back every file the folder is missing. It never overwrites.

use std::io::ErrorKind;
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::{FsStore, RemoteStore};
use crate::error::{CoreError, Result};
use crate::format::names::FileName;
use crate::format::slot::SlotFile;
use crate::format::{Id, epoch, event, slot, snapshot, vault_info};
use crate::policy::SlotScope;

/// The largest file of each kind, as the readers allow.
fn max_len(name: &FileName) -> usize {
    match name {
        FileName::VaultInfo => vault_info::LEN,
        FileName::Epoch { .. } => epoch::MAX_LEN,
        FileName::Slot { .. } => slot::MAX_FILE_LEN,
        FileName::Event { .. } => event::MAX_FILE_LEN,
        FileName::Snapshot { .. } => snapshot::MAX_FILE_LEN,
    }
}

/// What `update` changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MirrorUpdate {
    pub copied: usize,
    pub removed: usize,
}

pub struct Mirror {
    copy: FsStore,
}

impl Mirror {
    /// The copy for vault `vault_id` under this device's state directory.
    pub fn new(state_dir: &Path, vault_id: &Id) -> Self {
        Self {
            copy: FsStore::new(state_dir.join("mirror").join(hex::encode(vault_id))),
        }
    }

    /// Every copy under `state_dir`, by vault ID.
    pub fn all(state_dir: &Path) -> Vec<Id> {
        let Ok(dirs) = std::fs::read_dir(state_dir.join("mirror")) else {
            return Vec::new();
        };
        dirs.filter_map(|d| {
            let name = d.ok()?.file_name();
            hex::decode(name.to_str()?).ok()?.try_into().ok()
        })
        .collect()
    }

    /// Vault files in the copy.
    pub fn files(&self) -> Result<Vec<String>> {
        Ok(self
            .copy
            .list()?
            .into_iter()
            .filter(|p| FileName::parse(p).is_some())
            .collect())
    }

    /// Adds a file this device just wrote.
    pub fn record(&self, path: &str, bytes: &[u8]) -> Result<()> {
        match self.copy.create(path, bytes) {
            Err(CoreError::Io(e)) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
            other => other,
        }
    }

    /// Drops a file this device just deleted from the folder.
    pub fn forget(&self, path: &str) -> Result<()> {
        match self.copy.delete(path) {
            Err(CoreError::Io(e)) if e.kind() == ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    /// Makes the copy match a folder this device just found healthy, keeping
    /// `strata-vault` and the slots of `current_epoch` (see the module docs).
    pub fn update(
        &self,
        folder: &dyn RemoteStore,
        vault_id: &Id,
        current_epoch: u32,
    ) -> Result<MirrorUpdate> {
        let mut out = MirrorUpdate::default();
        let in_folder: Vec<String> = folder
            .list()?
            .into_iter()
            .filter(|p| FileName::parse(p).is_some())
            .collect();
        let in_copy = self.files()?;
        for path in &in_folder {
            if in_copy.binary_search(path).is_ok() {
                continue;
            }
            let name = FileName::parse(path).expect("filtered above");
            // A file that vanished or grew too large since the listing waits for the
            // next update.
            if let Ok(bytes) = folder.read(path, max_len(&name)) {
                self.record(path, &bytes)?;
                out.copied += 1;
            }
        }
        for path in &in_copy {
            if in_folder.binary_search(path).is_ok() || self.keeps(path, vault_id, current_epoch) {
                continue;
            }
            self.forget(path)?;
            out.removed += 1;
        }
        Ok(out)
    }

    /// Whether a file the folder no longer has stays in the copy anyway.
    fn keeps(&self, path: &str, vault_id: &Id, current_epoch: u32) -> bool {
        match FileName::parse(path) {
            Some(FileName::VaultInfo) => true,
            Some(name @ FileName::Slot { .. }) => self
                .copy
                .read(path, max_len(&name))
                .ok()
                .and_then(|bytes| {
                    SlotFile::parse(&bytes, vault_id, SlotScope::Synced)
                        .ok()
                        .map(|slot| slot.epoch == current_epoch)
                })
                .unwrap_or(false),
            _ => false,
        }
    }

    /// The files in the copy that the folder is missing.
    pub fn missing_from(&self, folder: &dyn RemoteStore) -> Result<Vec<String>> {
        let in_folder = folder.list()?;
        Ok(self
            .files()?
            .into_iter()
            .filter(|p| in_folder.binary_search(p).is_err())
            .collect())
    }

    /// Puts back every file the folder is missing. Never overwrites: a file that
    /// appeared in the meantime is left as it is. Returns how many were put back.
    pub fn restore(&self, folder: &dyn RemoteStore) -> Result<usize> {
        let mut restored = 0;
        for path in self.missing_from(folder)? {
            let name = FileName::parse(&path).expect("files() lists vault files");
            let bytes = self.copy.read(&path, max_len(&name))?;
            match folder.create(&path, &bytes) {
                Ok(()) => restored += 1,
                Err(CoreError::Io(e)) if e.kind() == ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Ok(restored)
    }
}

/// A folder whose writes and deletes also go to this device's copy, once the copy
/// is attached (after unlock, when the vault ID is known). Failures to update the
/// copy never fail the write: the next `Mirror::update` catches up.
pub struct MirroredStore<R> {
    folder: R,
    mirror: Mutex<Option<Arc<Mirror>>>,
}

impl<R: RemoteStore> MirroredStore<R> {
    pub fn new(folder: R) -> Self {
        Self {
            folder,
            mirror: Mutex::new(None),
        }
    }

    pub fn attach(&self, mirror: Arc<Mirror>) {
        *self.mirror.lock().unwrap_or_else(|e| e.into_inner()) = Some(mirror);
    }

    pub fn mirror(&self) -> Option<Arc<Mirror>> {
        self.mirror
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn folder(&self) -> &R {
        &self.folder
    }
}

impl<R: RemoteStore> RemoteStore for MirroredStore<R> {
    fn list(&self) -> Result<Vec<String>> {
        self.folder.list()
    }

    fn list_dir(&self, dir: &str) -> Result<Vec<String>> {
        self.folder.list_dir(dir)
    }

    fn read(&self, path: &str, max_len: usize) -> Result<Vec<u8>> {
        self.folder.read(path, max_len)
    }

    fn create(&self, path: &str, bytes: &[u8]) -> Result<()> {
        self.folder.create(path, bytes)?;
        if let Some(mirror) = self.mirror() {
            let _ = mirror.record(path, bytes);
        }
        Ok(())
    }

    fn delete(&self, path: &str) -> Result<()> {
        self.folder.delete(path)?;
        if let Some(mirror) = self.mirror() {
            let _ = mirror.forget(path);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::MemoryStore;

    fn event(client: u8) -> String {
        FileName::Event {
            client_id: [client; 16],
            seq: 1,
        }
        .to_path()
    }

    #[test]
    fn writes_are_copied_and_restore_never_overwrites() {
        let (before, a, b) = (event(1), event(2), event(3));
        let state = tempfile::tempdir().unwrap();
        let mirror = Arc::new(Mirror::new(state.path(), &[1; 16]));
        let store = MirroredStore::new(MemoryStore::new());
        store.create(&before, b"not copied").unwrap();
        store.attach(Arc::clone(&mirror));
        store.create(&a, b"a").unwrap();
        store.create(&b, b"b").unwrap();
        store.delete(&b).unwrap();
        assert_eq!(mirror.files().unwrap(), std::slice::from_ref(&a));

        // The folder lost a.evt, and something else took its name meanwhile.
        store.folder().remove(&a);
        assert_eq!(
            mirror.missing_from(store.folder()).unwrap(),
            std::slice::from_ref(&a)
        );
        store.folder().put(&a, b"someone else's".to_vec());
        assert_eq!(mirror.restore(store.folder()).unwrap(), 0);
        assert_eq!(store.folder().get(&a).unwrap(), b"someone else's");

        // Gone for real: put back.
        store.folder().remove(&a);
        assert_eq!(mirror.restore(store.folder()).unwrap(), 1);
        assert_eq!(store.folder().get(&a).unwrap(), b"a");
    }

    #[test]
    fn update_follows_the_folder_but_keeps_the_vault_info() {
        let (a, s) = (
            event(2),
            FileName::Snapshot {
                snapshot_id: [4; 16],
            }
            .to_path(),
        );
        let state = tempfile::tempdir().unwrap();
        let mirror = Mirror::new(state.path(), &[1; 16]);
        let folder = MemoryStore::new();
        folder.put("strata-vault", b"info".to_vec());
        folder.put(&a, b"a".to_vec());
        folder.put(&s, b"s".to_vec());
        folder.put("notes.txt", b"not a vault file".to_vec());
        assert_eq!(
            mirror.update(&folder, &[1; 16], 0).unwrap(),
            MirrorUpdate {
                copied: 3,
                removed: 0
            }
        );
        folder.remove("strata-vault");
        folder.remove(&a);
        assert_eq!(
            mirror.update(&folder, &[1; 16], 0).unwrap(),
            MirrorUpdate {
                copied: 0,
                removed: 1
            }
        );
        assert_eq!(mirror.files().unwrap(), [s, "strata-vault".to_string()]);
    }
}
