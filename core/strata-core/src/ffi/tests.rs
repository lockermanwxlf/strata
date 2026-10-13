//! The FFI surface end to end, on real directories: what Kotlin will see.

use super::*;

const PASSWORD: &[u8] = b"correct horse battery staple";

struct Dirs {
    vault: tempfile::TempDir,
    states: tempfile::TempDir,
}

impl Dirs {
    fn new() -> Self {
        Self {
            vault: tempfile::tempdir().unwrap(),
            states: tempfile::tempdir().unwrap(),
        }
    }

    fn vault(&self) -> String {
        self.vault.path().to_str().unwrap().into()
    }

    /// Each device keeps its local state in its own directory.
    fn state(&self, device: &str) -> String {
        self.states.path().join(device).to_str().unwrap().into()
    }

    fn create(&self) -> NewVault {
        create_vault(
            self.vault(),
            self.state("laptop"),
            PASSWORD.to_vec(),
            "Laptop".into(),
        )
        .unwrap()
    }

    fn open(&self, device: &str) -> Arc<Vault> {
        let vault = Vault::open(self.vault(), self.state(device), device.into()).unwrap();
        vault.unlock_password(PASSWORD.to_vec()).unwrap();
        vault
    }
}

fn set(entry_id: &str, name: &str, value: &[u8]) -> EntryEdit {
    EntryEdit::SetField {
        entry_id: entry_id.into(),
        name: name.into(),
        value: Some(value.to_vec()),
        secret: false,
    }
}

#[test]
fn create_edit_and_read_back() {
    let dirs = Dirs::new();
    let created = dirs.create();
    assert_eq!(
        String::from_utf8(created.recovery_words.clone())
            .unwrap()
            .split_whitespace()
            .count(),
        24
    );
    let vault = created.vault;
    assert!(!vault.is_locked());
    let id = new_entry_id().unwrap();
    vault
        .apply(vec![
            set(&id, "title", b"Bank"),
            set(&id, "username", b"me"),
            set(&id, "password", b"hunter2"),
            EntryEdit::AddTag {
                entry_id: id.clone(),
                tag: "money".into(),
            },
        ])
        .unwrap();

    let entries = vault.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].title.as_deref(), Some("Bank"));
    assert_eq!(entries[0].username.as_deref(), Some("me"));
    assert_eq!(entries[0].tags, vec!["money".to_string()]);

    // The detail shows the password as secret, with no value; reveal hands it out.
    let detail = vault.entry(id.clone()).unwrap();
    let password = detail.fields.iter().find(|f| f.name == "password").unwrap();
    assert!(password.secret && password.value.is_none());
    assert_eq!(
        vault.reveal(id.clone(), "password".into()).unwrap(),
        b"hunter2"
    );
    assert!(matches!(
        vault.reveal(id.clone(), "nope".into()),
        Err(VaultError::NotFound { .. })
    ));

    vault.lock();
    assert!(vault.is_locked() && vault.status().locked);
    assert!(matches!(vault.entries(), Err(VaultError::Locked)));
    assert!(matches!(
        vault.unlock_password(b"wrong".to_vec()),
        Err(VaultError::WrongCredential)
    ));
    vault.unlock_password(PASSWORD.to_vec()).unwrap();
    assert_eq!(vault.entries().unwrap().len(), 1);
}

#[test]
fn two_devices_sync_and_see_conflicts() {
    let dirs = Dirs::new();
    let laptop = dirs.create().vault;
    let phone = dirs.open("phone");
    let id = new_entry_id().unwrap();
    laptop.apply(vec![set(&id, "title", b"Mail")]).unwrap();
    assert_eq!(phone.sync().unwrap().applied, 1);
    assert_eq!(phone.entries().unwrap()[0].title.as_deref(), Some("Mail"));

    // Both change the password without seeing each other: a conflict, both kept.
    laptop
        .apply(vec![set(&id, "password", b"from laptop")])
        .unwrap();
    phone
        .apply(vec![set(&id, "password", b"from phone")])
        .unwrap();
    laptop.sync().unwrap();
    let status = laptop.status();
    assert_eq!(status.conflicts, 1);
    assert!(matches!(
        laptop.reveal(id.clone(), "password".into()),
        Err(VaultError::FieldConflict)
    ));
    let mut values: Vec<Vec<u8>> = laptop
        .reveal_conflict(id.clone(), "password".into())
        .unwrap()
        .into_iter()
        .map(|c| c.value.unwrap())
        .collect();
    values.sort();
    assert_eq!(
        values,
        vec![b"from laptop".to_vec(), b"from phone".to_vec()]
    );
    assert_eq!(laptop.devices().unwrap().len(), 2);
}

#[test]
fn a_password_change_reaches_the_other_device() {
    let dirs = Dirs::new();
    let laptop = dirs.create().vault;
    let phone = dirs.open("phone");
    phone
        .apply(vec![set(&new_entry_id().unwrap(), "title", b"x")])
        .unwrap();
    laptop.sync().unwrap();
    assert_eq!(
        laptop
            .change_password(b"new password".to_vec())
            .unwrap()
            .epoch,
        1
    );

    let summary = phone.sync().unwrap();
    assert!(summary.key_rotated && phone.status().key_rotated);
    assert!(matches!(
        phone.apply(vec![set(&new_entry_id().unwrap(), "title", b"y")]),
        Err(VaultError::KeyRotated)
    ));
    phone.lock();
    assert!(matches!(
        phone.unlock_password(PASSWORD.to_vec()),
        Err(VaultError::WrongCredential)
    ));
    assert!(
        !phone
            .unlock_password(b"new password".to_vec())
            .unwrap()
            .key_rotated
    );
    phone
        .apply(vec![set(&new_entry_id().unwrap(), "title", b"y")])
        .unwrap();
}

#[test]
fn an_alarm_is_reported_not_thrown() {
    let dirs = Dirs::new();
    let laptop = dirs.create().vault;
    laptop
        .apply(vec![set(&new_entry_id().unwrap(), "title", b"x")])
        .unwrap();
    // Someone deletes the laptop's latest event from the folder.
    let events = dirs.vault.path().join("events");
    let latest = std::fs::read_dir(&events)
        .unwrap()
        .map(|e| e.unwrap().path())
        .max()
        .unwrap();
    std::fs::remove_file(latest).unwrap();
    let summary = laptop.sync().unwrap();
    assert_eq!(summary.alarm, Some(AlarmKind::Rollback));
    assert_eq!(laptop.status().alarm, Some(AlarmKind::Rollback));
    // Still readable; nothing more is written.
    assert!(laptop.entries().is_ok());
    assert!(matches!(
        laptop.apply(vec![set(&new_entry_id().unwrap(), "title", b"y")]),
        Err(VaultError::Alarm { .. })
    ));
}

#[test]
fn bad_input_is_rejected_cleanly() {
    let dirs = Dirs::new();
    assert!(Vault::open(dirs.vault(), dirs.state("x"), String::new()).is_err());
    let vault = dirs.create().vault;
    assert!(matches!(
        vault.entry("not hex".into()),
        Err(VaultError::Rejected { .. })
    ));
    assert!(password_strength(b"password".to_vec()).unwrap().warn);
    assert!(
        !password_strength(b"correct horse battery staple violin".to_vec())
            .unwrap()
            .warn
    );
}
