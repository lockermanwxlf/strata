//! Memory hygiene (implementation plan, Phase 13): secrets never show up in `Debug`
//! output or error messages, whichever type carries them.

use strata_core::crypto::{SecretBytes, SecretKey};
use strata_core::ffi::{EntryEdit, Vault, VaultError, create_vault, new_entry_id};
use strata_core::format::body::Op;
use strata_core::local::StateRecord;
use strata_core::merge::edit::Edit;

const SECRET: &[u8] = b"hunter2-correct-horse";

/// The secret, as text and as the byte list `Debug` would print for a `Vec<u8>`.
fn assert_hidden(what: &str, output: &str) {
    let text = String::from_utf8_lossy(SECRET);
    let bytes = format!("{:?}", SECRET);
    assert!(
        !output.contains(text.as_ref()),
        "{what} shows the secret: {output}"
    );
    assert!(
        !output.contains(&bytes[1..bytes.len() - 1]),
        "{what} shows the bytes: {output}"
    );
}

#[test]
fn debug_output_never_shows_secrets() {
    let key = SecretKey::from_slice(&[0x5a; 32]).unwrap();
    let key_debug = format!("{key:?}");
    assert!(!key_debug.contains("90"), "{key_debug}"); // 0x5a
    assert_hidden(
        "SecretBytes",
        &format!("{:?}", SecretBytes::new(SECRET.to_vec())),
    );

    let edit = Edit::SetField {
        entry_id: [1; 16],
        name: "password".into(),
        value: Some(SecretBytes::new(SECRET.to_vec())),
        secret: true,
    };
    assert_hidden("Edit", &format!("{edit:?}"));
    let op = Op::SetField {
        entry_id: [1; 16],
        name: "password".into(),
        value: Some(SecretBytes::new(SECRET.to_vec())),
        secret: true,
    };
    assert_hidden("Op", &format!("{op:?}"));

    let record = StateRecord {
        device_seed: SecretKey::from_slice(&[0x5a; 32]).unwrap(),
        next_seq: 1,
        high_water: Vec::new(),
        pending: Vec::new(),
        snapshots: Vec::new(),
    };
    let record_debug = format!("{record:?}");
    assert!(record_debug.contains("[redacted]"), "{record_debug}");
    assert!(!record_debug.contains("90, 90"), "{record_debug}");
}

#[test]
fn errors_never_show_secrets() {
    let vault_dir = tempfile::tempdir().unwrap();
    let state_dir = tempfile::tempdir().unwrap();
    let path = |d: &tempfile::TempDir| d.path().to_str().unwrap().to_string();
    let created = create_vault(
        path(&vault_dir),
        path(&state_dir),
        b"the password".to_vec(),
        "Laptop".into(),
    )
    .unwrap();
    let id = new_entry_id().unwrap();
    created
        .vault
        .apply(vec![EntryEdit::SetField {
            entry_id: id.clone(),
            name: "password".into(),
            value: Some(SECRET.to_vec()),
            secret: true,
        }])
        .unwrap();

    // A field name the core rejects, carrying the secret.
    let rejected = created.vault.apply(vec![EntryEdit::SetField {
        entry_id: id.clone(),
        name: String::new(),
        value: Some(SECRET.to_vec()),
        secret: true,
    }]);
    let e = rejected.unwrap_err();
    assert_hidden("a rejected edit", &format!("{e} {e:?}"));

    // Wrong passwords and recovery words.
    let other_state = tempfile::tempdir().unwrap();
    let vault = Vault::open(path(&vault_dir), path(&other_state), "Phone".into()).unwrap();
    let e = vault.unlock_password(SECRET.to_vec()).unwrap_err();
    assert!(matches!(e, VaultError::WrongCredential));
    assert_hidden("a wrong password", &format!("{e} {e:?}"));
    let words = b"abandon ability able about above absent absorb abstract absurd abuse access accident \
                  account accuse achieve acid acoustic acquire across act action actor actress actual";
    let e = vault.unlock_recovery(words.to_vec()).unwrap_err();
    assert!(!format!("{e} {e:?}").contains("abandon"), "{e}");

    // A KeePass file with garbage where its encrypted contents go.
    let mut kdbx = include_bytes!("fixtures/kdbx/keepassxc.kdbx").to_vec();
    let n = kdbx.len();
    kdbx[n - 200..].copy_from_slice(&[0x41; 200]);
    if let Err(e) = created
        .vault
        .import_kdbx(kdbx, b"fixture-password".to_vec(), None)
    {
        assert!(!format!("{e} {e:?}").contains("bank-password"), "{e}");
    }
}
