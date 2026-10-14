//! Import against files KeePassXC wrote (`tests/fixtures/kdbx`, built by `make.sh`).

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::format::Id;
use crate::merge::edit::Edit;

const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/kdbx/keepassxc.kdbx");
const FIXTURE_WITH_KEYFILE: &[u8] =
    include_bytes!("../../tests/fixtures/kdbx/keepassxc-keyfile.kdbx");
const KEYFILE: &[u8] = include_bytes!("../../tests/fixtures/kdbx/keyfile.key");
const PASSWORD: &[u8] = b"fixture-password";

/// One imported entry: its fields as (value, secret), and its tags.
#[derive(Debug, Default)]
struct Imported {
    fields: BTreeMap<String, (Vec<u8>, bool)>,
    tags: BTreeSet<String>,
}

impl Imported {
    fn text(&self, name: &str) -> Option<&str> {
        self.fields
            .get(name)
            .map(|(v, _)| std::str::from_utf8(v).unwrap())
    }

    fn secret(&self, name: &str) -> bool {
        self.fields[name].1
    }
}

/// The edits grouped by entry, keyed by title.
fn entries(batches: &[Vec<Edit>]) -> BTreeMap<String, Imported> {
    let mut by_id: BTreeMap<Id, Imported> = BTreeMap::new();
    for edit in batches.iter().flatten() {
        match edit {
            Edit::SetField {
                entry_id,
                name,
                value,
                secret,
            } => {
                let value = value.as_ref().unwrap().expose().to_vec();
                by_id
                    .entry(*entry_id)
                    .or_default()
                    .fields
                    .insert(name.clone(), (value, *secret));
            }
            Edit::AddTag { entry_id, tag } => {
                by_id.entry(*entry_id).or_default().tags.insert(tag.clone());
            }
            other => panic!("unexpected edit {other:?}"),
        }
    }
    by_id
        .into_values()
        .map(|e| (e.text("title").unwrap_or_default().to_string(), e))
        .collect()
}

#[test]
fn imports_what_keepassxc_wrote() {
    let imported = import(FIXTURE, PASSWORD, None).unwrap();
    assert_eq!(
        imported.report,
        ImportReport {
            entries: 3,
            recycled: 1,
            history: 2,
            skipped: 1, // the 70 kB field
            custom_icons: 0,
        }
    );
    let entries = entries(&imported.batches);
    assert_eq!(
        entries.keys().collect::<Vec<_>>(),
        ["Bank", "Mail", "Visa"],
        "the recycle bin stays behind"
    );

    let bank = &entries["Bank"];
    assert_eq!(bank.text("username"), Some("customer-42"));
    assert_eq!(bank.text("password"), Some("bank-password"));
    assert!(bank.secret("password"));
    assert_eq!(bank.text("url"), Some("https://bank.example.test"));
    assert_eq!(bank.text("notes"), Some("Branch: Main St."));
    assert!(!bank.secret("notes"));
    assert_eq!(bank.text("PIN"), Some("4711"));
    assert!(bank.secret("PIN"), "protected custom fields stay secret");
    assert_eq!(bank.text("Account type"), Some("checking"));
    assert!(!bank.secret("Account type"));
    assert_eq!(
        bank.text("kdbx:field:url"),
        Some("a custom field that clashes with url")
    );
    assert_eq!(bank.text("Caf\u{e9}"), Some("a name that isn't NFC"));
    assert_eq!(
        bank.text("kdbx:attachment:key.txt"),
        Some("secret key file contents")
    );
    assert!(bank.secret("kdbx:attachment:key.txt"));
    assert_eq!(bank.text(GROUP_FIELD), Some("Finance"));
    assert_eq!(
        bank.tags,
        BTreeSet::from(["Finance".into(), "important".into(), "money".into()])
    );

    let extras = Extras::decode(&bank.fields[EXTRAS_FIELD].0).unwrap();
    let mut uuid = [0; 16];
    uuid[15] = 3;
    assert_eq!(extras.uuid, Some(uuid));
    assert_eq!(extras.icon, Some(66));
    assert_eq!(extras.foreground.as_deref(), Some("#FF0000"));
    assert_eq!(extras.background.as_deref(), Some("#00FF00"));
    assert_eq!(extras.override_url.as_deref(), Some("cmd://firefox {URL}"));
    assert!(!extras.quality_check);
    assert_eq!(extras.created, Some(1_577_836_800)); // 2020-01-01
    assert_eq!(extras.expiry, Some(1_893_456_000)); // 2030-01-01
    assert!(extras.expires);
    let autotype = extras.autotype.unwrap();
    assert!(autotype.enabled && autotype.use_clipboard);
    assert_eq!(
        autotype.sequence.as_deref(),
        Some("{USERNAME}{TAB}{PASSWORD}{ENTER}")
    );
    assert_eq!(
        autotype.associations,
        [("*Bank*".to_string(), "{PASSWORD}{ENTER}".to_string())]
    );
    assert!(
        extras
            .custom_data
            .contains(&("KPXC_DECRYPTION_TIME_PREFERENCE".into(), "100".into()))
    );

    let mail = &entries["Mail"];
    assert_eq!(
        mail.text("otp"),
        Some("otpauth://totp/Mail?secret=JBSWY3DPEHPK3PXP")
    );
    assert!(mail.secret("otp"));
    assert!(!mail.fields.contains_key("url"), "empty values are skipped");
    assert!(!mail.fields.contains_key("Huge"), "over the value limit");
    assert!(!mail.fields.contains_key(GROUP_FIELD), "in the root group");
    assert!(mail.tags.is_empty());

    let visa = &entries["Visa"];
    assert_eq!(visa.text(GROUP_FIELD), Some("Finance/Cards"));
    assert!(visa.tags.contains("Finance/Cards"));

    // History isn't imported: no old password appears anywhere.
    for entry in entries.values() {
        for (value, _) in entry.fields.values() {
            assert!(!value.windows(12).any(|w| w == b"old-bank-pas"));
        }
    }
}

#[test]
fn key_files_and_wrong_keys() {
    let imported = import(FIXTURE_WITH_KEYFILE, PASSWORD, Some(KEYFILE)).unwrap();
    assert_eq!(imported.report.entries, 3);
    assert!(matches!(
        import(FIXTURE_WITH_KEYFILE, PASSWORD, None),
        Err(KdbxError::WrongKey)
    ));
    assert!(matches!(
        import(FIXTURE, b"wrong", None),
        Err(KdbxError::WrongKey)
    ));
    assert!(matches!(
        import(FIXTURE, b"", None),
        Err(KdbxError::WrongKey)
    ));
    assert!(matches!(
        import(b"not a keepass file", PASSWORD, None),
        Err(KdbxError::Unreadable(_))
    ));
    let mut truncated = FIXTURE.to_vec();
    truncated.truncate(FIXTURE.len() / 2);
    assert!(import(&truncated, PASSWORD, None).is_err());
}

#[test]
fn batches_stay_inside_the_event_limits() {
    let entry_id = [1; 16];
    let big = |i: usize| Edit::SetField {
        entry_id,
        name: format!("field {i}"),
        value: Some(crate::crypto::SecretBytes::new(vec![b'x'; 60 * 1024])),
        secret: false,
    };
    let tag = |i: usize| Edit::AddTag {
        entry_id,
        tag: format!("tag {i}"),
    };
    let edits: Vec<Edit> = (0..40).map(big).chain((0..5000).map(tag)).collect();
    let batches = import::batches(edits);
    assert_eq!(batches.iter().map(Vec::len).sum::<usize>(), 5040);
    for batch in &batches {
        assert!(batch.len() <= 2000);
        let bytes: usize = batch
            .iter()
            .map(|e| match e {
                Edit::SetField { value, .. } => value.as_ref().unwrap().expose().len(),
                _ => 0,
            })
            .sum();
        assert!(bytes <= 768 * 1024, "{bytes}");
    }
}
