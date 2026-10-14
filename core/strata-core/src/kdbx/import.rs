//! KeePass file to edits (spec §8.2.1).

use std::collections::BTreeSet;

use keepass::db::{
    CustomDataValue, DataTransferObfuscation, DatabaseOpenError, EntryRef, GroupId, Icon,
};
use keepass::error::DatabaseKeyError;
use keepass::{Database, DatabaseKey};
use unicode_normalization::UnicodeNormalization;

use super::extras::{AutoType, Extras};
use super::{
    ATTACHMENT_PREFIX, EXTRAS_FIELD, FIELD_PREFIX, GROUP_FIELD, KdbxError, PREFIX, STANDARD_FIELDS,
    header,
};
use crate::crypto::SecretBytes;
use crate::error::Result;
use crate::format::Id;
use crate::format::body::{
    ALWAYS_SECRET_FIELDS, MAX_FIELD_VALUE_LEN, WELL_KNOWN_FIELDS, check_name,
};
use crate::merge::edit::{Edit, new_entry_id};

/// Most ops in one event; well under the format's limit.
const BATCH_OPS: usize = 2000;
/// Roughly the most bytes of names and values in one event; the format allows 1 MiB.
const BATCH_BYTES: usize = 768 * 1024;

/// What an import adds, ready to write, one event per batch.
pub struct Imported {
    pub batches: Vec<Vec<Edit>>,
    pub report: ImportReport,
}

/// What was imported and what was left out (spec §8.2.1).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImportReport {
    pub entries: u32,
    /// Entries in the recycle bin.
    pub recycled: u32,
    /// Older versions of entries.
    pub history: u32,
    /// Fields, attachments and tags outside the vault's limits.
    pub skipped: u32,
    /// Entries whose custom icon wasn't kept.
    pub custom_icons: u32,
}

/// Opens the KeePass file with its password (UTF-8) and optional key file, and maps
/// every entry to edits.
pub fn import(
    file: &[u8],
    password: &[u8],
    keyfile: Option<&[u8]>,
) -> std::result::Result<Imported, KdbxError> {
    let db = open_file(file, password, keyfile)?;
    Ok(from_database(&db)?)
}

/// Opens a KeePass file with its password (UTF-8; may be empty) and optional key file.
pub fn open_file(
    file: &[u8],
    password: &[u8],
    keyfile: Option<&[u8]>,
) -> std::result::Result<Database, KdbxError> {
    header::check(file)?;
    let mut key = DatabaseKey::new();
    if !password.is_empty() {
        let password = std::str::from_utf8(password).map_err(|_| KdbxError::WrongKey)?;
        key = key.with_password(password);
    }
    if let Some(mut keyfile) = keyfile {
        key = key
            .with_keyfile(&mut keyfile)
            .map_err(|_| KdbxError::Unreadable("can't read the key file".into()))?;
    }
    // Fixed messages only: the crate's own can quote the file, and errors after
    // decryption (XML parsing) or from a malformed key file would quote secrets.
    Database::parse(file, key).map_err(|e| {
        KdbxError::Unreadable(
            match e {
                DatabaseOpenError::Key(
                    DatabaseKeyError::IncorrectKey | DatabaseKeyError::EmptyKey,
                ) => {
                    return KdbxError::WrongKey;
                }
                DatabaseOpenError::Key(_) => "the key file isn't valid",
                DatabaseOpenError::UnsupportedVersion | DatabaseOpenError::VersionParse(_) => {
                    "this kind of KeePass file isn't supported; save it as KDBX 4 in KeePass first"
                }
                DatabaseOpenError::Io(_) | DatabaseOpenError::UnexpectedEof => {
                    "the file is incomplete"
                }
                DatabaseOpenError::Cryptography(_) => "the file is damaged: it doesn't decrypt",
                _ => "the file is damaged, or not a KeePass file",
            }
            .into(),
        )
    })
}

pub(crate) fn from_database(db: &Database) -> Result<Imported> {
    let mut report = ImportReport::default();
    let recycle_bin = db.recycle_bin().map(|g| g.id());
    // The crate keeps entries in a hash map; sort for a stable import order.
    let mut entries: Vec<EntryRef<'_>> = db.iter_all_entries().collect();
    entries.sort_by_key(|e| e.id().uuid());

    let mut edits = Vec::new();
    for entry in entries {
        let groups = ancestors(db, &entry);
        if recycle_bin.is_some_and(|bin| groups.contains(&bin)) {
            report.recycled += 1;
            continue;
        }
        report.entries += 1;
        report.history += entry
            .history
            .as_ref()
            .map_or(0, |h| h.get_entries().len() as u32);
        let path = group_path(db, &groups);
        edits.extend(entry_edits(&entry, path, new_entry_id()?, &mut report));
    }
    Ok(Imported {
        batches: batches(edits),
        report,
    })
}

fn entry_edits(entry: &EntryRef<'_>, path: String, id: Id, report: &mut ImportReport) -> Vec<Edit> {
    let mut out = Out {
        id,
        edits: Vec::new(),
        report,
    };

    let mut names: Vec<&String> = entry.fields.keys().collect();
    names.sort();
    for name in names {
        let value = &entry.fields[name];
        let field = strata_name(name);
        let secret = value.is_protected() || ALWAYS_SECRET_FIELDS.contains(&field.as_str());
        out.field(field, value.get().as_bytes().to_vec(), secret);
    }

    let mut attachments: Vec<_> = entry.attachments_named().collect();
    attachments.sort_by_key(|(name, _)| *name);
    for (name, attachment) in attachments {
        let name = format!("{ATTACHMENT_PREFIX}{name}");
        out.field(name, attachment.data.get().clone(), true);
    }

    let mut tags: BTreeSet<String> = entry.tags.iter().map(|t| t.nfc().collect()).collect();
    if !path.is_empty() {
        out.field(GROUP_FIELD.to_string(), path.clone().into_bytes(), false);
        tags.insert(path);
    }
    for tag in tags {
        out.tag(tag);
    }

    if matches!(entry.icon(), Some(Icon::Custom(_))) {
        out.report.custom_icons += 1;
    }
    // Secret: override URLs and auto-type sequences can hold credentials.
    out.field(EXTRAS_FIELD.to_string(), extras(entry).encode(), true);
    out.edits
}

/// Collects one entry's edits, leaving out (and counting) what breaks the limits.
struct Out<'r> {
    id: Id,
    edits: Vec<Edit>,
    report: &'r mut ImportReport,
}

impl Out<'_> {
    fn field(&mut self, name: String, value: Vec<u8>, secret: bool) {
        let value = SecretBytes::new(value);
        if value.expose().is_empty() {
            return;
        }
        let name: String = name.nfc().collect();
        if check_name(&name, "field").is_err() || value.expose().len() > MAX_FIELD_VALUE_LEN {
            self.report.skipped += 1;
            return;
        }
        self.edits.push(Edit::SetField {
            entry_id: self.id,
            name,
            value: Some(value),
            secret,
        });
    }

    fn tag(&mut self, tag: String) {
        if check_name(&tag, "tag").is_err() {
            self.report.skipped += 1;
            return;
        }
        self.edits.push(Edit::AddTag {
            entry_id: self.id,
            tag,
        });
    }
}

/// Strata's name for a KeePass string field.
fn strata_name(kdbx: &str) -> String {
    if let Some((_, strata)) = STANDARD_FIELDS.iter().find(|(k, _)| *k == kdbx) {
        return strata.to_string();
    }
    if WELL_KNOWN_FIELDS.contains(&kdbx) || kdbx.starts_with(PREFIX) {
        return format!("{FIELD_PREFIX}{kdbx}");
    }
    kdbx.to_string()
}

/// The entry's group and the groups above it, up to and including the root.
fn ancestors(db: &Database, entry: &EntryRef<'_>) -> Vec<GroupId> {
    let mut out = vec![entry.parent().id()];
    while let Some(parent) = db
        .group(*out.last().expect("not empty"))
        .and_then(|g| g.parent().map(|p| p.id()))
    {
        out.push(parent);
    }
    out
}

/// The names of the groups between the root and the entry, joined with `/`.
fn group_path(db: &Database, ancestors: &[GroupId]) -> String {
    let below_root = &ancestors[..ancestors.len().saturating_sub(1)];
    let names: Vec<String> = below_root
        .iter()
        .rev()
        .filter_map(|id| db.group(*id).map(|g| g.name.clone()))
        .collect();
    names.join("/").nfc().collect()
}

fn extras(entry: &EntryRef<'_>) -> Extras {
    let seconds = |t: Option<chrono::NaiveDateTime>| t.map(|t| t.and_utc().timestamp());
    Extras {
        uuid: Some(entry.id().uuid().into_bytes()),
        icon: match entry.icon() {
            Some(Icon::BuiltIn(i)) => Some(*i as u64),
            _ => None,
        },
        foreground: entry.foreground_color.as_ref().map(ToString::to_string),
        background: entry.background_color.as_ref().map(ToString::to_string),
        override_url: entry.override_url.clone().filter(|u| !u.is_empty()),
        quality_check: entry.quality_check,
        created: seconds(entry.times.creation),
        expiry: seconds(entry.times.expiry),
        expires: entry.times.expires.unwrap_or(false),
        autotype: entry.autotype.as_ref().map(|a| AutoType {
            enabled: a.enabled,
            sequence: a.default_sequence.clone().filter(|s| !s.is_empty()),
            use_clipboard: a.data_transfer_obfuscation == DataTransferObfuscation::UseClipboard,
            associations: a
                .associations
                .iter()
                .map(|x| (x.window.clone(), x.sequence.clone()))
                .collect(),
        }),
        custom_data: {
            let mut items: Vec<(String, String)> = entry
                .custom_data
                .iter()
                .filter_map(|(k, item)| match &item.value {
                    Some(CustomDataValue::String(v)) => Some((k.clone(), v.clone())),
                    _ => None,
                })
                .collect();
            items.sort();
            items
        },
    }
}

/// Splits the edits into events that stay within the format's limits.
pub(super) fn batches(edits: Vec<Edit>) -> Vec<Vec<Edit>> {
    let mut out: Vec<Vec<Edit>> = Vec::new();
    let mut current = Vec::new();
    let mut bytes = 0;
    for edit in edits {
        let size = match &edit {
            Edit::SetField { name, value, .. } => {
                64 + name.len() + value.as_ref().map_or(0, |v| v.expose().len())
            }
            Edit::AddTag { tag, .. } => 48 + tag.len(),
            _ => 48,
        };
        if !current.is_empty() && (current.len() >= BATCH_OPS || bytes + size > BATCH_BYTES) {
            out.push(std::mem::take(&mut current));
            bytes = 0;
        }
        bytes += size;
        current.push(edit);
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}
