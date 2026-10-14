//! The merged view to a KeePass file (spec §8.2.1).

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, NaiveDateTime};
use keepass::config::{DatabaseConfig, KdfConfig};
use keepass::db::{
    AutoTypeAssociation, Color, CustomDataItem, CustomDataValue, DataTransferObfuscation, EntryId,
    GroupId, Value,
};
use keepass::{Database, DatabaseKey};
use uuid::Uuid;

use super::extras::Extras;
use super::{
    ATTACHMENT_PREFIX, EXTRAS_FIELD, FIELD_PREFIX, GROUP_FIELD, KdbxError, PREFIX, STANDARD_FIELDS,
};
use crate::crypto::SecretBytes;
use crate::merge::view::{EntryView, Field, VaultView};

/// The export's Argon2id parameters: the vault's password defaults (spec §6.2).
const ARGON2_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
const ARGON2_ITERATIONS: u64 = 3;
const ARGON2_PARALLELISM: u32 = 4;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExportReport {
    pub entries: u32,
    /// Fields in conflict, exported as several fields.
    pub conflicts: u32,
    /// Values left out: not text where KeePass needs text, or `kdbx:` data Strata
    /// doesn't recognize.
    pub skipped: u32,
}

/// Every entry not in the trash, as a KDBX 4 file under `password` (UTF-8).
pub fn export(view: &VaultView<'_>, password: &[u8]) -> Result<(Vec<u8>, ExportReport), KdbxError> {
    let password = std::str::from_utf8(password)
        .map_err(|_| KdbxError::Write("the password isn't valid text".into()))?;
    if password.is_empty() {
        return Err(KdbxError::Write("the password is empty".into()));
    }
    let mut db = Database::with_config(config());
    db.root_mut().name = "Strata".into();
    let mut report = ExportReport::default();
    let mut groups = HashMap::new();
    let mut used = HashSet::new();
    let now = naive(now_seconds()).unwrap_or_default();

    for entry in view.entries.values().filter(|e| !e.deleted) {
        report.entries += 1;
        add_entry(&mut db, entry, now, &mut groups, &mut used, &mut report);
    }

    let mut out = Vec::new();
    db.save(&mut out, DatabaseKey::new().with_password(password))
        .map_err(|e| KdbxError::Write(e.to_string()))?;
    Ok((out, report))
}

fn add_entry(
    db: &mut Database,
    view: &EntryView<'_>,
    now: NaiveDateTime,
    groups: &mut HashMap<String, GroupId>,
    used: &mut HashSet<Uuid>,
    report: &mut ExportReport,
) {
    let text = |name: &str| match view.fields.get(name) {
        Some(Field::Value { value, .. }) => std::str::from_utf8(value.expose()).ok(),
        _ => None,
    };
    let extras = view
        .fields
        .get(EXTRAS_FIELD)
        .and_then(|f| match f {
            Field::Value { value, .. } => Extras::decode(value.expose()),
            Field::Conflict { .. } => None,
        })
        .unwrap_or_default();
    let path = text(GROUP_FIELD).unwrap_or_default().to_string();
    let group = group_for(db, &path, groups);

    // Only this export adds entries, and `used` holds every UUID it gave out.
    let uuid = extras
        .uuid
        .map(Uuid::from_bytes)
        .filter(|u| !used.contains(u))
        .unwrap_or_else(Uuid::new_v4);
    used.insert(uuid);
    let mut parent = db.group_mut(group).expect("groups come from group_for");
    let mut entry = parent
        .add_entry_with_id(EntryId::from_uuid(uuid))
        .expect("a UUID no entry has yet");

    // Strata's standard fields first, so they get KeePass's standard keys and a
    // custom field that happens to share a key gets a free name instead.
    let mut fields: Vec<(&str, &Field<'_>)> = view.fields.iter().map(|(n, f)| (*n, f)).collect();
    fields.sort_by_key(|(name, _)| !STANDARD_FIELDS.iter().any(|(_, s)| s == name));
    for (name, field) in fields {
        if name == EXTRAS_FIELD || name == GROUP_FIELD {
            continue;
        }
        let values = values(field);
        if values.len() > 1 {
            report.conflicts += 1;
        }
        for (i, (value, secret)) in values.into_iter().enumerate() {
            let suffix = if i == 0 {
                String::new()
            } else {
                format!(" (conflict {})", i + 1)
            };
            if let Some(attachment) = name.strip_prefix(ATTACHMENT_PREFIX) {
                let data = value.expose().to_vec();
                let data = if secret {
                    Value::protected(data)
                } else {
                    Value::unprotected(data)
                };
                entry.add_attachment(format!("{attachment}{suffix}"), data);
                continue;
            }
            let kdbx_name = match kdbx_name(name) {
                Some(n) => free_name(&entry.fields, format!("{n}{suffix}")),
                None => {
                    report.skipped += 1;
                    continue;
                }
            };
            let Ok(text) = std::str::from_utf8(value.expose()) else {
                report.skipped += 1;
                continue;
            };
            let value = if secret {
                Value::protected(text)
            } else {
                Value::unprotected(text)
            };
            entry.fields.insert(kdbx_name, value);
        }
    }

    entry.tags = view
        .tags
        .iter()
        .filter(|t| **t != path)
        .map(|t| t.to_string())
        .collect();

    entry.times.creation = Some(extras.created.and_then(naive).unwrap_or(now));
    entry.times.last_modification = Some(now);
    entry.times.last_access = Some(now);
    entry.times.expiry = extras.expiry.and_then(naive);
    entry.times.expires = Some(extras.expires);
    if let Some(icon) = extras.icon {
        entry.set_icon_builtin(icon as usize);
    }
    entry.foreground_color = extras
        .foreground
        .as_deref()
        .and_then(|c| Color::from_str(c).ok());
    entry.background_color = extras
        .background
        .as_deref()
        .and_then(|c| Color::from_str(c).ok());
    entry.override_url = extras.override_url.clone();
    entry.quality_check = extras.quality_check;
    if let Some(a) = &extras.autotype {
        let mut autotype = keepass::db::AutoType {
            enabled: a.enabled,
            default_sequence: a.sequence.clone(),
            ..Default::default()
        };
        if a.use_clipboard {
            autotype.data_transfer_obfuscation = DataTransferObfuscation::UseClipboard;
        }
        autotype.associations = a
            .associations
            .iter()
            .map(|(window, sequence)| AutoTypeAssociation {
                window: window.clone(),
                sequence: sequence.clone(),
            })
            .collect();
        entry.autotype = Some(autotype);
    }
    for (key, value) in &extras.custom_data {
        entry.custom_data.insert(
            key.clone(),
            CustomDataItem {
                value: Some(CustomDataValue::String(value.clone())),
                last_modification_time: None,
            },
        );
    }
}

/// A field's values in export order: a conflict's candidates by dot, deletions left out.
fn values<'a>(field: &Field<'a>) -> Vec<(&'a SecretBytes, bool)> {
    match field {
        Field::Value { value, secret, .. } => vec![(*value, *secret)],
        Field::Conflict { candidates } => candidates
            .iter()
            .filter_map(|c| c.value.map(|v| (v, true)))
            .collect(),
    }
}

/// `name`, or the first of `name (2)`, `name (3)` and so on that the entry doesn't
/// use yet.
fn free_name<V>(taken: &HashMap<String, V>, name: String) -> String {
    if !taken.contains_key(&name) {
        return name;
    }
    (2..)
        .map(|i| format!("{name} ({i})"))
        .find(|n| !taken.contains_key(n))
        .expect("an unbounded range has a free name")
}

/// KeePass's name for a Strata field, or `None` for `kdbx:` data this version
/// doesn't know.
fn kdbx_name(strata: &str) -> Option<String> {
    if let Some((kdbx, _)) = STANDARD_FIELDS.iter().find(|(_, s)| *s == strata) {
        return Some(kdbx.to_string());
    }
    if let Some(name) = strata.strip_prefix(FIELD_PREFIX) {
        return Some(name.to_string());
    }
    (!strata.starts_with(PREFIX)).then(|| strata.to_string())
}

/// The group at `path` below the root, created as needed.
fn group_for(db: &mut Database, path: &str, groups: &mut HashMap<String, GroupId>) -> GroupId {
    let mut current = db.root().id();
    let mut so_far = String::new();
    for name in path.split('/').filter(|n| !n.is_empty()) {
        so_far.push('/');
        so_far.push_str(name);
        current = match groups.get(&so_far) {
            Some(id) => *id,
            None => {
                let mut parent = db.group_mut(current).expect("known group");
                let mut group = parent.add_group();
                group.name = name.to_string();
                let id = group.id();
                groups.insert(so_far.clone(), id);
                id
            }
        };
    }
    current
}

fn config() -> DatabaseConfig {
    let mut config = DatabaseConfig::default();
    // The crate's default is Argon2d with a small memory cost. Keep its Argon2
    // version (0x13) and switch to Argon2id at the vault's own parameters.
    if let KdfConfig::Argon2 { version, .. } = config.kdf_config.clone() {
        config.kdf_config = KdfConfig::Argon2id {
            iterations: ARGON2_ITERATIONS,
            memory: ARGON2_MEMORY_BYTES,
            parallelism: ARGON2_PARALLELISM,
            version,
        };
    }
    config
}

fn naive(seconds: i64) -> Option<NaiveDateTime> {
    DateTime::from_timestamp(seconds, 0).map(|t| t.naive_utc())
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
