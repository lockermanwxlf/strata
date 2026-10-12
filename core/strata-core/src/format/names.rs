//! Vault file names (spec §5).
//!
//! Paths are relative to the vault directory and use `/`. Anything that doesn't
//! match a pattern exactly (temp files, sync-provider conflict copies, uppercase
//! hex) is not a vault file and is ignored, not rejected.

use super::Id;
use crate::error::{CoreError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileName {
    VaultInfo,
    Epoch { epoch: u32, creator: Id },
    Slot { slot_id: Id },
    Event { client_id: Id, seq: u64 },
    Snapshot { snapshot_id: Id },
}

impl FileName {
    pub fn parse(path: &str) -> Option<Self> {
        if path == "strata-vault" {
            return Some(FileName::VaultInfo);
        }
        let (dir, file) = path.split_once('/')?;
        match dir {
            "epochs" => {
                let (epoch, creator) = file.strip_suffix(".epoch")?.split_once('-')?;
                Some(FileName::Epoch {
                    epoch: u32::from_be_bytes(hex::<4>(epoch)?),
                    creator: hex(creator)?,
                })
            }
            "slots" => Some(FileName::Slot {
                slot_id: hex(file.strip_suffix(".slot")?)?,
            }),
            "events" => {
                let (client, seq) = file.strip_suffix(".evt")?.split_once('-')?;
                Some(FileName::Event {
                    client_id: hex(client)?,
                    seq: u64::from_be_bytes(hex::<8>(seq)?),
                })
            }
            "snapshots" => Some(FileName::Snapshot {
                snapshot_id: hex(file.strip_suffix(".snap")?)?,
            }),
            _ => None,
        }
    }

    pub fn to_path(&self) -> String {
        match self {
            FileName::VaultInfo => "strata-vault".into(),
            FileName::Epoch { epoch, creator } => {
                format!("epochs/{epoch:08x}-{}.epoch", to_hex(creator))
            }
            FileName::Slot { slot_id } => format!("slots/{}.slot", to_hex(slot_id)),
            FileName::Event { client_id, seq } => {
                format!("events/{}-{seq:016x}.evt", to_hex(client_id))
            }
            FileName::Snapshot { snapshot_id } => {
                format!("snapshots/{}.snap", to_hex(snapshot_id))
            }
        }
    }

    /// A file's contents must match its name (spec §5).
    pub fn expect(&self, from_contents: FileName) -> Result<()> {
        if *self != from_contents {
            return Err(CoreError::rejected(
                "vault file",
                "contents don't match the file name",
            ));
        }
        Ok(())
    }
}

/// Exactly `2 * N` lowercase hex digits.
fn hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = s.as_bytes();
    if bytes.len() != 2 * N {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        out[i] = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let names = [
            FileName::VaultInfo,
            FileName::Epoch {
                epoch: 0x0102,
                creator: [0xab; 16],
            },
            FileName::Slot { slot_id: [1; 16] },
            FileName::Event {
                client_id: [2; 16],
                seq: 0x1_0000_0001,
            },
            FileName::Snapshot {
                snapshot_id: [3; 16],
            },
        ];
        for name in names {
            assert_eq!(FileName::parse(&name.to_path()), Some(name), "{name:?}");
        }
        assert_eq!(
            FileName::Event {
                client_id: [0xab; 16],
                seq: 26
            }
            .to_path(),
            "events/abababababababababababababababab-000000000000001a.evt"
        );
    }

    #[test]
    fn ignores_anything_else() {
        let id = "ab".repeat(16);
        for path in [
            "strata-vault.tmp".to_string(),
            format!(".tmp-{id}"),
            format!("events/{id}-000000000000001a.evt.tmp"),
            format!("events/.{id}-000000000000001a.evt"),
            format!("events/{id}-000000000000001a (1).evt"),
            format!("events/{}-000000000000001a.evt", id.to_uppercase()),
            format!("events/{id}-1a.evt"),
            format!("events/{id}000000000000001a.evt"),
            format!("slots/{id}.evt"),
            format!("slots/{}.slot", &id[..30]),
            format!("epochs/0000000g-{id}.epoch"),
            format!("other/{id}.slot"),
            format!("events/sub/{id}-000000000000001a.evt"),
        ] {
            assert_eq!(FileName::parse(&path), None, "{path}");
        }
    }
}
