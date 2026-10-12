//! Slot files (spec §6.2): `slots/<slotId>.slot` for synced slots (kinds 1–3,
//! magic `STSL`) and local slot records (kind 4, magic `STLS`, spec §11).

use super::{Id, check_vault_id, read_preamble, write_preamble};
use crate::crypto::aead::{self, NONCE_LEN, TAG_LEN};
use crate::crypto::kdf::Argon2Params;
use crate::crypto::recovery::{self, ENC_LEN, PUBLIC_KEY_LEN, RecoveryKeyPair};
use crate::crypto::{SecretKey, aead::random_nonce};
use crate::encoding::Reader;
use crate::error::{CoreError, Result};
use crate::format::names::FileName;
use crate::policy::SlotScope;

pub const SYNCED_MAGIC: &[u8; 4] = b"STSL";
pub const LOCAL_MAGIC: &[u8; 4] = b"STLS";
pub const MAX_PARAMS_LEN: usize = 2048;
const HEADER_LEN: usize = 47;
const WRAPPED_LEN: usize = SecretKey::LEN + TAG_LEN;
const WHAT: &str = "slot";

pub const KIND_PASSWORD: u8 = 1;
pub const KIND_RECOVERY: u8 = 2;
pub const KIND_FIDO2: u8 = 3;
pub const KIND_PLATFORM: u8 = 4;

/// Protector IDs for platform slots (spec §11).
pub const PROTECTOR_IDS: std::ops::RangeInclusive<u8> = 1..=5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotParams {
    Password {
        argon: Argon2Params,
        salt: [u8; 16],
    },
    Recovery {
        pk: Box<[u8; PUBLIC_KEY_LEN]>,
        anchor_epoch: u32,
        anchor_tag: [u8; 32],
    },
    Fido2 {
        salt: [u8; 32],
        credential_id: Vec<u8>,
    },
    Platform {
        protector_id: u8,
        blob: Vec<u8>,
    },
}

impl SlotParams {
    pub fn kind(&self) -> u8 {
        match self {
            SlotParams::Password { .. } => KIND_PASSWORD,
            SlotParams::Recovery { .. } => KIND_RECOVERY,
            SlotParams::Fido2 { .. } => KIND_FIDO2,
            SlotParams::Platform { .. } => KIND_PLATFORM,
        }
    }

    fn scope(&self) -> SlotScope {
        match self {
            SlotParams::Platform { .. } => SlotScope::Local,
            _ => SlotScope::Synced,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            SlotParams::Password { argon, salt } => {
                out.extend_from_slice(&argon.m_kib.to_le_bytes());
                out.extend_from_slice(&argon.t.to_le_bytes());
                out.extend_from_slice(&argon.p.to_le_bytes());
                out.extend_from_slice(salt);
            }
            SlotParams::Recovery {
                pk,
                anchor_epoch,
                anchor_tag,
            } => {
                out.extend_from_slice(pk.as_slice());
                out.extend_from_slice(&anchor_epoch.to_le_bytes());
                out.extend_from_slice(anchor_tag);
            }
            SlotParams::Fido2 {
                salt,
                credential_id,
            } => {
                out.extend_from_slice(salt);
                out.extend_from_slice(&(credential_id.len() as u16).to_le_bytes());
                out.extend_from_slice(credential_id);
            }
            SlotParams::Platform { protector_id, blob } => {
                out.push(*protector_id);
                out.extend_from_slice(&(blob.len() as u16).to_le_bytes());
                out.extend_from_slice(blob);
            }
        }
        out
    }

    fn parse(kind: u8, bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, "slot params");
        let params = match kind {
            KIND_PASSWORD => {
                let argon = Argon2Params {
                    m_kib: r.u32_le()?,
                    t: r.u32_le()?,
                    p: r.u32_le()?,
                };
                argon.validate()?;
                SlotParams::Password {
                    argon,
                    salt: r.array()?,
                }
            }
            KIND_RECOVERY => SlotParams::Recovery {
                pk: Box::new(r.array()?),
                anchor_epoch: r.u32_le()?,
                anchor_tag: r.array()?,
            },
            KIND_FIDO2 => {
                let salt = r.array()?;
                let len = r.u16_le()? as usize;
                if !(1..=1023).contains(&len) {
                    return Err(CoreError::rejected(
                        WHAT,
                        "credential ID length out of range",
                    ));
                }
                SlotParams::Fido2 {
                    salt,
                    credential_id: r.take(len)?.to_vec(),
                }
            }
            KIND_PLATFORM => {
                let protector_id = r.u8()?;
                if !PROTECTOR_IDS.contains(&protector_id) {
                    return Err(CoreError::rejected(WHAT, "unknown protector"));
                }
                let len = r.u16_le()? as usize;
                SlotParams::Platform {
                    protector_id,
                    blob: r.take(len)?.to_vec(),
                }
            }
            _ => return Err(CoreError::rejected(WHAT, "unknown slot kind")),
        };
        r.finish()?;
        Ok(params)
    }
}

/// A parsed slot. Keeps the file bytes, because the AAD is a range of them.
#[derive(Debug)]
pub struct SlotFile<'a> {
    pub vault_id: Id,
    pub slot_id: Id,
    pub epoch: u32,
    pub params: SlotParams,
    bytes: &'a [u8],
    params_end: usize,
}

impl<'a> SlotFile<'a> {
    /// Parses a slot. `scope` says where it was found: `slots/` (synced) or local
    /// state. Kind 4 is accepted only locally, kinds 1–3 only as synced files.
    pub fn parse(bytes: &'a [u8], vault_id: &Id, scope: SlotScope) -> Result<Self> {
        let magic = match scope {
            SlotScope::Synced => SYNCED_MAGIC,
            SlotScope::Local => LOCAL_MAGIC,
        };
        let mut r = Reader::new(bytes, WHAT);
        read_preamble(&mut r, magic, WHAT)?;
        let found_vault: Id = r.array()?;
        check_vault_id(&found_vault, vault_id, WHAT)?;
        let slot_id = r.array()?;
        let epoch = r.u32_le()?;
        let kind = r.u8()?;
        let params_len = r.u16_le()? as usize;
        if params_len > MAX_PARAMS_LEN {
            return Err(CoreError::rejected(WHAT, "params too long"));
        }
        let params = SlotParams::parse(kind, r.take(params_len)?)?;
        if params.scope() != scope {
            return Err(CoreError::rejected(WHAT, "slot kind not allowed here"));
        }
        let params_end = r.position();
        let wrap_len = if kind == KIND_RECOVERY {
            ENC_LEN + WRAPPED_LEN
        } else {
            NONCE_LEN + WRAPPED_LEN
        };
        r.take(wrap_len)?;
        r.finish()?;
        Ok(Self {
            vault_id: found_vault,
            slot_id,
            epoch,
            params,
            bytes,
            params_end,
        })
    }

    pub fn file_name(&self) -> FileName {
        FileName::Slot {
            slot_id: self.slot_id,
        }
    }

    /// Unwraps the epoch key with a KEK derived from the slot secret (kinds 1, 3, 4).
    pub fn open_with_kek(&self, kek: &SecretKey) -> Result<SecretKey> {
        if self.params.kind() == KIND_RECOVERY {
            return Err(CoreError::rejected(
                WHAT,
                "recovery slots need the recovery key",
            ));
        }
        let nonce_end = self.params_end + NONCE_LEN;
        let nonce = self.bytes[self.params_end..nonce_end].try_into().unwrap();
        let pt = aead::open(
            kek,
            &nonce,
            &self.bytes[nonce_end..],
            &self.bytes[..nonce_end],
            WHAT,
        )?;
        SecretKey::from_slice(pt.expose())
    }

    /// Unwraps the epoch key from a recovery slot (kind 2). The anchor is checked
    /// separately, against the key chain (spec §6.2.1).
    pub fn open_recovery(&self, keypair: &RecoveryKeyPair) -> Result<SecretKey> {
        let SlotParams::Recovery { pk, .. } = &self.params else {
            return Err(CoreError::rejected(WHAT, "not a recovery slot"));
        };
        if pk.as_slice() != keypair.public_key() {
            return Err(CoreError::rejected(
                WHAT,
                "recovery key doesn't match this slot",
            ));
        }
        let enc_end = self.params_end + ENC_LEN;
        keypair.open(
            &self.bytes[self.params_end..enc_end],
            &self.bytes[enc_end..],
            &self.bytes[..self.params_end],
        )
    }
}

fn header(vault_id: &Id, slot_id: &Id, epoch: u32, params: &SlotParams) -> Result<Vec<u8>> {
    let encoded = params.encode();
    if encoded.len() > MAX_PARAMS_LEN {
        return Err(CoreError::rejected(WHAT, "params too long"));
    }
    let mut out = Vec::with_capacity(HEADER_LEN + encoded.len() + ENC_LEN + WRAPPED_LEN);
    let magic = match params.scope() {
        SlotScope::Synced => SYNCED_MAGIC,
        SlotScope::Local => LOCAL_MAGIC,
    };
    write_preamble(&mut out, magic);
    out.extend_from_slice(vault_id);
    out.extend_from_slice(slot_id);
    out.extend_from_slice(&epoch.to_le_bytes());
    out.push(params.kind());
    out.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
    out.extend_from_slice(&encoded);
    Ok(out)
}

/// Writes a password, FIDO2 or platform slot wrapping `ek` under `kek`.
pub fn seal_with_kek(
    vault_id: &Id,
    slot_id: &Id,
    epoch: u32,
    params: &SlotParams,
    kek: &SecretKey,
    ek: &SecretKey,
) -> Result<Vec<u8>> {
    seal_with_kek_and_nonce(vault_id, slot_id, epoch, params, kek, ek, &random_nonce()?)
}

/// `seal_with_kek` with a fixed nonce, for test vectors.
pub fn seal_with_kek_and_nonce(
    vault_id: &Id,
    slot_id: &Id,
    epoch: u32,
    params: &SlotParams,
    kek: &SecretKey,
    ek: &SecretKey,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    if params.kind() == KIND_RECOVERY {
        return Err(CoreError::rejected(
            WHAT,
            "recovery slots are sealed to a public key",
        ));
    }
    let mut out = header(vault_id, slot_id, epoch, params)?;
    out.extend_from_slice(nonce);
    let ct = aead::seal(kek, nonce, ek.expose(), &out);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Writes a recovery slot: `ek` sealed to the slot's X-Wing public key.
pub fn seal_recovery(
    vault_id: &Id,
    slot_id: &Id,
    epoch: u32,
    params: &SlotParams,
    ek: &SecretKey,
    randomness: Option<&[u8; recovery::ENCAP_RANDOMNESS_LEN]>,
) -> Result<Vec<u8>> {
    let SlotParams::Recovery { pk, .. } = params else {
        return Err(CoreError::rejected(WHAT, "not a recovery slot"));
    };
    let mut out = header(vault_id, slot_id, epoch, params)?;
    let (enc, ct) = match randomness {
        Some(r) => recovery::seal_with_randomness(pk.as_slice(), &out, ek, r)?,
        None => recovery::seal(pk.as_slice(), &out, ek)?,
    };
    out.extend_from_slice(&enc);
    out.extend_from_slice(&ct);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: Id = [1; 16];

    fn key(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }

    fn password_params() -> SlotParams {
        SlotParams::Password {
            argon: Argon2Params::DEFAULT,
            salt: [4; 16],
        }
    }

    #[test]
    fn kek_slots_round_trip() {
        let cases = [
            (password_params(), SlotScope::Synced),
            (
                SlotParams::Fido2 {
                    salt: [5; 32],
                    credential_id: vec![6; 70],
                },
                SlotScope::Synced,
            ),
            (
                SlotParams::Platform {
                    protector_id: 2,
                    blob: vec![7; 300],
                },
                SlotScope::Local,
            ),
        ];
        for (params, scope) in cases {
            let bytes = seal_with_kek(&VAULT, &[2; 16], 3, &params, &key(8), &key(9)).unwrap();
            let slot = SlotFile::parse(&bytes, &VAULT, scope).unwrap();
            assert_eq!(slot.params, params);
            assert_eq!((slot.slot_id, slot.epoch), ([2; 16], 3));
            assert_eq!(slot.open_with_kek(&key(8)).unwrap(), key(9));
            assert!(slot.open_with_kek(&key(10)).is_err());
        }
    }

    #[test]
    fn recovery_slot_round_trip() {
        let r = key(3);
        let kp = RecoveryKeyPair::derive(&r);
        let params = SlotParams::Recovery {
            pk: Box::new(*kp.public_key()),
            anchor_epoch: 0,
            anchor_tag: [0; 32],
        };
        let bytes = seal_recovery(&VAULT, &[2; 16], 0, &params, &key(9), None).unwrap();
        let slot = SlotFile::parse(&bytes, &VAULT, SlotScope::Synced).unwrap();
        assert_eq!(slot.open_recovery(&kp).unwrap(), key(9));
        assert!(
            slot.open_recovery(&RecoveryKeyPair::derive(&key(4)))
                .is_err()
        );
        assert!(slot.open_with_kek(&key(9)).is_err());
    }

    #[test]
    fn rejects_moved_tampered_or_misplaced_slots() {
        let bytes =
            seal_with_kek(&VAULT, &[2; 16], 3, &password_params(), &key(8), &key(9)).unwrap();
        // Another vault.
        assert!(SlotFile::parse(&bytes, &[9; 16], SlotScope::Synced).is_err());
        // Every single-bit change breaks parsing or authentication.
        for i in 0..bytes.len() {
            for bit in 0..8 {
                let mut bad = bytes.clone();
                bad[i] ^= 1 << bit;
                let ok = SlotFile::parse(&bad, &VAULT, SlotScope::Synced)
                    .and_then(|s| s.open_with_kek(&key(8)));
                assert!(ok.is_err(), "byte {i} bit {bit}");
            }
        }
        // A synced file read as a local slot, and the reverse.
        assert!(SlotFile::parse(&bytes, &VAULT, SlotScope::Local).is_err());
        let local = seal_with_kek(
            &VAULT,
            &[2; 16],
            3,
            &SlotParams::Platform {
                protector_id: 1,
                blob: vec![1],
            },
            &key(8),
            &key(9),
        )
        .unwrap();
        assert!(SlotFile::parse(&local, &VAULT, SlotScope::Synced).is_err());
        // Out-of-bounds Argon2 parameters are rejected while parsing.
        let weak = SlotParams::Password {
            argon: Argon2Params {
                m_kib: 1024,
                ..Argon2Params::DEFAULT
            },
            salt: [0; 16],
        };
        let weak_bytes = seal_with_kek(&VAULT, &[2; 16], 3, &weak, &key(8), &key(9)).unwrap();
        assert!(SlotFile::parse(&weak_bytes, &VAULT, SlotScope::Synced).is_err());
    }
}
