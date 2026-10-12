//! Epoch records (spec §7.1): `epochs/<epoch:08x>-<creator>.epoch`.

use super::body::{MAX_CLOCK_ENTRIES, VectorClock};
use super::{Id, check_max_len, check_vault_id, read_preamble, split_signature, write_preamble};
use crate::crypto::SecretKey;
use crate::crypto::aead::{self, NONCE_LEN, TAG_LEN, random_nonce};
use crate::crypto::sign::{self, DeviceKey, SIGNATURE_LEN};
use crate::encoding::Reader;
use crate::error::{CoreError, Result};
use crate::format::names::FileName;

pub const MAGIC: &[u8; 4] = b"STEP";
const FIXED_LEN: usize = 78;
const CUTOVER_ENTRY_LEN: usize = 24;
const CHAIN_LEN: usize = NONCE_LEN + SecretKey::LEN + TAG_LEN;
pub const MAX_LEN: usize =
    FIXED_LEN + CUTOVER_ENTRY_LEN * MAX_CLOCK_ENTRIES + CHAIN_LEN + SIGNATURE_LEN;
const WHAT: &str = "epoch record";

#[derive(Debug)]
pub struct EpochRecord<'a> {
    pub vault_id: Id,
    pub epoch: u32,
    pub creator: Id,
    pub key_id: [u8; 32],
    /// The creator's applied vector clock at rotation (empty for epoch 0).
    pub cutover: VectorClock,
    signed: &'a [u8],
    signature: [u8; SIGNATURE_LEN],
    /// Offset of the chain wrap's nonce, for epochs above 0.
    chain_start: Option<usize>,
}

impl<'a> EpochRecord<'a> {
    pub fn parse(bytes: &'a [u8], vault_id: &Id) -> Result<Self> {
        check_max_len(bytes, MAX_LEN, WHAT)?;
        let (signed, signature) = split_signature(bytes, WHAT)?;
        let mut r = Reader::new(signed, WHAT);
        read_preamble(&mut r, MAGIC, WHAT)?;
        let found_vault: Id = r.array()?;
        check_vault_id(&found_vault, vault_id, WHAT)?;
        let epoch = r.u32_le()?;
        let creator = r.array()?;
        let key_id = r.array()?;
        let count = r.u16_le()? as usize;
        if count > MAX_CLOCK_ENTRIES {
            return Err(CoreError::rejected(WHAT, "too many cutover entries"));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push((r.array()?, r.u64_le()?));
        }
        let cutover = VectorClock(entries);
        cutover.validate(WHAT)?;
        let chain_start = if epoch == 0 {
            if !cutover.0.is_empty() {
                return Err(CoreError::rejected(WHAT, "epoch 0 has a cutover"));
            }
            None
        } else {
            let start = r.position();
            r.take(CHAIN_LEN)?;
            Some(start)
        };
        r.finish()?;
        Ok(Self {
            vault_id: found_vault,
            epoch,
            creator,
            key_id,
            cutover,
            signed,
            signature,
            chain_start,
        })
    }

    pub fn file_name(&self) -> FileName {
        FileName::Epoch {
            epoch: self.epoch,
            creator: self.creator,
        }
    }

    pub fn signature_valid(&self, creator_pk: &[u8; 32]) -> bool {
        sign::verify(creator_pk, self.signed, &self.signature)
    }

    /// Unwraps `EK_{epoch-1}` with `chain_key_epoch` (spec §7.1).
    pub fn open_chain(&self, chain_key: &SecretKey) -> Result<SecretKey> {
        let start = self
            .chain_start
            .ok_or(CoreError::rejected(WHAT, "epoch 0 has no previous key"))?;
        let nonce_end = start + NONCE_LEN;
        let nonce = self.signed[start..nonce_end].try_into().unwrap();
        let pt = aead::open(
            chain_key,
            &nonce,
            &self.signed[nonce_end..],
            &self.signed[..nonce_end],
            WHAT,
        )?;
        SecretKey::from_slice(pt.expose())
    }
}

/// What a rotation adds to a new epoch record: the previous epoch key, wrapped
/// under this epoch's chain key.
pub struct ChainWrap<'k> {
    pub chain_key: &'k SecretKey,
    pub prev_epoch_key: &'k SecretKey,
    /// Fixed for test vectors; `None` reads a fresh one from the OS.
    pub nonce: Option<[u8; NONCE_LEN]>,
}

pub struct NewEpoch<'a> {
    pub vault_id: Id,
    pub epoch: u32,
    pub creator: Id,
    pub key_id: [u8; 32],
    pub cutover: &'a VectorClock,
    pub chain: Option<ChainWrap<'a>>,
}

impl NewEpoch<'_> {
    pub fn seal(&self, device: &DeviceKey) -> Result<Vec<u8>> {
        if (self.epoch == 0) != self.chain.is_none() {
            return Err(CoreError::rejected(
                WHAT,
                "only epochs above 0 carry a chain wrap",
            ));
        }
        if self.epoch == 0 && !self.cutover.0.is_empty() {
            return Err(CoreError::rejected(WHAT, "epoch 0 has a cutover"));
        }
        self.cutover.validate(WHAT)?;
        let mut out =
            Vec::with_capacity(MAX_LEN.min(
                FIXED_LEN + CUTOVER_ENTRY_LEN * self.cutover.0.len() + CHAIN_LEN + SIGNATURE_LEN,
            ));
        write_preamble(&mut out, MAGIC);
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.creator);
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&(self.cutover.0.len() as u16).to_le_bytes());
        for (client, seq) in &self.cutover.0 {
            out.extend_from_slice(client);
            out.extend_from_slice(&seq.to_le_bytes());
        }
        if let Some(chain) = &self.chain {
            let nonce = match chain.nonce {
                Some(n) => n,
                None => random_nonce()?,
            };
            out.extend_from_slice(&nonce);
            let ct = aead::seal(chain.chain_key, &nonce, chain.prev_epoch_key.expose(), &out);
            out.extend_from_slice(&ct);
        }
        let signature = device.sign(&out);
        out.extend_from_slice(&signature);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: Id = [1; 16];

    fn key(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }

    #[test]
    fn epoch_zero_and_chained_epoch_round_trip() {
        let device = DeviceKey::from_seed(&key(1));
        let empty = VectorClock::default();
        let zero = NewEpoch {
            vault_id: VAULT,
            epoch: 0,
            creator: [2; 16],
            key_id: [3; 32],
            cutover: &empty,
            chain: None,
        }
        .seal(&device)
        .unwrap();
        let rec = EpochRecord::parse(&zero, &VAULT).unwrap();
        assert_eq!((rec.epoch, rec.key_id), (0, [3; 32]));
        assert!(rec.signature_valid(&device.public_key()));
        assert!(rec.open_chain(&key(5)).is_err());

        let cutover = VectorClock(vec![([2; 16], 4), ([7; 16], 1)]);
        let one = NewEpoch {
            vault_id: VAULT,
            epoch: 1,
            creator: [2; 16],
            key_id: [4; 32],
            cutover: &cutover,
            chain: Some(ChainWrap {
                chain_key: &key(5),
                prev_epoch_key: &key(6),
                nonce: None,
            }),
        }
        .seal(&device)
        .unwrap();
        let rec = EpochRecord::parse(&one, &VAULT).unwrap();
        assert_eq!(rec.cutover, cutover);
        assert_eq!(rec.open_chain(&key(5)).unwrap(), key(6));
        assert!(rec.open_chain(&key(7)).is_err());
        assert!(!rec.signature_valid(&DeviceKey::from_seed(&key(2)).public_key()));
    }

    #[test]
    fn every_bit_flip_is_caught() {
        let device = DeviceKey::from_seed(&key(1));
        let cutover = VectorClock(vec![([2; 16], 4)]);
        let bytes = NewEpoch {
            vault_id: VAULT,
            epoch: 1,
            creator: [2; 16],
            key_id: [4; 32],
            cutover: &cutover,
            chain: Some(ChainWrap {
                chain_key: &key(5),
                prev_epoch_key: &key(6),
                nonce: None,
            }),
        }
        .seal(&device)
        .unwrap();
        for i in 0..bytes.len() {
            for bit in 0..8 {
                let mut bad = bytes.clone();
                bad[i] ^= 1 << bit;
                let accepted = EpochRecord::parse(&bad, &VAULT).is_ok_and(|r| {
                    r.signature_valid(&device.public_key()) && r.open_chain(&key(5)).is_ok()
                });
                assert!(!accepted, "byte {i} bit {bit}");
            }
        }
    }
}
