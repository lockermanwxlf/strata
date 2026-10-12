//! Snapshot files (spec §10.1): `snapshots/<snapshotId>.snap`.

use super::body::SnapshotBody;
use super::{
    Id, check_max_len, check_vault_id, open_body, read_preamble, seal_body_and_sign,
    split_signature, write_preamble,
};
use crate::crypto::SecretKey;
use crate::crypto::aead::{NONCE_LEN, TAG_LEN, random_nonce};
use crate::crypto::sign::{self, DeviceKey, SIGNATURE_LEN};
use crate::encoding::{Reader, cbor};
use crate::error::{CoreError, Result};
use crate::format::names::FileName;

pub const MAGIC: &[u8; 4] = b"STSN";
pub const HEADER_LEN: usize = 84;
pub const MAX_FILE_LEN: usize = 64 * 1024 * 1024;
const MIN_FILE_LEN: usize = HEADER_LEN + 256 + TAG_LEN + SIGNATURE_LEN;
const WHAT: &str = "snapshot";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotHeader {
    pub vault_id: Id,
    pub snapshot_id: Id,
    pub creator: Id,
    pub epoch: u32,
}

impl SnapshotHeader {
    pub fn file_name(&self) -> FileName {
        FileName::Snapshot {
            snapshot_id: self.snapshot_id,
        }
    }

    pub fn seal(
        &self,
        body: &SnapshotBody,
        snapshot_key: &SecretKey,
        device: &DeviceKey,
        nonce: Option<[u8; NONCE_LEN]>,
    ) -> Result<Vec<u8>> {
        body.validate()?;
        let encoded = cbor::encode(body);
        let mut out = Vec::with_capacity(HEADER_LEN);
        write_preamble(&mut out, MAGIC);
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.snapshot_id);
        out.extend_from_slice(&self.creator);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&match nonce {
            Some(n) => n,
            None => random_nonce()?,
        });
        let file = seal_body_and_sign(out, HEADER_LEN - NONCE_LEN, &encoded, snapshot_key, device)?;
        if file.len() > MAX_FILE_LEN {
            return Err(CoreError::rejected(WHAT, "snapshot too large"));
        }
        Ok(file)
    }
}

#[derive(Debug)]
pub struct SealedSnapshot<'a> {
    pub header: SnapshotHeader,
    nonce: [u8; NONCE_LEN],
    signed: &'a [u8],
    signature: [u8; SIGNATURE_LEN],
}

impl<'a> SealedSnapshot<'a> {
    pub fn parse(bytes: &'a [u8], vault_id: &Id) -> Result<Self> {
        check_max_len(bytes, MAX_FILE_LEN, WHAT)?;
        let (signed, signature) = split_signature(bytes, WHAT)?;
        let mut r = Reader::new(signed, WHAT);
        read_preamble(&mut r, MAGIC, WHAT)?;
        if bytes.len() < MIN_FILE_LEN {
            return Err(CoreError::rejected(WHAT, "truncated"));
        }
        let header = SnapshotHeader {
            vault_id: r.array()?,
            snapshot_id: r.array()?,
            creator: r.array()?,
            epoch: r.u32_le()?,
        };
        check_vault_id(&header.vault_id, vault_id, WHAT)?;
        Ok(Self {
            header,
            nonce: r.array()?,
            signed,
            signature,
        })
    }

    pub fn signature_valid(&self, creator_pk: &[u8; 32]) -> bool {
        sign::verify(creator_pk, self.signed, &self.signature)
    }

    pub fn open(&self, snapshot_key: &SecretKey) -> Result<SnapshotBody> {
        let (plaintext, range) = open_body(
            snapshot_key,
            &self.nonce,
            &self.signed[HEADER_LEN..],
            &self.signed[..HEADER_LEN],
            WHAT,
        )?;
        let body: SnapshotBody = cbor::decode_strict(&plaintext.expose()[range], "snapshot body")?;
        body.validate()?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::body::tests::{ALICE, BOB};
    use crate::format::body::{Dot, Op, RetainedOp, VectorClock};

    const VAULT: Id = [1; 16];

    fn key(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }

    pub(crate) fn sample_body() -> SnapshotBody {
        SnapshotBody {
            watermark: vec![(ALICE, 2, [0x21; 32]), (BOB, 1, [0x22; 32])],
            clocks: vec![VectorClock(vec![(ALICE, 2), (BOB, 1)])],
            ops: vec![RetainedOp {
                dot: Dot {
                    client_id: ALICE,
                    seq: 1,
                    op_index: 0,
                },
                hlc: 9,
                vc_index: 0,
                op: Op::RegisterDevice {
                    client_id: ALICE,
                    dev_pk: [0x11; 32],
                    name: "Laptop".into(),
                },
            }],
        }
    }

    #[test]
    fn round_trip_and_every_bit_flip_is_caught() {
        let device = DeviceKey::from_seed(&key(1));
        let header = SnapshotHeader {
            vault_id: VAULT,
            snapshot_id: [5; 16],
            creator: ALICE,
            epoch: 0,
        };
        let bytes = header.seal(&sample_body(), &key(2), &device, None).unwrap();
        let snap = SealedSnapshot::parse(&bytes, &VAULT).unwrap();
        assert_eq!(snap.header, header);
        assert!(snap.signature_valid(&device.public_key()));
        assert_eq!(snap.open(&key(2)).unwrap(), sample_body());

        let accepted = |b: &[u8]| {
            SealedSnapshot::parse(b, &VAULT)
                .is_ok_and(|s| s.signature_valid(&device.public_key()) && s.open(&key(2)).is_ok())
        };
        for i in 0..bytes.len() {
            for bit in 0..8 {
                let mut bad = bytes.clone();
                bad[i] ^= 1 << bit;
                assert!(!accepted(&bad), "byte {i} bit {bit}");
            }
        }
        assert!(SealedSnapshot::parse(&bytes, &[9; 16]).is_err());
    }
}
