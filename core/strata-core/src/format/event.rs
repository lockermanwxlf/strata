//! Event files (spec §8.1): `events/<clientId>-<seq:016x>.evt`.
//!
//! Reading is two steps, matching spec §9.1: `parse` reads the cleartext header
//! (so the caller can pick the epoch key and the signer's public key), then `open`
//! decrypts and validates the body and `signature_valid` checks the signature.

use super::body::EventBody;
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

pub const MAGIC: &[u8; 4] = b"STEV";
pub const HEADER_LEN: usize = 76;
pub const MAX_FILE_LEN: usize = 2 * 1024 * 1024;
pub const MAX_BODY_LEN: usize = 1024 * 1024;
const MIN_FILE_LEN: usize = HEADER_LEN + 256 + TAG_LEN + SIGNATURE_LEN;
const WHAT: &str = "event";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventHeader {
    pub vault_id: Id,
    pub client_id: Id,
    pub seq: u64,
    pub epoch: u32,
}

impl EventHeader {
    pub fn file_name(&self) -> FileName {
        FileName::Event {
            client_id: self.client_id,
            seq: self.seq,
        }
    }

    /// Encrypts and signs an event. `body` is validated first, so this never writes
    /// an event that readers would reject.
    pub fn seal(
        &self,
        body: &EventBody,
        event_key: &SecretKey,
        device: &DeviceKey,
        nonce: Option<[u8; NONCE_LEN]>,
    ) -> Result<Vec<u8>> {
        if self.seq == 0 {
            return Err(CoreError::rejected(WHAT, "seq starts at 1"));
        }
        body.validate(&self.client_id, self.seq)?;
        let encoded = cbor::encode(body);
        if encoded.len() > MAX_BODY_LEN {
            return Err(CoreError::rejected(WHAT, "body too large"));
        }
        let mut out = Vec::with_capacity(HEADER_LEN);
        write_preamble(&mut out, MAGIC);
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.client_id);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&match nonce {
            Some(n) => n,
            None => random_nonce()?,
        });
        seal_body_and_sign(out, HEADER_LEN - NONCE_LEN, &encoded, event_key, device)
    }
}

/// An event whose header has been parsed but whose body hasn't been decrypted.
#[derive(Debug)]
pub struct SealedEvent<'a> {
    pub header: EventHeader,
    nonce: [u8; NONCE_LEN],
    signed: &'a [u8],
    signature: [u8; SIGNATURE_LEN],
}

impl<'a> SealedEvent<'a> {
    pub fn parse(bytes: &'a [u8], vault_id: &Id) -> Result<Self> {
        check_max_len(bytes, MAX_FILE_LEN, WHAT)?;
        let (signed, signature) = split_signature(bytes, WHAT)?;
        let mut r = Reader::new(signed, WHAT);
        read_preamble(&mut r, MAGIC, WHAT)?;
        if bytes.len() < MIN_FILE_LEN {
            return Err(CoreError::rejected(WHAT, "truncated"));
        }
        let header = EventHeader {
            vault_id: r.array()?,
            client_id: r.array()?,
            seq: r.u64_le()?,
            epoch: r.u32_le()?,
        };
        check_vault_id(&header.vault_id, vault_id, WHAT)?;
        if header.seq == 0 {
            return Err(CoreError::rejected(WHAT, "seq starts at 1"));
        }
        Ok(Self {
            header,
            nonce: r.array()?,
            signed,
            signature,
        })
    }

    /// The bytes the signature covers. `H(c, s)` is SHA-256 over these plus the signature.
    pub fn signed_bytes(&self) -> &'a [u8] {
        self.signed
    }

    pub fn signature_valid(&self, dev_pk: &[u8; 32]) -> bool {
        sign::verify(dev_pk, self.signed, &self.signature)
    }

    /// Decrypts, unpads, decodes and validates the body (spec §9.1 steps 2 and 4).
    pub fn open(&self, event_key: &SecretKey) -> Result<EventBody> {
        let (plaintext, range) = open_body(
            event_key,
            &self.nonce,
            &self.signed[HEADER_LEN..],
            &self.signed[..HEADER_LEN],
            WHAT,
        )?;
        if range.len() > MAX_BODY_LEN {
            return Err(CoreError::rejected(WHAT, "body too large"));
        }
        let body: EventBody = cbor::decode_strict(&plaintext.expose()[range], "event body")?;
        body.validate(&self.header.client_id, self.header.seq)?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::padding;
    use crate::format::body::Op;
    use crate::format::body::tests::{ALICE, sample_first_event};

    const VAULT: Id = [1; 16];

    fn key(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }

    fn header() -> EventHeader {
        EventHeader {
            vault_id: VAULT,
            client_id: ALICE,
            seq: 1,
            epoch: 0,
        }
    }

    fn sealed() -> (Vec<u8>, DeviceKey) {
        let device = DeviceKey::from_seed(&key(1));
        let bytes = header()
            .seal(&sample_first_event(), &key(2), &device, None)
            .unwrap();
        (bytes, device)
    }

    /// Accepted means: parses, decrypts, validates, and the signature verifies.
    fn accepted(bytes: &[u8], device: &DeviceKey) -> bool {
        SealedEvent::parse(bytes, &VAULT)
            .is_ok_and(|e| e.signature_valid(&device.public_key()) && e.open(&key(2)).is_ok())
    }

    #[test]
    fn round_trip() {
        let (bytes, device) = sealed();
        let event = SealedEvent::parse(&bytes, &VAULT).unwrap();
        assert_eq!(event.header, header());
        assert!(event.signature_valid(&device.public_key()));
        assert_eq!(event.open(&key(2)).unwrap(), sample_first_event());
        assert!(event.open(&key(3)).is_err());
    }

    #[test]
    fn every_bit_flip_is_caught() {
        let (bytes, device) = sealed();
        for i in 0..bytes.len() {
            for bit in 0..8 {
                let mut bad = bytes.clone();
                bad[i] ^= 1 << bit;
                assert!(!accepted(&bad, &device), "byte {i} bit {bit}");
            }
        }
        assert!(!accepted(&bytes[..bytes.len() - 1], &device));
    }

    #[test]
    fn name_and_vault_must_match() {
        let (bytes, _) = sealed();
        assert!(SealedEvent::parse(&bytes, &[9; 16]).is_err());
        let event = SealedEvent::parse(&bytes, &VAULT).unwrap();
        let renamed = FileName::Event {
            client_id: ALICE,
            seq: 2,
        };
        assert!(renamed.expect(event.header.file_name()).is_err());
        let right = FileName::parse(&event.header.file_name().to_path()).unwrap();
        right.expect(event.header.file_name()).unwrap();
    }

    #[test]
    fn signature_from_another_device_fails() {
        let (bytes, _) = sealed();
        let other = DeviceKey::from_seed(&key(9));
        let event = SealedEvent::parse(&bytes, &VAULT).unwrap();
        assert!(!event.signature_valid(&other.public_key()));
    }

    /// Seals arbitrary plaintext with a correct header, AAD and signature, so the
    /// only thing wrong is the plaintext itself.
    fn seal_raw_plaintext(plaintext: &[u8], device: &DeviceKey) -> Vec<u8> {
        let mut out = Vec::new();
        write_preamble(&mut out, MAGIC);
        out.extend_from_slice(&VAULT);
        out.extend_from_slice(&ALICE);
        out.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&[7; NONCE_LEN]);
        let ct = crate::crypto::aead::seal(&key(2), &[7; NONCE_LEN], plaintext, &out);
        out.extend_from_slice(&ct);
        let sig = device.sign(&out);
        out.extend_from_slice(&sig);
        out
    }

    #[test]
    fn rejects_bad_plaintext_even_when_authentic() {
        let device = DeviceKey::from_seed(&key(1));
        let body = cbor::encode(&sample_first_event());

        // Nonzero padding.
        let mut padded = padding::pad(&body).unwrap().to_vec();
        *padded.last_mut().unwrap() = 1;
        assert!(!accepted(&seal_raw_plaintext(&padded, &device), &device));

        // Non-canonical CBOR: an hlc of 5 written as an 8-byte integer.
        let small = EventBody {
            hlc: 5,
            ..sample_first_event()
        };
        let mut non_canonical = cbor::encode(&small).to_vec();
        assert_eq!(&non_canonical[..3], &[0xa4, 0x01, 0x05]);
        non_canonical.splice(2..3, [0x1b, 0, 0, 0, 0, 0, 0, 0, 5]);
        let padded = padding::pad(&non_canonical).unwrap();
        assert!(!accepted(&seal_raw_plaintext(&padded, &device), &device));

        // A well-formed body that breaks a rule (seq 1 without RegisterDevice).
        let mut invalid = sample_first_event();
        invalid.ops.remove(0);
        let padded = padding::pad(&cbor::encode(&invalid)).unwrap();
        assert!(!accepted(&seal_raw_plaintext(&padded, &device), &device));

        // And the control: the same path with a good body is accepted.
        let padded = padding::pad(&body).unwrap();
        assert!(accepted(&seal_raw_plaintext(&padded, &device), &device));
    }

    #[test]
    fn refuses_to_write_invalid_events() {
        let device = DeviceKey::from_seed(&key(1));
        let mut body = sample_first_event();
        body.ops.push(Op::RegisterDevice {
            client_id: ALICE,
            dev_pk: [0; 32],
            name: "again".into(),
        });
        assert!(header().seal(&body, &key(2), &device, None).is_err());
        let zero_seq = EventHeader { seq: 0, ..header() };
        assert!(
            zero_seq
                .seal(&sample_first_event(), &key(2), &device, None)
                .is_err()
        );
    }

    #[test]
    fn newer_version_is_update_required() {
        let (mut bytes, _) = sealed();
        bytes[4] = 2;
        assert!(matches!(
            SealedEvent::parse(&bytes, &VAULT),
            Err(CoreError::UpdateRequired { found: 2 })
        ));
    }
}
