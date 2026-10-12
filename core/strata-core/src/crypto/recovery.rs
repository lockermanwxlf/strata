//! The recovery key and its slot (spec §6.2.1): BIP39 words, the X-Wing key pair,
//! HPKE wrap/unwrap of the epoch key, and the recovery anchor.

use hmac::{Hmac, KeyInit, Mac};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::rand_core::{TryCryptoRng, TryRng};
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::kdf::{hkdf, label};
use super::{SecretBytes, SecretKey, fill_random};
use crate::error::{CoreError, Result};

/// HPKE `info` for recovery slots.
pub const HPKE_INFO: &[u8] = b"strata v1 recovery-slot";
const ANCHOR_PREFIX: &[u8] = b"strata v1 recovery-anchor";

pub const PUBLIC_KEY_LEN: usize = 1216;
pub const ENC_LEN: usize = 1120;
/// Random bytes X-Wing consumes per encapsulation.
pub const ENCAP_RANDOMNESS_LEN: usize = 64;
pub const WORD_COUNT: usize = 24;

type Kem = XWing;

/// A fresh 256-bit recovery key `R` from the OS CSPRNG.
pub fn generate() -> Result<SecretKey> {
    SecretKey::generate()
}

/// `R` as 24 space-separated BIP39 English words (spec §6.2.1), as UTF-8 bytes so the
/// UI can show them without ever holding them in a string type it can't wipe.
pub fn to_words(r: &SecretKey) -> SecretBytes {
    let mnemonic = bip39::Mnemonic::from_entropy(r.expose())
        .expect("32 bytes is a valid BIP39 entropy length");
    let mut out = Vec::with_capacity(WORD_COUNT * 9);
    for (i, word) in mnemonic.words().enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        out.extend_from_slice(word.as_bytes());
    }
    SecretBytes::new(out)
}

/// Why the words the user typed don't decode. The UI turns these into specific help.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WordsError {
    #[error("a recovery key has 24 words; this has {0}")]
    WrongCount(usize),
    #[error("word {0} isn't in the recovery word list")]
    UnknownWord(usize),
    #[error("the words don't match; one may be mistyped or out of order")]
    BadChecksum,
}

/// Parses words typed by the user. Case and extra whitespace don't matter.
pub fn from_words(input: &[u8]) -> Result<SecretKey, WordsError> {
    // The English word list is lowercase ASCII, so lowercasing ASCII is the only
    // normalization needed. Anything else simply fails to match a word.
    // Each input byte becomes one char of at most 2 UTF-8 bytes; reserving that up
    // front means the buffer never reallocates and leaves a copy of the words behind.
    let mut cleaned = Zeroizing::new(String::with_capacity(input.len() * 2));
    for (i, word) in input
        .split(|b| b.is_ascii_whitespace())
        .filter(|w| !w.is_empty())
        .enumerate()
    {
        if i > 0 {
            cleaned.push(' ');
        }
        for &b in word {
            cleaned.push(char::from(b.to_ascii_lowercase()));
        }
    }
    let count = cleaned.split(' ').filter(|w| !w.is_empty()).count();
    if count != WORD_COUNT {
        return Err(WordsError::WrongCount(count));
    }
    let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &cleaned)
        .map_err(|e| match e {
            bip39::Error::UnknownWord(i) => WordsError::UnknownWord(i + 1),
            bip39::Error::BadWordCount(n) => WordsError::WrongCount(n),
            _ => WordsError::BadChecksum,
        })?;
    let (mut entropy, len) = mnemonic.to_entropy_array();
    let key = SecretKey::from_slice(&entropy[..len]);
    entropy.zeroize();
    Ok(key.expect("24 words always decode to 32 bytes"))
}

/// The recovery slot's X-Wing key pair, derived from `R`.
pub struct RecoveryKeyPair {
    sk: <Kem as KemTrait>::PrivateKey,
    pk: Box<[u8; PUBLIC_KEY_LEN]>,
}

impl RecoveryKeyPair {
    /// `(sk, pk) = DeriveKeyPair(R)` (spec §6.2.1).
    pub fn derive(r: &SecretKey) -> Self {
        let (sk, pk) = Kem::derive_keypair(r.expose());
        let mut pk_bytes = Box::new([0u8; PUBLIC_KEY_LEN]);
        pk.write_exact(pk_bytes.as_mut_slice());
        Self { sk, pk: pk_bytes }
    }

    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.pk
    }

    /// Unwraps `EK` from a recovery slot. `aad` is the slot's header and params
    /// (spec §6.2: bytes `[0..47+P)`).
    pub fn open(&self, enc: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<SecretKey> {
        let reject = || CoreError::rejected("recovery slot", "authentication failed");
        let mut pt = open_base(&self.sk, enc, HPKE_INFO, ciphertext, aad).ok_or_else(reject)?;
        let key = SecretKey::from_slice(&pt);
        pt.zeroize();
        key.map_err(|_| reject())
    }
}

/// Wraps `EK` to a recovery public key. No `R` needed, which is what lets rotation
/// re-wrap the recovery slot (spec §7.2). Returns `(enc, ciphertext)`.
pub fn seal(pk: &[u8], aad: &[u8], ek: &SecretKey) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut randomness = Zeroizing::new([0u8; ENCAP_RANDOMNESS_LEN]);
    fill_random(randomness.as_mut_slice())?;
    seal_with_randomness(pk, aad, ek, &randomness)
}

/// `seal` with caller-supplied encapsulation randomness, so test vectors are
/// reproducible. Production code calls `seal`, which reads it from the OS.
pub fn seal_with_randomness(
    pk: &[u8],
    aad: &[u8],
    ek: &SecretKey,
    randomness: &[u8; ENCAP_RANDOMNESS_LEN],
) -> Result<(Vec<u8>, Vec<u8>)> {
    seal_base(pk, HPKE_INFO, ek.expose(), aad, randomness)
}

/// HPKE `SealBase` for the suite in spec §3, with fixed encapsulation randomness.
///
/// `pk` comes from a slot file on untrusted storage, so a key that parses but can't
/// be encapsulated to is rejected rather than trusted.
fn seal_base(
    pk: &[u8],
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    randomness: &[u8; ENCAP_RANDOMNESS_LEN],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let invalid = || CoreError::rejected("recovery slot", "invalid public key");
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(pk).map_err(|_| invalid())?;
    let mut rng = FixedRng {
        bytes: randomness,
        used: 0,
    };
    let (enc, ct) = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeS::Base,
        &pk,
        info,
        plaintext,
        aad,
        &mut rng,
    )
    .map_err(|_| invalid())?;
    assert_eq!(
        rng.used, ENCAP_RANDOMNESS_LEN,
        "X-Wing must consume exactly its encapsulation randomness"
    );
    Ok((enc.to_bytes().to_vec(), ct))
}

/// HPKE `OpenBase` for the suite in spec §3. `None` on any failure.
fn open_base(
    sk: &<Kem as KemTrait>::PrivateKey,
    enc: &[u8],
    info: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(enc).ok()?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base,
        sk,
        &enc,
        info,
        ciphertext,
        aad,
    )
    .ok()
}

/// The recovery anchor (spec §6.2.1). Computed only when `R` is generated, with
/// `anchor_epoch` set to the epoch current at that moment.
pub fn anchor_tag(
    r: &SecretKey,
    vault_id: &[u8; 16],
    anchor_epoch: u32,
    key_id: &[u8; 32],
    pk: &[u8],
) -> [u8; 32] {
    anchor_mac(r, vault_id, anchor_epoch, key_id, pk)
        .finalize()
        .into_bytes()
        .into()
}

/// Constant-time check of a slot's anchor against `R` and the real key chain.
pub fn verify_anchor(
    r: &SecretKey,
    vault_id: &[u8; 16],
    anchor_epoch: u32,
    key_id: &[u8; 32],
    pk: &[u8],
    tag: &[u8; 32],
) -> bool {
    anchor_mac(r, vault_id, anchor_epoch, key_id, pk)
        .verify_slice(tag)
        .is_ok()
}

fn anchor_mac(
    r: &SecretKey,
    vault_id: &[u8; 16],
    anchor_epoch: u32,
    key_id: &[u8; 32],
    pk: &[u8],
) -> Hmac<Sha256> {
    let anchor_key = hkdf(vault_id, r.expose(), label::RECOVERY_ANCHOR_KEY);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(anchor_key.expose())
        .expect("HMAC accepts any key length");
    mac.update(ANCHOR_PREFIX);
    mac.update(vault_id);
    mac.update(&anchor_epoch.to_le_bytes());
    mac.update(key_id);
    mac.update(pk);
    mac
}

/// Hands out a fixed buffer of randomness. Panics if asked for more than it holds:
/// that would mean the KEM's randomness use changed, and must never silently
/// yield predictable bytes.
struct FixedRng<'a> {
    bytes: &'a [u8; ENCAP_RANDOMNESS_LEN],
    used: usize,
}

impl TryRng for FixedRng<'_> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let end = self.used + dst.len();
        assert!(
            end <= self.bytes.len(),
            "encapsulation randomness exhausted"
        );
        dst.copy_from_slice(&self.bytes[self.used..end]);
        self.used = end;
        Ok(())
    }
}

impl TryCryptoRng for FixedRng<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }

    #[test]
    fn words_round_trip_and_tolerate_case_and_spacing() {
        let key = generate().unwrap();
        let words = to_words(&key);
        let text = std::str::from_utf8(words.expose()).unwrap();
        assert_eq!(text.split(' ').count(), WORD_COUNT);
        assert_eq!(from_words(words.expose()).unwrap(), key);
        let messy = format!("  {}\n", text.to_uppercase().replace(' ', "   \t"));
        assert_eq!(from_words(messy.as_bytes()).unwrap(), key);
    }

    #[test]
    fn words_errors_are_specific() {
        let words = to_words(&r(1));
        let text = std::str::from_utf8(words.expose()).unwrap().to_string();
        let mut list: Vec<&str> = text.split(' ').collect();

        assert_eq!(
            from_words(list[..23].join(" ").as_bytes()),
            Err(WordsError::WrongCount(23))
        );
        list[4] = "notaword";
        assert_eq!(
            from_words(list.join(" ").as_bytes()),
            Err(WordsError::UnknownWord(5))
        );
        // Swapping two different words keeps every word valid but breaks the checksum.
        let mut swapped: Vec<&str> = text.split(' ').collect();
        let j = (1..WORD_COUNT).find(|&j| swapped[j] != swapped[0]).unwrap();
        swapped.swap(0, j);
        assert_eq!(
            from_words(swapped.join(" ").as_bytes()),
            Err(WordsError::BadChecksum)
        );
    }

    /// The official IETF vector for exactly our suite (X-Wing, HKDF-SHA256,
    /// ChaCha20-Poly1305), run through our own wrapper.
    #[test]
    fn ietf_hpke_pq_04_a5_1() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/vectors/ietf-hpke-pq-04-A.5.1.json"
        ))
        .unwrap();
        let h = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
        assert_eq!(v["kem_id"], "25722");
        assert_eq!(v["kdf_id"], "1");
        assert_eq!(v["aead_id"], "3");

        let kp = RecoveryKeyPair::derive(&SecretKey::from_slice(&h("ikmR")).unwrap());
        assert_eq!(kp.public_key().as_slice(), h("pkRm"));
        assert_eq!(kp.sk.to_bytes().as_slice(), h("skRm"));

        let e = &v["encryptions"][0];
        let eh = |k: &str| hex::decode(e[k].as_str().unwrap()).unwrap();
        let randomness: [u8; ENCAP_RANDOMNESS_LEN] = h("ikmE").try_into().unwrap();
        let (enc, ct) = seal_base(
            kp.public_key(),
            &h("info"),
            &eh("pt"),
            &eh("aad"),
            &randomness,
        )
        .unwrap();
        assert_eq!(enc, h("enc"));
        assert_eq!(ct, eh("ct"));
        assert_eq!(
            open_base(&kp.sk, &enc, &h("info"), &ct, &eh("aad")).unwrap(),
            eh("pt")
        );
    }

    #[test]
    fn non_ascii_input_is_an_unknown_word_not_a_panic() {
        let words = to_words(&r(1));
        let text = std::str::from_utf8(words.expose())
            .unwrap()
            .replacen("a", "\u{e1}", 3);
        assert!(matches!(
            from_words(text.as_bytes()),
            Err(WordsError::UnknownWord(_))
        ));
    }

    #[test]
    fn seal_rejects_a_malformed_public_key() {
        let ek = r(9);
        assert!(seal(&[0u8; 10], b"aad", &ek).is_err());
        // Right length, but the ML-KEM part is all 0xff: coefficients aren't reduced
        // mod q, which FIPS 203's encapsulation-key check must refuse.
        let bad = [0xffu8; PUBLIC_KEY_LEN];
        assert!(seal(&bad, b"aad", &ek).is_err());
    }

    #[test]
    fn keypair_is_deterministic() {
        let a = RecoveryKeyPair::derive(&r(1));
        assert_eq!(a.public_key(), RecoveryKeyPair::derive(&r(1)).public_key());
        assert_ne!(a.public_key(), RecoveryKeyPair::derive(&r(2)).public_key());
    }

    #[test]
    fn seal_open_round_trip_and_rejects_tampering() {
        let kp = RecoveryKeyPair::derive(&r(1));
        let ek = SecretKey::generate().unwrap();
        let (enc, ct) = seal(kp.public_key(), b"slot header", &ek).unwrap();
        assert_eq!(enc.len(), ENC_LEN);
        assert_eq!(ct.len(), 32 + 16);
        assert_eq!(kp.open(&enc, &ct, b"slot header").unwrap(), ek);

        assert!(kp.open(&enc, &ct, b"slot headeR").is_err());
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;
        assert!(kp.open(&enc, &bad_ct, b"slot header").is_err());
        let mut bad_enc = enc.clone();
        bad_enc[0] ^= 1;
        assert!(kp.open(&bad_enc, &ct, b"slot header").is_err());
        assert!(kp.open(&enc[..ENC_LEN - 1], &ct, b"slot header").is_err());
        let other = RecoveryKeyPair::derive(&r(2));
        assert!(other.open(&enc, &ct, b"slot header").is_err());
    }

    #[test]
    fn seal_with_fixed_randomness_is_deterministic() {
        let kp = RecoveryKeyPair::derive(&r(1));
        let ek = r(9);
        let a = seal_with_randomness(kp.public_key(), b"x", &ek, &[4; 64]).unwrap();
        let b = seal_with_randomness(kp.public_key(), b"x", &ek, &[4; 64]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn anchor_binds_every_input() {
        let pk = RecoveryKeyPair::derive(&r(1)).public_key().to_vec();
        let tag = anchor_tag(&r(1), &[1; 16], 0, &[2; 32], &pk);
        assert!(verify_anchor(&r(1), &[1; 16], 0, &[2; 32], &pk, &tag));
        assert!(!verify_anchor(&r(2), &[1; 16], 0, &[2; 32], &pk, &tag));
        assert!(!verify_anchor(&r(1), &[9; 16], 0, &[2; 32], &pk, &tag));
        assert!(!verify_anchor(&r(1), &[1; 16], 1, &[2; 32], &pk, &tag));
        assert!(!verify_anchor(&r(1), &[1; 16], 0, &[3; 32], &pk, &tag));
        let other_pk = RecoveryKeyPair::derive(&r(2)).public_key().to_vec();
        assert!(!verify_anchor(
            &r(1),
            &[1; 16],
            0,
            &[2; 32],
            &other_pk,
            &tag
        ));
    }
}
