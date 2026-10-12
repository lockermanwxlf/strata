//! Fixed test vectors (spec §14.1, items 1, 2, 4 and the crypto parts of 3 and 6).
//!
//! `cargo test` recomputes every vector from its inputs and compares it with the
//! frozen JSON in `tests/vectors/`. To regenerate after a deliberate spec change:
//!
//! ```sh
//! STRATA_WRITE_VECTORS=1 cargo test --test vectors
//! ```
//!
//! Regenerated vectors must then be cross-checked by the independent implementation
//! in `core/tools/vectors/` before they are committed.

use std::path::PathBuf;

use serde_json::{Value, json};
use strata_core::crypto::kdf::{self, Argon2Params, EpochKeys};
use strata_core::crypto::{SecretKey, aead, recovery, sign};
use strata_core::encoding::padding;

/// Bytes `start, start+1, …` (wrapping), so inputs are obviously synthetic.
fn seq(start: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| start.wrapping_add(i as u8)).collect()
}

fn arr<const N: usize>(start: u8) -> [u8; N] {
    seq(start, N).try_into().unwrap()
}

fn key(start: u8) -> SecretKey {
    SecretKey::from_slice(&seq(start, 32)).unwrap()
}

fn kdf_vectors() -> Value {
    let cases: Vec<Value> = [(0x00u8, 0x20u8, 0x40u8, 0x50u8), (0xf0, 0xa0, 0x10, 0x77)]
        .into_iter()
        .map(|(v, e, s, ss)| {
            let vault_id = arr::<16>(v);
            let slot_id = arr::<16>(s);
            let keys = EpochKeys::derive(&vault_id, &key(e));
            json!({
                "vault_id": hex::encode(vault_id),
                "epoch_key": hex::encode(key(e).expose()),
                "slot_id": hex::encode(slot_id),
                "slot_secret": hex::encode(key(ss).expose()),
                "key_id": hex::encode(keys.key_id),
                "event_key": hex::encode(keys.event.expose()),
                "snapshot_key": hex::encode(keys.snapshot.expose()),
                "epoch_chain_key": hex::encode(keys.chain.expose()),
                "local_state_key": hex::encode(keys.local_state.expose()),
                "slot_kek": hex::encode(kdf::slot_kek(&vault_id, &slot_id, &key(ss)).expose()),
            })
        })
        .collect();
    json!({
        "description": "HKDF-SHA256 subkeys of an epoch key (spec §6.1) and the slot KEK (§6.2)",
        "cases": cases,
    })
}

fn argon2_vectors() -> Value {
    let p = Argon2Params::DEFAULT;
    let cases: Vec<Value> = [
        (
            "NFD input: 'cafe' + combining acute, normalized to NFC",
            "cafe\u{301} \u{1f512}",
        ),
        (
            "NFC input: same password, already composed",
            "caf\u{e9} \u{1f512}",
        ),
        ("ASCII", "correct horse battery staple"),
    ]
    .into_iter()
    .map(|(note, password)| {
        let salt = arr::<16>(0x60);
        let nfc: String = unicode_normalization::UnicodeNormalization::nfc(password).collect();
        let s = kdf::password_slot_secret(password.as_bytes(), &salt, p).unwrap();
        json!({
            "note": note,
            "password_utf8": hex::encode(password),
            "password_nfc_utf8": hex::encode(nfc),
            "salt": hex::encode(salt),
            "m_kib": p.m_kib, "t": p.t, "p": p.p,
            "slot_secret": hex::encode(s.expose()),
        })
    })
    .collect();
    json!({
        "description": "Argon2id v0x13 password slot secret (spec §6.2); input is NFC-normalized first",
        "cases": cases,
    })
}

fn aead_vectors() -> Value {
    let cases: Vec<Value> = [
        (b"".to_vec(), seq(0x90, 13)),
        (seq(0x00, 256), seq(0xb0, 76)),
    ]
    .into_iter()
    .map(|(plaintext, aad)| {
        let nonce = arr::<24>(0xc0);
        let ct = aead::seal(&key(0x30), &nonce, &plaintext, &aad);
        json!({
            "key": hex::encode(key(0x30).expose()),
            "nonce": hex::encode(nonce),
            "aad": hex::encode(&aad),
            "plaintext": hex::encode(&plaintext),
            "ciphertext": hex::encode(ct),
        })
    })
    .collect();
    json!({
        "description": "XChaCha20-Poly1305; ciphertext includes the 16-byte tag (spec §3)",
        "cases": cases,
    })
}

fn padding_vectors() -> Value {
    let lengths: Vec<Value> = [0u32, 1, 252, 253, 1000, 4096, 1 << 20]
        .into_iter()
        .map(|n: u32| json!({ "body_len": n, "padded_len": padding::padded_len(n) }))
        .collect();
    let body = b"strata";
    json!({
        "description": "Padme padding with a 256-byte minimum (spec §4)",
        "lengths": lengths,
        "example": {
            "body": hex::encode(body),
            "padded": hex::encode(padding::pad(body).unwrap().as_slice()),
        },
    })
}

fn recovery_vectors() -> Value {
    let r = key(0x80);
    let kp = recovery::RecoveryKeyPair::derive(&r);
    let pk = kp.public_key();
    let vault_id = arr::<16>(0x00);
    let key_id = arr::<32>(0xd0);
    let aad = seq(0xe0, 47 + 1252); // stands in for a slot header + recovery params
    let ek = key(0x20);
    let randomness = arr::<64>(0x40);
    let (enc, ct) = recovery::seal_with_randomness(pk, &aad, &ek, &randomness).unwrap();
    let words = recovery::to_words(&r);
    json!({
        "description": "Recovery key (spec §6.2.1): BIP39 words, X-Wing DeriveKeyPair, HPKE Base seal of EK, recovery anchor",
        "recovery_key": hex::encode(r.expose()),
        "words": std::str::from_utf8(words.expose()).unwrap(),
        "public_key": hex::encode(pk),
        "hpke": {
            "kem_id": 0x647a, "kdf_id": 1, "aead_id": 3,
            "info": hex::encode(recovery::HPKE_INFO),
            "aad": hex::encode(&aad),
            "plaintext_epoch_key": hex::encode(ek.expose()),
            "encap_randomness": hex::encode(randomness),
            "enc": hex::encode(&enc),
            "ciphertext": hex::encode(&ct),
        },
        "anchor": {
            "vault_id": hex::encode(vault_id),
            "anchor_epoch": 3,
            "key_id": hex::encode(key_id),
            "tag": hex::encode(recovery::anchor_tag(&r, &vault_id, 3, &key_id, pk)),
        },
    })
}

fn ed25519_vectors() -> Value {
    let cases: Vec<Value> = [(0x11u8, b"".to_vec()), (0x22, seq(0x00, 140))]
        .into_iter()
        .map(|(s, message)| {
            let device = sign::DeviceKey::from_seed(&key(s));
            json!({
                "seed": hex::encode(key(s).expose()),
                "public_key": hex::encode(device.public_key()),
                "signed_bytes": hex::encode(&message),
                "signature": hex::encode(device.sign(&message)),
            })
        })
        .collect();
    json!({
        "description": "Ed25519 device signatures over \"strata v1 signature\" || signed_bytes (spec §6.4)",
        "prefix": hex::encode(sign::SIGNATURE_PREFIX),
        "cases": cases,
    })
}

fn check(name: &str, computed: Value) {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "vectors", name]
        .iter()
        .collect();
    if std::env::var_os("STRATA_WRITE_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut text = serde_json::to_string_pretty(&computed).unwrap();
        text.push('\n');
        std::fs::write(&path, text).unwrap();
        return;
    }
    let frozen: Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("{} missing; see the module docs", path.display())),
    )
    .unwrap();
    assert!(
        frozen == computed,
        "{name}: the implementation no longer matches the frozen vectors"
    );
}

#[test]
fn kdf() {
    check("kdf.json", kdf_vectors());
}

#[test]
fn argon2id() {
    let v = argon2_vectors();
    // The NFD and NFC spellings of the same password must give the same secret.
    assert_eq!(v["cases"][0]["slot_secret"], v["cases"][1]["slot_secret"]);
    check("argon2id.json", v);
}

#[test]
fn aead() {
    check("aead.json", aead_vectors());
}

#[test]
fn padding() {
    check("padding.json", padding_vectors());
}

#[test]
fn recovery() {
    check("recovery.json", recovery_vectors());
}

#[test]
fn ed25519() {
    check("ed25519.json", ed25519_vectors());
}
