//! Fixed test vectors (spec §14.1, items 1–4 and 6; item 5 comes with the merge code).
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
use strata_core::crypto::{SecretBytes, SecretKey, aead, recovery, sign};
use strata_core::encoding::padding;
use strata_core::format::body::{Dot, EventBody, Op, RetainedOp, SnapshotBody, VectorClock};
use strata_core::format::epoch::{ChainWrap, NewEpoch};
use strata_core::format::event::EventHeader;
use strata_core::format::slot::{self, SlotParams};
use strata_core::format::snapshot::SnapshotHeader;
use strata_core::format::vault_info::VaultInfo;
use strata_core::merge::OpSet;
use strata_core::merge::view::{Field, VaultView};
use strata_core::policy::SlotScope;

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

// ---- Complete files (spec §14.1 items 3 and 6) -------------------------------

fn h(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(bytes)
}

fn op_json(op: &Op) -> Value {
    match op {
        Op::SetField {
            entry_id,
            name,
            value,
            secret,
        } => json!({
            "type": "SetField", "entry_id": h(entry_id), "name": name,
            "value": value.as_ref().map(|v| h(v.expose())), "secret": secret,
        }),
        Op::DeleteEntry { entry_id } => json!({"type": "DeleteEntry", "entry_id": h(entry_id)}),
        Op::KeepEntry { entry_id } => json!({"type": "KeepEntry", "entry_id": h(entry_id)}),
        Op::AddTag { entry_id, tag } => {
            json!({"type": "AddTag", "entry_id": h(entry_id), "tag": tag})
        }
        Op::RemoveTag {
            entry_id,
            tag,
            dots,
        } => json!({
            "type": "RemoveTag", "entry_id": h(entry_id), "tag": tag,
            "dots": dots.iter().map(|d| json!([h(d.client_id), d.seq, d.op_index])).collect::<Vec<_>>(),
        }),
        Op::RetireClient {
            client_id,
            last_seq,
        } => json!({"type": "RetireClient", "client_id": h(client_id), "last_seq": last_seq}),
        Op::RegisterDevice {
            client_id,
            dev_pk,
            name,
        } => json!({
            "type": "RegisterDevice", "client_id": h(client_id), "dev_pk": h(dev_pk), "name": name,
        }),
        Op::SetDeviceName { name } => json!({"type": "SetDeviceName", "name": name}),
    }
}

fn clock_json(clock: &VectorClock) -> Value {
    json!(
        clock
            .0
            .iter()
            .map(|(id, s)| json!([hex::encode(id), s]))
            .collect::<Vec<_>>()
    )
}

fn file_vectors() -> Value {
    let vault = arr::<16>(0x00);
    let (ek0, ek1) = (key(0x20), key(0x40));
    let (k0, k1) = (
        EpochKeys::derive(&vault, &ek0),
        EpochKeys::derive(&vault, &ek1),
    );
    let (alice, bob, entry) = (arr::<16>(0xa0), arr::<16>(0xb0), arr::<16>(0xe0));
    let seed = key(0x11);
    let device = sign::DeviceKey::from_seed(&seed);

    // Slots, all wrapping the epoch 1 key.
    let password = "correct horse battery staple";
    let pw_salt = arr::<16>(0x60);
    let pw_id = arr::<16>(0x70);
    let pw_secret =
        kdf::password_slot_secret(password.as_bytes(), &pw_salt, Argon2Params::DEFAULT).unwrap();
    let pw_slot = slot::seal_with_kek_and_nonce(
        &vault,
        &pw_id,
        1,
        &SlotParams::Password {
            argon: Argon2Params::DEFAULT,
            salt: pw_salt,
        },
        &kdf::slot_kek(&vault, &pw_id, &pw_secret),
        &ek1,
        &arr(0x80),
    )
    .unwrap();

    let r = key(0x80);
    let kp = recovery::RecoveryKeyPair::derive(&r);
    let rec_id = arr::<16>(0x71);
    let rec_slot = slot::seal_recovery(
        &vault,
        &rec_id,
        1,
        &SlotParams::Recovery {
            pk: Box::new(*kp.public_key()),
            anchor_epoch: 0,
            anchor_tag: recovery::anchor_tag(&r, &vault, 0, &k0.key_id, kp.public_key()),
        },
        &ek1,
        Some(&arr(0x90)),
    )
    .unwrap();

    let fido_secret = key(0xc0);
    let fido_id = arr::<16>(0x72);
    let fido_slot = slot::seal_with_kek_and_nonce(
        &vault,
        &fido_id,
        1,
        &SlotParams::Fido2 {
            salt: arr(0xd0),
            credential_id: seq(0xe0, 40),
        },
        &kdf::slot_kek(&vault, &fido_id, &fido_secret),
        &ek1,
        &arr(0x81),
    )
    .unwrap();

    let platform_secret = key(0xc8);
    let platform_id = arr::<16>(0x73);
    let platform_slot = slot::seal_with_kek_and_nonce(
        &vault,
        &platform_id,
        1,
        &SlotParams::Platform {
            protector_id: 2,
            blob: seq(0x30, 50),
        },
        &kdf::slot_kek(&vault, &platform_id, &platform_secret),
        &ek1,
        &arr(0x82),
    )
    .unwrap();
    // Each slot reads back and opens to EK1 through the public API.
    for (bytes, scope, kek) in [
        (
            &pw_slot,
            SlotScope::Synced,
            kdf::slot_kek(&vault, &pw_id, &pw_secret),
        ),
        (
            &fido_slot,
            SlotScope::Synced,
            kdf::slot_kek(&vault, &fido_id, &fido_secret),
        ),
        (
            &platform_slot,
            SlotScope::Local,
            kdf::slot_kek(&vault, &platform_id, &platform_secret),
        ),
    ] {
        let parsed = slot::SlotFile::parse(bytes, &vault, scope).unwrap();
        assert_eq!(parsed.open_with_kek(&kek).unwrap(), ek1);
    }

    // Epoch records.
    let no_cutover = VectorClock::default();
    let epoch0 = NewEpoch {
        vault_id: vault,
        epoch: 0,
        creator: alice,
        key_id: k0.key_id,
        recovery_pk_hash: recovery::pk_hash(kp.public_key()),
        cutover: &no_cutover,
        chain: None,
    }
    .seal(&device)
    .unwrap();
    let cutover = VectorClock(vec![(alice, 2), (bob, 1)]);
    let epoch1 = NewEpoch {
        vault_id: vault,
        epoch: 1,
        creator: alice,
        key_id: k1.key_id,
        recovery_pk_hash: recovery::pk_hash(kp.public_key()),
        cutover: &cutover,
        chain: Some(ChainWrap {
            chain_key: &k1.chain,
            prev_epoch_key: &ek0,
            nonce: Some(arr(0x83)),
        }),
    }
    .seal(&device)
    .unwrap();

    // Alice's first event, in epoch 0, using every op type.
    let event_body = EventBody {
        hlc: 0x0001_9a2b_3c4d_0001,
        clock: VectorClock(vec![(alice, 1), (bob, 3)]),
        prev_hash: [0; 32],
        ops: vec![
            Op::RegisterDevice {
                client_id: alice,
                dev_pk: device.public_key(),
                name: "Laptop".into(),
            },
            Op::SetField {
                entry_id: entry,
                name: "title".into(),
                value: Some(SecretBytes::from_slice("Café ☕".as_bytes())),
                secret: false,
            },
            Op::SetField {
                entry_id: entry,
                name: "password".into(),
                value: Some(SecretBytes::from_slice(b"hunter2")),
                secret: true,
            },
            Op::SetField {
                entry_id: entry,
                name: "notes".into(),
                value: None,
                secret: false,
            },
            Op::AddTag {
                entry_id: entry,
                tag: "work".into(),
            },
            Op::RemoveTag {
                entry_id: entry,
                tag: "home".into(),
                dots: vec![Dot {
                    client_id: bob,
                    seq: 3,
                    op_index: 1,
                }],
            },
            Op::KeepEntry { entry_id: entry },
            Op::DeleteEntry { entry_id: entry },
            Op::RetireClient {
                client_id: bob,
                last_seq: 3,
            },
            Op::SetDeviceName {
                name: "Work laptop".into(),
            },
        ],
    };
    let event = EventHeader {
        vault_id: vault,
        client_id: alice,
        seq: 1,
        epoch: 0,
    }
    .seal(&event_body, &k0.event, &device, Some(arr(0x84)))
    .unwrap();

    // A snapshot in epoch 1.
    let snapshot_body = SnapshotBody {
        watermark: vec![(alice, 2, arr(0x41)), (bob, 3, arr(0x61))],
        clocks: vec![
            VectorClock(vec![(alice, 1), (bob, 3)]),
            VectorClock(vec![(alice, 2), (bob, 3)]),
        ],
        ops: vec![
            RetainedOp {
                dot: Dot {
                    client_id: alice,
                    seq: 1,
                    op_index: 0,
                },
                hlc: event_body.hlc,
                vc_index: 0,
                op: Op::RegisterDevice {
                    client_id: alice,
                    dev_pk: device.public_key(),
                    name: "Laptop".into(),
                },
            },
            RetainedOp {
                dot: Dot {
                    client_id: alice,
                    seq: 2,
                    op_index: 0,
                },
                hlc: event_body.hlc + 1,
                vc_index: 1,
                op: Op::SetField {
                    entry_id: entry,
                    name: "password".into(),
                    value: Some(SecretBytes::from_slice(b"correct horse")),
                    secret: true,
                },
            },
        ],
    };
    let snapshot = SnapshotHeader {
        vault_id: vault,
        snapshot_id: arr(0x74),
        creator: alice,
        epoch: 1,
    }
    .seal(&snapshot_body, &k1.snapshot, &device, Some(arr(0x85)))
    .unwrap();

    json!({
        "description": "Complete vault files (spec §5–§10), built from the inputs listed. Keys not listed are derived as in §6.1.",
        "vault_id": h(vault),
        "epoch_keys": [h(ek0.expose()), h(ek1.expose())],
        "device": { "client_id": h(alice), "seed": h(seed.expose()) },
        "vault_info": { "file": h(VaultInfo { vault_id: vault }.encode()) },
        "slots": [
            { "kind": 1, "slot_id": h(pw_id), "epoch": 1, "password_utf8": h(password),
              "salt": h(pw_salt), "m_kib": 65536, "t": 3, "p": 4, "nonce": h(arr::<24>(0x80)),
              "file": h(&pw_slot) },
            { "kind": 2, "slot_id": h(rec_id), "epoch": 1, "recovery_key": h(r.expose()),
              "anchor_epoch": 0, "encap_randomness": h(arr::<64>(0x90)), "file": h(&rec_slot) },
            { "kind": 3, "slot_id": h(fido_id), "epoch": 1, "slot_secret": h(fido_secret.expose()),
              "salt": h(arr::<32>(0xd0)), "credential_id": h(seq(0xe0, 40)), "nonce": h(arr::<24>(0x81)),
              "file": h(&fido_slot) },
            { "kind": 4, "slot_id": h(platform_id), "epoch": 1, "slot_secret": h(platform_secret.expose()),
              "protector_id": 2, "blob": h(seq(0x30, 50)), "nonce": h(arr::<24>(0x82)),
              "file": h(&platform_slot) },
        ],
        "epochs": [
            { "epoch": 0, "creator": h(alice), "cutover": [], "file": h(&epoch0) },
            { "epoch": 1, "creator": h(alice), "cutover": clock_json(&cutover),
              "chain_nonce": h(arr::<24>(0x83)), "file": h(&epoch1) },
        ],
        "event": {
            "client_id": h(alice), "seq": 1, "epoch": 0, "nonce": h(arr::<24>(0x84)),
            "body": {
                "hlc": event_body.hlc, "clock": clock_json(&event_body.clock),
                "prev_hash": h(event_body.prev_hash),
                "ops": event_body.ops.iter().map(op_json).collect::<Vec<_>>(),
            },
            "file": h(&event),
        },
        "snapshot": {
            "snapshot_id": h(arr::<16>(0x74)), "creator": h(alice), "epoch": 1, "nonce": h(arr::<24>(0x85)),
            "body": {
                "watermark": snapshot_body.watermark.iter()
                    .map(|(c, s, hash)| json!([h(c), s, h(hash)])).collect::<Vec<_>>(),
                "clocks": snapshot_body.clocks.iter().map(clock_json).collect::<Vec<_>>(),
                "ops": snapshot_body.ops.iter().map(|r| json!({
                    "client_id": h(r.dot.client_id), "seq": r.dot.seq, "op_index": r.dot.op_index,
                    "hlc": r.hlc, "vc_index": r.vc_index, "op": op_json(&r.op),
                })).collect::<Vec<_>>(),
            },
            "file": h(&snapshot),
        },
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

#[test]
fn files() {
    check("files.json", file_vectors());
}

// ---- Merge fixture (spec §14.1 item 5) ----------------------------------------

fn view_json(view: &VaultView<'_>) -> Value {
    let dot = |d: &Dot| json!([h(d.client_id), d.seq, d.op_index]);
    let entries: serde_json::Map<String, Value> = view
        .entries
        .iter()
        .map(|(id, e)| {
            let fields: serde_json::Map<String, Value> = e
                .fields
                .iter()
                .map(|(name, f)| {
                    let v = match f {
                        Field::Value {
                            value,
                            secret,
                            dot: d,
                        } => {
                            json!({"secret": secret, "value": h(value.expose()), "dot": dot(d)})
                        }
                        Field::Conflict { candidates, .. } => json!({"conflict": candidates
                            .iter()
                            .map(|c| json!([c.value.map(|v| h(v.expose())), dot(&c.dot)]))
                            .collect::<Vec<_>>()}),
                    };
                    (name.to_string(), v)
                })
                .collect();
            let v = json!({
                "deleted": e.deleted,
                "unanswered_delete": e.unanswered_delete,
                "tags": e.tags.iter().collect::<Vec<_>>(),
                "fields": fields,
            });
            (h(id), v)
        })
        .collect();
    let devices: serde_json::Map<String, Value> = view
        .devices
        .iter()
        .map(|(id, d)| {
            let v =
                json!({"dev_pk": h(d.dev_pk), "name": d.name, "retired_after": d.retired_after});
            (h(id), v)
        })
        .collect();
    json!({ "entries": entries, "devices": devices })
}

fn merge_vectors() -> Value {
    let (a, b, c) = (arr::<16>(0xa0), arr::<16>(0xb0), arr::<16>(0xc0));
    let (x, y, v, z) = (
        arr::<16>(0x10),
        arr::<16>(0x20),
        arr::<16>(0x30),
        arr::<16>(0x40),
    );
    let set = |entry: [u8; 16], name: &str, value: &str, secret: bool| Op::SetField {
        entry_id: entry,
        name: name.into(),
        value: Some(SecretBytes::from_slice(value.as_bytes())),
        secret,
    };
    let register = |client: [u8; 16], name: &str| Op::RegisterDevice {
        client_id: client,
        dev_pk: [client[0]; 32],
        name: name.into(),
    };
    // (client, seq, hlc, clock, ops). Comments say what each event saw.
    let events = || {
        vec![
            (
                a,
                1,
                1,
                vec![(a, 1)],
                vec![
                    register(a, "Laptop"),
                    set(x, "title", "Bank", false),
                    set(x, "password", "p0", true),
                    Op::AddTag {
                        entry_id: x,
                        tag: "finance".into(),
                    },
                    set(y, "title", "Mail", false),
                    set(v, "title", "Vault", false),
                ],
            ),
            // B saw only A1.
            (
                b,
                1,
                2,
                vec![(a, 1), (b, 1)],
                vec![
                    register(b, "Phone"),
                    set(x, "password", "from B", true),
                    Op::RemoveTag {
                        entry_id: x,
                        tag: "finance".into(),
                        dots: vec![Dot {
                            client_id: a,
                            seq: 1,
                            op_index: 3,
                        }],
                    },
                    Op::DeleteEntry { entry_id: y },
                    Op::DeleteEntry { entry_id: v },
                ],
            ),
            // A, concurrently with B1.
            (
                a,
                2,
                3,
                vec![(a, 2)],
                vec![
                    set(x, "password", "from A", true),
                    Op::AddTag {
                        entry_id: x,
                        tag: "finance".into(),
                    },
                    set(y, "notes", "n", false),
                    set(v, "notes", "n2", false),
                    Op::SetDeviceName {
                        name: "Work laptop".into(),
                    },
                ],
            ),
            // C saw A2 and B1.
            (
                c,
                1,
                4,
                vec![(a, 2), (b, 1), (c, 1)],
                vec![
                    register(c, "Tablet"),
                    set(x, "title", "Bank (C)", false),
                    Op::RetireClient {
                        client_id: b,
                        last_seq: 1,
                    },
                    Op::KeepEntry { entry_id: v },
                    set(z, "title", "Old", false),
                ],
            ),
            (
                c,
                2,
                5,
                vec![(a, 2), (b, 1), (c, 2)],
                vec![Op::DeleteEntry { entry_id: z }],
            ),
            // B again, still having seen only A1.
            (
                b,
                2,
                6,
                vec![(a, 1), (b, 2)],
                vec![
                    set(x, "title", "Bank (B)", false),
                    // Concurrent with A2's notes: both kept (notes are multi-value).
                    set(v, "notes", "n2 from B", false),
                ],
            ),
        ]
    };

    let build = || {
        let mut ops = OpSet::new();
        for (client, seq, hlc, clock, body_ops) in events() {
            let body = EventBody {
                hlc,
                clock: VectorClock(clock),
                prev_hash: [0; 32],
                ops: body_ops,
            };
            body.validate(&client, seq).unwrap();
            ops.apply_event(client, seq, body);
        }
        ops
    };
    let full = build();
    let expected = view_json(&full.view());
    let mut reduced = build();
    reduced.reduce();
    assert_eq!(
        view_json(&reduced.view()),
        expected,
        "reduction changed the view"
    );

    json!({
        "description": "Merge fixture (spec §9.2): events and the vault view they produce",
        "events": events().into_iter().map(|(client, seq, hlc, clock, ops)| json!({
            "client_id": h(client), "seq": seq, "hlc": hlc,
            "clock": clock_json(&VectorClock(clock)),
            "ops": ops.iter().map(op_json).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "view": expected,
    })
}

#[test]
fn merge() {
    check("merge.json", merge_vectors());
}
