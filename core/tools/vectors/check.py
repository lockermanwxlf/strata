# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "argon2-cffi==25.1.0",
#   "cbor2==6.1.5",
#   "cryptography==50.0.2",
#   "kyber-py==1.2.0",
#   "mnemonic==0.21",
#   "pynacl==1.6.0",
# ]
# ///
"""Independent cross-check of Strata's test vectors (docs/spec.md §14.1).

The Rust core generates the vectors in core/strata-core/tests/vectors/. This script
recomputes every one of them from the spec, using implementations that share no code
with the Rust crates:

  - HKDF and HMAC: the Python standard library (RFC 5869 written out below)
  - Argon2id: argon2-cffi (the reference C implementation)
  - XChaCha20-Poly1305 and Ed25519: PyNaCl (libsodium)
  - BIP39: mnemonic (Trezor's reference implementation)
  - CBOR: cbor2, in canonical mode
  - ML-KEM-768 and X25519: cryptography (OpenSSL), plus kyber-py for the
    deterministic encapsulation OpenSSL doesn't expose
  - X-Wing and HPKE: written out below from draft-connolly-cfrg-xwing-kem-10,
    draft-ietf-hpke-hpke and RFC 9180, and first validated against the IETF's own
    vector for exactly our suite (draft-ietf-hpke-pq-04, A.5.1)

Run from the repository root:

    uv run core/tools/vectors/check.py

Exits non-zero on the first mismatch.
"""

import hashlib
import hmac
import json
import struct
import sys
import unicodedata
from pathlib import Path

import argon2.low_level
import cbor2
import nacl.bindings
import nacl.signing
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from kyber_py.ml_kem import ML_KEM_768
from mnemonic import Mnemonic

VECTORS = Path(__file__).resolve().parents[2] / "strata-core" / "tests" / "vectors"
checks = 0


def load(name):
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def h(s):
    return bytes.fromhex(s)


def expect(label, actual, expected):
    global checks
    if actual != expected:
        print(f"MISMATCH {label}\n  expected {expected!r}\n  actual   {actual!r}")
        sys.exit(1)
    checks += 1


# RFC 5869
def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def hkdf(salt, ikm, info):  # spec §3: HKDF(salt, ikm, info, 32)
    return hkdf_expand(hkdf_extract(salt, ikm), info, 32)


def i2osp(n, w):
    return n.to_bytes(w, "big")


# X-Wing, draft-connolly-cfrg-xwing-kem-10 §5
XWING_LABEL = b"\\.//^\\"
assert len(XWING_LABEL) == 6


def xwing_expand(sk):
    expanded = hashlib.shake_256(sk).digest(96)
    dk_m = mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[0:64])
    sk_x = x25519.X25519PrivateKey.from_private_bytes(expanded[64:96])
    pk_m = dk_m.public_key().public_bytes_raw()
    pk_x = sk_x.public_key().public_bytes_raw()
    return dk_m, sk_x, pk_m, pk_x


def xwing_combiner(ss_m, ss_x, ct_x, pk_x):
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


def xwing_decap(ct, sk):
    dk_m, sk_x, _, pk_x = xwing_expand(sk)
    ct_m, ct_x = ct[0:1088], ct[1088:1120]
    ss_m = dk_m.decapsulate(ct_m)
    ss_x = sk_x.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x))
    return xwing_combiner(ss_m, ss_x, ct_x, pk_x)


def xwing_encap_derand(pk, eseed):
    pk_m, pk_x = pk[0:1184], pk[1184:1216]
    ek_x = x25519.X25519PrivateKey.from_private_bytes(eseed[32:64])
    ct_x = ek_x.public_key().public_bytes_raw()
    ss_x = ek_x.exchange(x25519.X25519PublicKey.from_public_bytes(pk_x))
    ss_m, ct_m = ML_KEM_768._encaps_internal(pk_m, eseed[0:32])
    return xwing_combiner(ss_m, ss_x, ct_x, pk_x), ct_m + ct_x


# HPKE, draft-ietf-hpke-hpke (two-stage KDF) and draft-ietf-hpke-pq
KEM_ID, KDF_ID, AEAD_ID = 0x647A, 0x0001, 0x0003
KEM_SUITE = b"KEM" + i2osp(KEM_ID, 2)
HPKE_SUITE = b"HPKE" + i2osp(KEM_ID, 2) + i2osp(KDF_ID, 2) + i2osp(AEAD_ID, 2)


def length_prefixed(x):
    return i2osp(len(x), 2) + x


def derive_keypair(ikm):
    # seed = SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", 32), KEM suite_id
    labeled = ikm + b"HPKE-v1" + KEM_SUITE + length_prefixed(b"DeriveKeyPair") + i2osp(32, 2) + b""
    sk = hashlib.shake_256(labeled).digest(32)
    _, _, pk_m, pk_x = xwing_expand(sk)
    return sk, pk_m + pk_x


def labeled_extract(salt, label, ikm):
    return hkdf_extract(salt, b"HPKE-v1" + HPKE_SUITE + label + ikm)


def labeled_expand(prk, label, info, length):
    return hkdf_expand(prk, i2osp(length, 2) + b"HPKE-v1" + HPKE_SUITE + label + info, length)


def key_schedule_base(shared_secret, info):
    psk_id_hash = labeled_extract(b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = labeled_extract(shared_secret, b"secret", b"")
    return labeled_expand(secret, b"key", context, 32), labeled_expand(secret, b"base_nonce", context, 12)


def open_base(enc, sk, info, aad, ct):
    key, nonce = key_schedule_base(xwing_decap(enc, sk), info)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)


def seal_base_derand(pk, info, aad, pt, eseed):
    ss, enc = xwing_encap_derand(pk, eseed)
    key, nonce = key_schedule_base(ss, info)
    return enc, ChaCha20Poly1305(key).encrypt(nonce, pt, aad)


def check_ietf_hpke_vector():
    """Validate the Python X-Wing/HPKE above before trusting it to judge Rust's output."""
    v = load("ietf-hpke-pq-04-A.5.1.json")
    expect("A.5.1 suite", (v["kem_id"], v["kdf_id"], v["aead_id"]), ("25722", "1", "3"))
    sk, pk = derive_keypair(h(v["ikmR"]))
    expect("A.5.1 skRm", sk, h(v["skRm"]))
    expect("A.5.1 pkRm", pk, h(v["pkRm"]))
    expect("A.5.1 shared_secret", xwing_decap(h(v["enc"]), sk), h(v["shared_secret"]))
    key, nonce = key_schedule_base(h(v["shared_secret"]), h(v["info"]))
    expect("A.5.1 key", key, h(v["key"]))
    expect("A.5.1 base_nonce", nonce, h(v["base_nonce"]))
    e = v["encryptions"][0]
    expect("A.5.1 open", open_base(h(v["enc"]), sk, h(v["info"]), h(e["aad"]), h(e["ct"])), h(e["pt"]))
    enc, ct = seal_base_derand(pk, h(v["info"]), h(e["aad"]), h(e["pt"]), h(v["ikmE"]))
    expect("A.5.1 enc", enc, h(v["enc"]))
    expect("A.5.1 ct", ct, h(e["ct"]))


def check_kdf():
    for c in load("kdf.json")["cases"]:
        vid, ek = h(c["vault_id"]), h(c["epoch_key"])
        for name, label in [
            ("key_id", b"strata v1 key-id"),
            ("event_key", b"strata v1 event-key"),
            ("snapshot_key", b"strata v1 snapshot-key"),
            ("epoch_chain_key", b"strata v1 epoch-chain-key"),
            ("local_state_key", b"strata v1 local-state-key"),
        ]:
            expect(f"kdf {name}", hkdf(vid, ek, label), h(c[name]))
        kek = hkdf(vid + h(c["slot_id"]), h(c["slot_secret"]), b"strata v1 slot-kek")
        expect("kdf slot_kek", kek, h(c["slot_kek"]))


def check_argon2id():
    for c in load("argon2id.json")["cases"]:
        password = h(c["password_utf8"]).decode("utf-8")
        nfc = unicodedata.normalize("NFC", password).encode("utf-8")
        expect("argon2id NFC", nfc, h(c["password_nfc_utf8"]))
        s = argon2.low_level.hash_secret_raw(
            secret=nfc,
            salt=h(c["salt"]),
            time_cost=c["t"],
            memory_cost=c["m_kib"],
            parallelism=c["p"],
            hash_len=32,
            type=argon2.low_level.Type.ID,
            version=19,
        )
        expect(f"argon2id {c['note']}", s, h(c["slot_secret"]))


def check_aead():
    for c in load("aead.json")["cases"]:
        ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            h(c["plaintext"]), h(c["aad"]), h(c["nonce"]), h(c["key"])
        )
        expect("aead ciphertext", ct, h(c["ciphertext"]))


def padme(length):
    e = length.bit_length() - 1
    s = e.bit_length()
    mask = (1 << (e - s)) - 1
    return (length + mask) & ~mask


def check_padding():
    v = load("padding.json")
    for c in v["lengths"]:
        expect(f"padded_len({c['body_len']})", padme(max(4 + c["body_len"], 256)), c["padded_len"])
    body = h(v["example"]["body"])
    padded = struct.pack("<I", len(body)) + body
    padded += bytes(padme(max(len(padded), 256)) - len(padded))
    expect("padding example", padded, h(v["example"]["padded"]))


def check_ed25519():
    v = load("ed25519.json")
    prefix = h(v["prefix"])
    expect("ed25519 prefix", prefix, b"strata v1 signature")
    for c in v["cases"]:
        key = nacl.signing.SigningKey(h(c["seed"]))
        expect("ed25519 public key", bytes(key.verify_key), h(c["public_key"]))
        sig = key.sign(prefix + h(c["signed_bytes"])).signature
        expect("ed25519 signature", sig, h(c["signature"]))


def check_recovery():
    v = load("recovery.json")
    r = h(v["recovery_key"])
    words = Mnemonic("english")
    expect("bip39 words", words.to_mnemonic(r), v["words"])
    expect("bip39 entropy", bytes(words.to_entropy(v["words"])), r)

    sk, pk = derive_keypair(r)
    expect("recovery public key", pk, h(v["public_key"]))

    x = v["hpke"]
    expect("hpke suite", (x["kem_id"], x["kdf_id"], x["aead_id"]), (KEM_ID, KDF_ID, AEAD_ID))
    expect("hpke info", h(x["info"]), b"strata v1 recovery-slot")
    ek = open_base(h(x["enc"]), sk, h(x["info"]), h(x["aad"]), h(x["ciphertext"]))
    expect("hpke open", ek, h(x["plaintext_epoch_key"]))
    enc, ct = seal_base_derand(pk, h(x["info"]), h(x["aad"]), ek, h(x["encap_randomness"]))
    expect("hpke enc", enc, h(x["enc"]))
    expect("hpke ciphertext", ct, h(x["ciphertext"]))

    a = v["anchor"]
    vid = h(a["vault_id"])
    anchor_key = hkdf(vid, r, b"strata v1 recovery-anchor-key")
    msg = b"strata v1 recovery-anchor" + vid + struct.pack("<I", a["anchor_epoch"]) + h(a["key_id"]) + pk
    expect("recovery anchor", hmac.new(anchor_key, msg, hashlib.sha256).digest(), h(a["tag"]))


# ---- Complete files (spec §5–§10), rebuilt from the spec text ----------------


def le16(n):
    return struct.pack("<H", n)


def le32(n):
    return struct.pack("<I", n)


def le64(n):
    return struct.pack("<Q", n)


def preamble(magic):  # magic || LE16 format_version || LE16 flags
    return magic + le16(1) + le16(0)


def derive_epoch_keys(vault_id, ek):  # spec §6.1
    labels = ["key-id", "event-key", "snapshot-key", "epoch-chain-key", "local-state-key"]
    return {label: hkdf(vault_id, ek, b"strata v1 " + label.encode()) for label in labels}


def xchacha(key, nonce, plaintext, aad):
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)


def device_sign(seed, signed_bytes):  # spec §6.4
    return nacl.signing.SigningKey(seed).sign(b"strata v1 signature" + signed_bytes).signature


def pad(body):  # spec §4
    total = padme(max(4 + len(body), 256))
    return le32(len(body)) + body + bytes(total - 4 - len(body))


def op_cbor(o):  # spec §8.2: flat arrays, op type first
    t = o["type"]
    if t == "SetField":
        value = None if o["value"] is None else h(o["value"])
        return [1, h(o["entry_id"]), o["name"], value, o["secret"]]
    if t == "DeleteEntry":
        return [2, h(o["entry_id"])]
    if t == "KeepEntry":
        return [3, h(o["entry_id"])]
    if t == "AddTag":
        return [4, h(o["entry_id"]), o["tag"]]
    if t == "RemoveTag":
        return [5, h(o["entry_id"]), o["tag"], [[h(c), s, i] for c, s, i in o["dots"]]]
    if t == "RetireClient":
        return [6, h(o["client_id"]), o["last_seq"]]
    if t == "RegisterDevice":
        return [7, h(o["client_id"]), h(o["dev_pk"]), o["name"]]
    if t == "SetDeviceName":
        return [8, o["name"]]
    raise ValueError(t)


def clock_cbor(clock):
    return [[h(c), s] for c, s in clock]


def check_files():
    v = load("files.json")
    vid = h(v["vault_id"])
    eks = [h(e) for e in v["epoch_keys"]]
    keys = [derive_epoch_keys(vid, e) for e in eks]
    seed = h(v["device"]["seed"])

    expect("strata-vault", preamble(b"STVT") + vid, h(v["vault_info"]["file"]))

    for s in v["slots"]:  # spec §6.2
        kind, slot_id, epoch = s["kind"], h(s["slot_id"]), s["epoch"]
        if kind == 1:
            password = unicodedata.normalize("NFC", h(s["password_utf8"]).decode())
            secret = argon2.low_level.hash_secret_raw(
                secret=password.encode(), salt=h(s["salt"]), time_cost=s["t"],
                memory_cost=s["m_kib"], parallelism=s["p"], hash_len=32,
                type=argon2.low_level.Type.ID, version=19,
            )
            params = le32(s["m_kib"]) + le32(s["t"]) + le32(s["p"]) + h(s["salt"])
        elif kind == 2:
            r = h(s["recovery_key"])
            _, pk = derive_keypair(r)
            anchor_key = hkdf(vid, r, b"strata v1 recovery-anchor-key")
            anchor_epoch = s["anchor_epoch"]
            msg = b"strata v1 recovery-anchor" + vid + le32(anchor_epoch) + keys[anchor_epoch]["key-id"] + pk
            tag = hmac.new(anchor_key, msg, hashlib.sha256).digest()
            params = pk + le32(anchor_epoch) + tag
        elif kind == 3:
            secret, cred = h(s["slot_secret"]), h(s["credential_id"])
            params = h(s["salt"]) + le16(len(cred)) + cred
        else:
            secret, blob = h(s["slot_secret"]), h(s["blob"])
            params = bytes([s["protector_id"]]) + le16(len(blob)) + blob
        magic = b"STLS" if kind == 4 else b"STSL"
        header = preamble(magic) + vid + slot_id + le32(epoch) + bytes([kind]) + le16(len(params)) + params
        if kind == 2:
            enc, ct = seal_base_derand(pk, b"strata v1 recovery-slot", header, eks[epoch], h(s["encap_randomness"]))
            file = header + enc + ct
        else:
            kek = hkdf(vid + slot_id, secret, b"strata v1 slot-kek")
            nonce = h(s["nonce"])
            file = header + nonce + xchacha(kek, nonce, eks[epoch], header + nonce)
        expect(f"slot kind {kind}", file, h(s["file"]))

    for e in v["epochs"]:  # spec §7.1
        epoch = e["epoch"]
        record = preamble(b"STEP") + vid + le32(epoch) + h(e["creator"]) + keys[epoch]["key-id"]
        record += le16(len(e["cutover"])) + b"".join(h(c) + le64(s) for c, s in e["cutover"])
        if epoch > 0:
            nonce = h(e["chain_nonce"])
            record += nonce
            record += xchacha(keys[epoch]["epoch-chain-key"], nonce, eks[epoch - 1], record)
        expect(f"epoch {epoch} record", record + device_sign(seed, record), h(e["file"]))

    ev = v["event"]  # spec §8
    b = ev["body"]
    body = cbor2.dumps(
        {1: b["hlc"], 2: clock_cbor(b["clock"]), 3: h(b["prev_hash"]), 4: [op_cbor(o) for o in b["ops"]]},
        canonical=True,
    )
    nonce = h(ev["nonce"])
    header = preamble(b"STEV") + vid + h(ev["client_id"]) + le64(ev["seq"]) + le32(ev["epoch"]) + nonce
    signed = header + xchacha(keys[ev["epoch"]]["event-key"], nonce, pad(body), header)
    expect("event file", signed + device_sign(seed, signed), h(ev["file"]))

    sn = v["snapshot"]  # spec §10
    b = sn["body"]
    body = cbor2.dumps(
        {
            1: [[h(c), s, h(hash_)] for c, s, hash_ in b["watermark"]],
            2: [clock_cbor(c) for c in b["clocks"]],
            3: [[h(o["client_id"]), o["seq"], o["op_index"], o["hlc"], o["vc_index"], op_cbor(o["op"])] for o in b["ops"]],
        },
        canonical=True,
    )
    nonce = h(sn["nonce"])
    header = preamble(b"STSN") + vid + h(sn["snapshot_id"]) + h(sn["creator"]) + le32(sn["epoch"]) + nonce
    signed = header + xchacha(keys[sn["epoch"]]["snapshot-key"], nonce, pad(body), header)
    expect("snapshot file", signed + device_sign(seed, signed), h(sn["file"]))


# ---- Merge (spec §9.2), written out from the spec's definitions -------------


def check_merge():
    v = load("merge.json")
    ops = []  # (client, seq, index, hlc, clock, op)
    for e in v["events"]:
        clock = {c: s for c, s in e["clock"]}
        for i, op in enumerate(e["ops"]):
            ops.append((e["client_id"], e["seq"], i, e["hlc"], clock, op))

    def before(a, b):  # a → b
        if (a[0], a[1]) == (b[0], b[1]):
            return a[2] < b[2]
        return b[4].get(a[0], 0) >= a[1]

    def dot(o):
        return [o[0], o[1], o[2]]

    def of(kind, **match):
        return [o for o in ops if o[5]["type"] == kind and all(o[5].get(k) == val for k, val in match.items())]

    entries = {}
    for entry_id in sorted({o[5]["entry_id"] for o in ops if "entry_id" in o[5]}):
        writes = of("SetField", entry_id=entry_id) + of("KeepEntry", entry_id=entry_id)
        if not writes:
            continue  # an entry exists iff it has a write
        deletes = of("DeleteEntry", entry_id=entry_id)
        deleted = any(all(before(w, d) for w in writes) for d in deletes)
        unanswered = not deleted and any(not any(before(d, w) for w in writes) for d in deletes)

        fields = {}
        for name in sorted({o[5]["name"] for o in of("SetField", entry_id=entry_id)}):
            group = of("SetField", entry_id=entry_id, name=name)
            cands = [w for w in group if not any(before(w, other) for other in group)]
            secret = any(c[5]["secret"] for c in cands)
            if secret and len(cands) > 1:
                if all(c[5]["value"] is None for c in cands):
                    continue
                cands.sort(key=lambda c: (bytes.fromhex(c[0]), c[1], c[2]))
                fields[name] = {"conflict": [[c[5]["value"], dot(c)] for c in cands]}
                continue
            winner = max(cands, key=lambda c: (c[3], bytes.fromhex(c[0]), c[1], c[2]))
            if winner[5]["value"] is not None:
                fields[name] = {"secret": secret, "value": winner[5]["value"], "dot": dot(winner)}

        tags = []
        for tag in sorted({o[5]["tag"] for o in of("AddTag", entry_id=entry_id)}):
            removed = {tuple(d) for r in of("RemoveTag", entry_id=entry_id, tag=tag) for d in r[5]["dots"]}
            if any(tuple(dot(a)) not in removed for a in of("AddTag", entry_id=entry_id, tag=tag)):
                tags.append(tag)

        entries[entry_id] = {"deleted": deleted, "unanswered_delete": unanswered, "tags": tags, "fields": fields}

    devices = {}
    for reg in of("RegisterDevice"):
        client = reg[5]["client_id"]
        naming = [o for o in ops if o[0] == client and o[5]["type"] in ("RegisterDevice", "SetDeviceName")]
        latest = max(naming, key=lambda o: (o[1], o[2]))
        retired = [o[5]["last_seq"] for o in of("RetireClient", client_id=client)]
        devices[client] = {"dev_pk": reg[5]["dev_pk"], "name": latest[5]["name"],
                           "retired_after": min(retired) if retired else None}

    expect("merge view", {"entries": entries, "devices": devices}, v["view"])


if __name__ == "__main__":
    check_ietf_hpke_vector()
    check_kdf()
    check_argon2id()
    check_aead()
    check_padding()
    check_ed25519()
    check_recovery()
    check_files()
    check_merge()
    print(f"OK: {checks} checks passed")
