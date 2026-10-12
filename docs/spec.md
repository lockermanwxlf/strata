# Strata vault format and cryptography

**Status: DRAFT 0.3 (2026-10-11). No external review yet. Not yet safe for real passwords** (see implementation-plan.md, Phase 13).

This document is the source of truth for byte layouts, key derivation, parameters and associated data. Code implements this spec. When the two disagree, either the code is wrong or the spec needs a deliberate change. Items marked **OPEN-n** are undecided and collected in §15.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

---

## 1. Goals and threat model

**Protects against:**

- **An attacker who controls the remote storage.** They can read, delete, reorder and replay files, roll them back to older versions, and write arbitrary files. They learn only the metadata listed in §13 and cannot read or forge vault contents. Rollback, forks, replays and slot substitution are detected on any device that has synced before.
- **An attacker who steals a locked device.** Local slots are bound to hardware keystores, and local state is encrypted.
- **A revoked device** (one that once unlocked the vault). After key rotation (§7) it cannot read new data. It keeps everything it already had. Anything it still writes with an old key is signed, attributed to it, and flagged for review and one-click revert (§9.2). It is not silently dropped: see the design note in §9.2 for why.
- **One device impersonating another.** Every device signs what it writes with its own key (§6.4). Even a device holding the vault key cannot forge another device's events, so every change is attributable to a device.

**Does not protect against:**

- A compromised, unlocked device. It holds the keys. It can write as itself and can register new devices, but those changes are attributed to it and show up in the device list.
- A **fresh** device's first sync. There is nothing to compare against, so it is trust-on-first-use (§6.3). The exception is unlocking with the recovery key, which the anchor in §6.2.1 verifies.
- Misattribution inside a snapshot. A snapshot's retained ops keep their original dots, but not their original signatures, so attributing them relies on the snapshot's creator (§10.1).
- Metadata leakage beyond §13.

## 2. Notation and conventions

- `a || b` is concatenation. `LE16/LE32/LE64(x)` is an unsigned little-endian integer of 2/4/8 bytes.
- `"text"` in a byte context means its ASCII bytes, with no terminator.
- `[i..j)` is the byte range from offset `i` (inclusive) to `j` (exclusive).
- IDs are 16 bytes from the OS CSPRNG. In file names they are written as 32 lowercase hex characters.
- **Random** always means the OS CSPRNG (`getrandom`). There are no user-space RNGs.
- **Reject** means fail loudly. The item is not used, the error is surfaced, and where §9.4 says so an alarm is raised. Parsers never skip malformed data silently.
- **AAD rule.** In every envelope below, the AEAD associated data is **every byte of the file before the ciphertext**, exactly as stored, nonce included.
- **Signature rule.** Events, snapshots and epoch records end with a 64-byte device signature (§6.4) over **every byte of the file before it**.

## 3. Primitives

These are the only primitives. Adding one means changing this spec.

| Purpose | Primitive | Rust crate |
|---|---|---|
| AEAD | XChaCha20-Poly1305 (24-byte random nonce, 16-byte tag) | `chacha20poly1305` |
| Password hashing | Argon2id, version 0x13 (RFC 9106) | `argon2` |
| Key derivation | HKDF-SHA256 (RFC 5869) | `hkdf`, `sha2` |
| Hashing (hash chains, file IDs) | SHA-256 | `sha2` |
| Public-key encryption (recovery slots) | HPKE (RFC 9180), Base mode. Suite: KEM **X-Wing** (MLKEM768-X25519, a post-quantum/classical hybrid) `0x647a`, KDF HKDF-SHA256 `0x0001`, AEAD ChaCha20-Poly1305 `0x0003`. X-Wing uses SHA3-256 and SHAKE256 internally; those count as part of the KEM, not as separate primitives. | `hpke` (`mlkem` feature) |
| MAC (recovery anchor) | HMAC-SHA256 (RFC 2104). This is the same HMAC that HKDF already uses. | `hmac` |
| Signatures (device keys) | Ed25519 (RFC 8032), pure. Verification is strict: non-canonical encodings and small-order points are rejected. | `ed25519-dalek` (`verify_strict`) |
| Constant-time compare | n/a | `subtle` |
| Secret memory | n/a | `zeroize` |
| Unicode normalization (passwords, names) | NFC | `unicode-normalization` |

HKDF is always used as `HKDF(salt, ikm, info, 32)`: Extract with `salt`, then Expand with `info` to 32 bytes.

**Why X-Wing.** Everything else here is symmetric, and 256-bit symmetric keys hold up against quantum attacks. The recovery slot is the one place where a public key sits in cleartext on the remote. With plain X25519, anyone who copied the vault files could use a future quantum computer to derive the private key, open the slot, and then follow the epoch chain to read the whole history ("harvest now, decrypt later"). A hybrid stays secure as long as either X25519 or ML-KEM-768 (FIPS 203) holds. X-Wing's HPKE codepoint comes from an Internet-Draft (draft-ietf-hpke-pq, as implemented by `hpke` 0.14). Strata pins that exact behavior with test vectors. If the final RFC changes it, adopting the change is a `format_version` bump.

Ed25519 device signatures are not post-quantum. That is deliberate: forging a signature only helps an attacker once such a computer exists, which leaves nothing to harvest today, and device public keys exist only inside encrypted bodies. A later format version can switch to ML-DSA if needed.

## 4. Encoding

There are two layers.

1. **Envelopes:** fixed-layout binary, defined per file type in §5 to §10. They are parsed **before** authentication, so they are simple, fixed-offset, and covered by the AAD.
2. **Bodies:** the authenticated plaintext inside the AEAD. These use CBOR (RFC 8949) restricted as follows.
   - **Deterministic encoding only** (RFC 8949 §4.2.1): shortest-form integers and lengths, definite lengths, and map keys sorted bytewise. Readers MUST enforce this by re-encoding the decoded value and comparing bytes.
   - **Allowed types:** unsigned int, byte string, text string (valid UTF-8), array, map, bool, null. No floats, tags, negative integers or indefinite lengths.
   - **Maps use unsigned-integer keys.** Unknown keys and unknown op types are rejected. Anything new needs a new `format_version` (§12).
3. **Padding.** Every encrypted body is padded before encryption:

   ```
   L          = 4 + len(body)
   padded_len = padme(max(L, 256))
   plaintext  = LE32(len(body)) || body || zero bytes up to padded_len
   ```

   `padme` is the Padmé function (Nikitin et al., PETS 2019):

   ```
   padme(L): E = floor(log2(L)); S = floor(log2(E)) + 1
             mask = 2^(E - S) - 1; return (L + mask) & ~mask
   ```

   On decryption, readers MUST check three things: `len(body) <= len(plaintext) - 4`, `len(plaintext) == padme(max(4 + len(body), 256))`, and that every padding byte is zero. Anything else is rejected.

**Size limits.** Readers check these before allocating.

| Item | Limit |
|---|---|
| Event file | 2 MiB |
| Event body | 1 MiB |
| Snapshot file | 64 MiB |
| Slot `params` | 2048 bytes |
| Ops per event | 4096 |
| Entries per vector clock | 4096 |
| Field value | 64 KiB |
| Field name, tag or device name | 1..=128 bytes of UTF-8, NFC |

## 5. Vault layout

```
<vault>/
  strata-vault                          vault info (§5.1). Written once.
  epochs/<epoch:08x>-<clientId>.epoch   one per key epoch (§7). Immutable.
  slots/<slotId>.slot                   synced slots (§6). Immutable.
  events/<clientId>-<seq:016x>.evt      events (§8). Immutable.
  snapshots/<snapshotId>.snap           snapshots (§10). Immutable.
```

- Clients only **create** files, never modify them. Deletions happen only in the cases listed: removing slots after rotation (§7), garbage collection (§10.3), and purge (§10.4).
- Writers create each file under a temporary name beginning with `.` and then rename it into place. When the backend supports it, they use create-exclusive and never overwrite. If the target name already exists, the writer MUST NOT overwrite it and MUST raise a fork alarm (§9.4).
- Readers ignore names that don't exactly match the patterns above. That covers temporary files and the conflict copies that sync providers create.
- The values inside a file MUST match its name: client ID, seq, epoch, slot ID or snapshot ID. A mismatch is rejected.

> **Design note.** There is no single `header` file. A header that changes over time (new slots, rotation) would be the only overwritten file in the vault and could conflict. It is split into immutable `strata-vault`, `epochs/` and `slots/` files instead.

### 5.1 `strata-vault`

```
[0..4)    magic "STVT"
[4..6)    LE16 format_version = 1
[6..8)    LE16 flags = 0
[8..24)   vault_id
```

This file is not authenticated. Every key derivation and every AAD binds `vault_id`, so tampering with this file makes all later checks fail.

## 6. Keys and slots

### 6.1 Key hierarchy

- **Epoch key** `EK_e`: 32 random bytes per epoch `e` (epoch 0 is created with the vault). "The vault key" in CLAUDE.md means the current epoch's `EK_e`.
- Everything else is derived from it with `salt = vault_id`:

| Name | Derivation | Used for |
|---|---|---|
| `key_id_e` | `HKDF(vault_id, EK_e, "strata v1 key-id")` | key commitment and pinning (§6.3) |
| `event_key_e` | `HKDF(vault_id, EK_e, "strata v1 event-key")` | events (§8) |
| `snapshot_key_e` | `HKDF(vault_id, EK_e, "strata v1 snapshot-key")` | snapshots (§10) |
| `chain_key_e` | `HKDF(vault_id, EK_e, "strata v1 epoch-chain-key")` | wrapping `EK_{e-1}` (§7) |
| `local_key_e` | `HKDF(vault_id, EK_e, "strata v1 local-state-key")` | device-local state (§11) |

> **Design note.** There is no MAC subkey. Every authenticated structure is an AEAD ciphertext that binds its context through AAD, and the key commitment is `key_id`. Fewer primitives means less to review.

### 6.2 Slots

A slot wraps `EK_e`. Most kinds wrap it under a key-encryption key (KEK) derived from a 32-byte **slot secret** `S`, which comes from a single protector. The recovery slot is the exception: it uses public-key encryption instead (§6.2.1).

```
KEK     = HKDF(vault_id || slot_id, S, "strata v1 slot-kek")
wrapped = XChaCha20-Poly1305-Seal(KEK, nonce, EK_e, aad)
```

Every `S` and KEK is zeroized immediately after use.

| Kind | Code | Scope | Slot secret `S` | `params` |
|---|---|---|---|---|
| Password | 1 | Synced | `Argon2id(P, salt, m, t, p, 32)`, where `P` is the UTF-8 password after NFC normalization, with no trimming | `LE32 m_kib, LE32 t, LE32 p, salt[16]` (28 bytes) |
| Recovery key | 2 | Synced | none: HPKE to an X-Wing key pair derived from the recovery key `R` (§6.2.1) | `pk[1216], LE32 anchor_epoch, anchor_tag[32]` (1252 bytes) |
| FIDO2 `hmac-secret` | 3 | Synced | the 32-byte `hmac-secret` output for `salt32` | `salt32[32], LE16 len, credential_id[len]` with `1 <= len <= 1023`. RP ID: OPEN-4. |
| Platform keystore | 4 | **Local only** | 32 random bytes, protected by a `PlatformProtector` (§11) | `u8 protector_id, LE16 len, blob[len]` |

**Argon2id parameters.** The default is `m = 65536` KiB (64 MiB), `t = 3`, `p = 4` (RFC 9106 §4, second recommended option). Readers MUST reject slots that fall outside these bounds:

| Parameter | Minimum | Maximum |
|---|---|---|
| `m` | 65536 KiB | 1048576 KiB |
| `t` | 3 | 10 |
| `p` | 1 | 16 |

The maximums stop a malicious slot from exhausting memory or CPU. The minimums enforce policy.

**Policy.** The core MUST call `check_slot_policy` (`policy.rs`) before it creates any slot. Kind 4 MUST NOT appear in `slots/`; readers reject it there.

- **PINs** are the only Weak protector. They are entered into a platform protector (a TPM PIN, or the Android device credential), so they appear only in kind-4 local slots, and the policy requires that keystore to be hardware-backed and rate-limited.
- **Passwords of any strength** count as Strong and may be synced. This is the user's choice. Before the core creates or changes a password slot, it gives the UI a strength estimate (a zxcvbn-style guess count). Below about 10^10 estimated guesses, the UI MUST warn that anyone holding the vault files can guess the password offline, and MUST require an explicit "use anyway". The exact threshold and wording are UI guidance, not part of the format.

**Slot file.** `P` below is `params_len`.

```
[0..4)      magic "STSL"
[4..6)      LE16 format_version = 1
[6..8)      LE16 flags = 0
[8..24)     vault_id
[24..40)    slot_id
[40..44)    LE32 epoch                 the epoch whose key this slot wraps
[44..45)    u8 kind
[45..47)    LE16 params_len
[47..47+P)  params
[47+P..)    wrap, depending on kind:
              kinds 1, 3 (4):  nonce[24] || XChaCha20-Poly1305 ciphertext of EK_epoch [48]
                           AAD = [0..71+P), i.e. everything before the ciphertext
              kind 2:      enc[1120] || HPKE ciphertext of EK_epoch [48]   (§6.2.1)
                           HPKE aad = [0..47+P); HPKE itself binds enc
```

Binding the vault ID, slot ID, epoch, kind and params means a slot can't be moved to another vault, slot ID or epoch, and its parameters can't be changed without detection.

### 6.2.1 Recovery slot

The recovery key is `R`: 32 random bytes (256 bits). It is shown to the user once, as a 24-word BIP39 mnemonic (English word list). BIP39's 8-bit checksum catches typos when the user types it back in. Only BIP39's encoding is used, never its PBKDF2 seed derivation. `R` is derived into an X-Wing key pair:

```
(sk, pk) = DeriveKeyPair(R)          X-Wing's HPKE DeriveKeyPair (draft-ietf-hpke-pq),
                                     for the suite in §3. sk is a 32-byte seed; pk is 1216 bytes.
```

**Wrap.** No `R` is needed, so rotation (§7.2) can re-wrap the recovery slot without the user producing the recovery key:

```
(enc, ct) = SealBase(pk, info = "strata v1 recovery-slot", aad = [0..47+P), pt = EK_e)
```

**Why the anchor exists.** Anyone can encrypt to `pk`. Without the anchor, an attacker who controls storage could replace the vault with a fabricated one, made of an epoch 0 record and a recovery slot wrapping a key the attacker knows. The real recovery key would open it. Recovery usually happens on a fresh device with no pin (§6.3), so nothing would catch it. The anchor ties `R` to the real key chain, and only someone holding `R` can produce it.

**Anchor.** Computed only when `R` is generated, with `anchor_epoch` set to the epoch current at that moment:

```
anchor_key = HKDF(vault_id, R, "strata v1 recovery-anchor-key")
anchor_tag = HMAC-SHA256(anchor_key, "strata v1 recovery-anchor" || vault_id
                         || LE32(anchor_epoch) || key_id_{anchor_epoch} || pk)
```

At rotation, `pk`, `anchor_epoch` and `anchor_tag` are copied unchanged into the re-wrapped slot.

**Unlock with `R`.** Applies on every device, including fresh ones, so recovery is **not** trust-on-first-use:

1. Derive `(sk, pk)`. Consider only kind-2 slots whose `pk` matches. Pick the one with the highest epoch.
2. Compute `EK_e = OpenBase(enc, sk, info, aad, ct)`. Then run the `key_id` check from §6.3 step 3.
3. Walk the epoch chain (§7) from `e` back to `anchor_epoch`, verifying each `key_id`. Recompute `anchor_tag` and compare it in constant time.
4. On any failure, raise a slot-substitution alarm.
5. After the anchor check, the pin rules in §6.3 step 4 apply as usual. A fresh device pins the result.

**Replacing a recovery key.** Generate a new `R` and write a new slot with a fresh anchor at the current epoch. Removing the old recovery slot is a slot removal, so it rotates (§7.2).

A vault MUST NOT reuse a recovery key from another vault. Equal `pk` values would link the two vaults (§13).

### 6.3 Unlock and slot-substitution defense

XChaCha20-Poly1305 is not key-committing. An attacker who controls storage could craft a slot that opens under the user's KEK to a key the attacker knows (see Len, Grubbs and Ristenpart, "Partitioning Oracle Attacks"). If the client accepted that key, every event it wrote afterward would be readable by the attacker. The defense is the key ID plus pinning.

1. Read `strata-vault`, then parse all epoch records and slot files strictly.
2. Try the slots of the chosen kind, highest epoch first. Derive `S` and the KEK, then open the slot. An AEAD failure means "try the next slot". Only slots whose epoch has an epoch record are tried, and at most 8 of them, so planted slots can't make unlock arbitrarily slow (each password slot costs a full Argon2 run). Readers also cap every file read at its type's size limit before reading it in.
3. With the candidate `EK_e`, compute `key_id_e` and find an epoch record for `e` whose `key_id` matches (constant-time). If there is none, reject the slot: the vault is inconsistent or under attack.
4. **Device with a pin** (local state holds `(e_p, key_id_p)`):
   - `e == e_p`: `key_id_e` MUST equal `key_id_p`.
   - `e > e_p`: walk the chain (§7) from `e` back to `e_p`. Each unwrapped `EK_{i-1}` MUST match the `key_id` in epoch record `i-1`, and the key reached at `e_p` MUST match `key_id_p`.
   - `e < e_p`: the slot is stale. Ignore it. If no epoch record at or above `e_p` exists, raise a rollback alarm.
   - If any check fails, raise a **slot-substitution alarm**: refuse to write, and tell the user.
5. **Device without a pin** (fresh install): pin `(e, key_id_e)`. This is trust-on-first-use. Showing a short `key_id` fingerprint that the user can compare between devices is OPEN-6.
6. After unlock, the device holds `EK` for the current epoch and, through the chain, every earlier one.
7. The pin then moves forward to the current epoch and its `key_id`. The chain walk has verified that epoch back to the old pin, and pinning the newest verified epoch means a later rollback to any earlier state is detected.

### 6.4 Device signing keys

Every client has an Ed25519 key pair `(dev_sk, dev_pk)`. It generates the pair when it gets its `client_id`, and keeps `dev_sk` in its encrypted state record (§11). A device that becomes a new client (§9.4) generates a new pair.

**Registration.** The first op of a client's first event `(c, 1)` MUST be `RegisterDevice(c, dev_pk, name)` (§8.2). `RegisterDevice` MUST NOT appear anywhere else. The vault's **device registry** maps `c` to that `dev_pk` (§9.2). A device's key never changes.

**Signing.**

```
signature = Ed25519-Sign(dev_sk, "strata v1 signature" || every byte of the file before the signature)
```

**Which key verifies a file.**

| File | Key |
|---|---|
| Event `(c, 1)` | the `dev_pk` in its own `RegisterDevice` op. It is self-signed. |
| Event `(c, s > 1)` | `registry[c]`. Causal delivery (§9.1) applies `(c, 1)` first. |
| Snapshot, epoch record | `registry[creator]`. If the creator isn't registered yet, verification waits until its registration arrives. A fresh device that learns the creator's key only from the snapshot itself accepts it on the same trust-on-first-use basis as §6.3. |

An AEAD-valid file whose signature fails verification is **rejected and raises a forgery alarm** (§9.4). Only a vault-key holder can produce such a file, so it means a device is misbehaving.

**Retired devices.** After `RetireClient(c, last_seq)`:

- Events from `c` with `s > last_seq` are applied and merged like any other. Their changes are flagged for review (§9.2).
- A snapshot signed by `c` is accepted only if `watermark[c] <= last_seq`, and an epoch record signed by `c` only if `cutover[c] <= last_seq`. Anything else they sign is rejected.

## 7. Epochs and rotation

### 7.1 Epoch record

File name: `epochs/<epoch:08x>-<creator clientId>.epoch`. `C` below is `cutover_count`, and each cutover entry is 24 bytes.

```
[0..4)    magic "STEP"
[4..6)    LE16 format_version = 1
[6..8)    LE16 flags = 0
[8..24)   vault_id
[24..28)  LE32 epoch
[28..44)  creator client_id
[44..76)  key_id_epoch
[76..78)  LE16 cutover_count
[78..X)   cutover entries: client_id[16] || LE64 seq      X = 78 + 24*C
-- epoch > 0 only:
[X..X+24)     nonce
[X+24..X+72)  Seal(chain_key_epoch, nonce, EK_{epoch-1}, aad = [0..X+24))
-- always:
[last 64)     signature by the creator (§6.4)
```

- **Epoch 0** has `cutover_count = 0` and no chain wrap. It is protected by the `key_id` check in §6.3 and by its creator's signature.
- **Epoch > 0:** the chain wrap authenticates the whole record under `EK_epoch`, and the signature attributes it to its creator.
- **The cutover vector** is the creator's applied vector clock at rotation. It records which devices were known when the rotation happened (§7.2). Its entries follow the vector-clock rules in §8.2: sorted by `client_id`, no duplicates, no zero seqs, and at most 4096.

### 7.2 Rotation

Rotation is how revocation works: removing a synced slot, revoking a device, changing the password, and purging (§10.4). Removing a synced slot without rotating gives no protection, because anyone who kept a copy of the old slot file can still open it. So **the core MUST rotate whenever it removes a synced slot.**

1. Generate a new `EK_{e+1}`.
2. Write epoch record `e+1`. Its `cutover` is the rotating client's current applied vector clock (§9.1), and it carries `EK_e` wrapped under `chain_key_{e+1}`.
3. For every synced slot being kept, write a new slot file with a new `slot_id`, wrapping `EK_{e+1}`:
   - **Password slots:** the user enters the password. This is the new password when the rotation is a password change.
   - **Recovery slots:** re-wrapped to `pk` (§6.2.1). The recovery key isn't needed.
   - **FIDO2 slots:** the token must be present. A token that isn't present has its slot dropped, and the UI offers to re-enroll the token later.
4. Re-wrap this device's local slots, then delete every slot file with `epoch <= e`.
5. From now on, write events in epoch `e+1`.

Steps 2 and 3 complete before step 4, so a crash part-way through leaves the vault usable.

**Rotation never wraps the new key under an old one.** Otherwise a revoked holder of `EK_e` could follow the chain forward. The result is that other devices' local slots, which wrap `EK_e`, now open only the old epoch. Those devices fall back to a synced protector (the password) once, then re-wrap their local slots. The core can do that re-wrap in the same session without another biometric prompt.

Until a device holds the newest epoch's key it MUST NOT write. Anything written under an old key is readable by every holder of that key, which after a revocation includes the revoked device. A device that sees a newer epoch record than it can open stops writing and asks for a synced protector (the password) again. It keeps reading.

**Late events from an old epoch.** These are legitimate when a device was offline during a rotation and wrote events under the key it had. Take an event `(c, s)` in epoch `e' < current`:

The event is applied like any other: its signature (§6.4) proves which device wrote it, and the merge can't treat it specially without letting devices disagree (§9.2). What depends on the epoch record is how it is flagged:

- **`c` appears in `cutover_{e'+1}`** (the device was known when the rotation happened): nothing to flag, unless `c` has since been retired.
- **`c` doesn't appear:** the device registered under an old key after the rotation. That is how a revoked device holding the old key would invent a new identity, so the device is marked **suspect** in the device list, and its changes are flagged for review.

Concurrent rotations, meaning two records for the same epoch: OPEN-2.

## 8. Events

### 8.1 Envelope

File name: `events/<clientId>-<seq:016x>.evt`. `seq` starts at 1 for each client.

```
[0..4)    magic "STEV"
[4..6)    LE16 format_version = 1
[6..8)    LE16 flags = 0
[8..24)   vault_id
[24..40)  client_id
[40..48)  LE64 seq
[48..52)  LE32 epoch
[52..76)  nonce (24 bytes, random)
[76..N-64)  Seal(event_key_epoch, nonce, padded(body), aad = [0..76))
[N-64..N)   signature by client_id over [0..N-64) (§6.4)          N = file length
```

The AAD binds the vault ID, event ID `(client_id, seq)` and epoch, as CLAUDE.md requires, plus the version and flags. The file hash `H(c, s) = SHA-256(the entire file)`, signature included.

### 8.2 Body

```
EventBody = {
  1: uint             ; hlc (§8.3)
  2: VectorClock      ; see below
  3: bstr .size 32    ; prev_hash = H(c, s-1); 32 zero bytes when s = 1
  4: [* Op]
}
VectorClock = [* [bstr .size 16, uint]]   ; (client_id, seq). Sorted by client_id,
                                          ; no duplicates, no zero seqs.
```

`VC[c]` MUST equal `s`. The vector clock records every event the writer had applied when it wrote this one. An event with no ops is valid: clients use one as a heartbeat (§10.3).

**Ops.** Each op is a CBOR array whose first element is its type.

| Type | Op | Fields |
|---|---|---|
| 1 | `SetField` | `entry_id bstr16, name tstr, value (bstr / null), secret bool` |
| 2 | `DeleteEntry` | `entry_id bstr16` |
| 3 | `KeepEntry` | `entry_id bstr16` |
| 4 | `AddTag` | `entry_id bstr16, tag tstr` |
| 5 | `RemoveTag` | `entry_id bstr16, tag tstr, [* Dot]` (the observed `AddTag` dots) |
| 6 | `RetireClient` | `client_id bstr16, last_seq uint` |
| 7 | `RegisterDevice` | `client_id bstr16, dev_pk bstr32, name tstr`. Only as op 0 of `(c, 1)`, with `client_id = c` (§6.4). |
| 8 | `SetDeviceName` | `name tstr`. Renames the device that wrote the event. |

Notes:

- `Dot = [client_id bstr16, seq uint, op_index uint]`. It identifies one op.
- A `SetField` value of `null` deletes the field.
- **Well-known field names:** `title`, `username`, `password`, `url`, `notes`, `otp`. `password` and `otp` MUST have `secret = true`.
- **Custom fields:** any other name. KDBX's "protected" flag maps to `secret`.
- **KDBX round-trip data:** fields named `kdbx:<...>` hold KDBX data Strata doesn't interpret, as opaque bytes, so it survives export.
- Field values are bytes (text values are UTF-8), so secrets can be zeroized.

### 8.3 Hybrid logical clock

An HLC value is 64 bits: the top 48 bits are Unix time in milliseconds and the low 16 bits are a counter (Kulkarni et al., 2014).

- A writer MUST give each new event an HLC strictly greater than the HLC of every event it has applied and of its own previous event. It SHOULD use `max(that + 1, now_ms << 16)`.
- When the counter would overflow, the writer increments the millisecond part.
- Readers MUST reject an event whose HLC is not greater than its own predecessor's, when the predecessor is available.
- Readers SHOULD warn about an HLC more than 24 hours in the future.

The HLC orders concurrent non-secret writes (§9.2) and is shown in history. It never decides causality. Vector clocks do that.

## 9. Sync and merge

### 9.1 Validating and applying events

For each new event file, in any order, a reader:

1. Parses the envelope and checks the name match, version, `flags = 0` and `vault_id`.
2. Gets the key for the event's epoch. If the epoch is unknown, it holds the event and retries after processing epoch records. It then decrypts, checks the padding, and checks that the CBOR is deterministic and matches the schema and limits.
3. Verifies the signature with the key from §6.4. If it fails, the event is rejected and a forgery alarm is raised.
4. **Rejects** the event in any of these cases:
   - `RegisterDevice` is missing from op 0 of `(c, 1)`, appears anywhere else, or names a `client_id` other than `c`.
   - `VC[c] != s`.
   - The predecessor `(c, s-1)` is available and either its vector clock is not componentwise ≤ this event's, or its HLC is not lower.
   - `prev_hash` doesn't match the predecessor's file hash. When the predecessor has been compacted, the snapshot's watermark hash is used instead (§10.1).
5. **Holds** the event until every event its vector clock names has been applied or is covered by a snapshot (causal delivery). An event held longer than 7 days raises a warning.
6. Doesn't reject events for retirement or for arriving late in an old epoch. Whether a device has seen a `RetireClient` or a newer epoch record yet depends on sync order, so rejecting here would let devices disagree. Those events are flagged for review instead (§7.2, §9.2).
7. Applies the event by adding its ops to the op set. The device's **applied vector clock** maps each client to the highest contiguous seq it has applied.

### 9.2 Merge semantics

The vault's state is a pure function of the **set** of applied ops. Arrival order doesn't matter, and applying the same op twice changes nothing.

**Happened-before.** Ops are related through the vector clock of their event, `VC(o)`. For ops `o1` and `o2` with dots `(c1, s1, i1)` and `(c2, s2, i2)`, `o1 → o2` holds iff either:

- they are in the same event and `i1 < i2`, or
- they are in different events and `VC(o2)[c1] >= s1`.

`o1 ∥ o2` (concurrent) iff neither happened before the other.

**Field register `(x, f)`** for entry `x` and field `f`:

- `W` is the set of `SetField` ops on `(x, f)`.
- The candidates are `C = { w ∈ W : no w' ∈ W with w → w' }`.
- **Secret field** (any candidate has `secret = true`):
  - `|C| = 1`: the field's value is that candidate.
  - `|C| > 1`: a **conflict**. All candidate values are shown to the user, with `null` displayed as "deleted". If every candidate is `null`, nothing is in conflict and the field is absent. To resolve it, the user writes a new `SetField`, which dominates every candidate. This is how "concurrent password changes keep both values" works.
- **Non-secret field:** the value is the candidate with the greatest `(hlc, client_id, seq, op_index)`. This is last-writer-wins, restricted to concurrent writes.
- A field whose resolved value is `null` is absent.

**Entries.** For entry `x`, `Writes(x)` is all `SetField` and `KeepEntry` ops on `x`, and `Deletes(x)` is all `DeleteEntry` ops on `x`.

- `x` exists iff `Writes(x)` is non-empty.
- `x` is **deleted** iff some `d ∈ Deletes(x)` has every `w ∈ Writes(x)` happening before it (`w → d`). In words: a delete wins only over the writes it saw.
- A live `x` has an **unanswered delete** iff some `d ∈ Deletes(x)` has no write after it. The UI asks "deleted on another device: keep or delete?":
  - **Keep** writes a `KeepEntry` op.
  - **Delete** writes a `DeleteEntry` op, which dominates everything.
- Deleted entries stay readable (as trash) until they are purged (§10.4).

**Tags** on `(x, t)` form an observed-remove set: a tag is present iff some `AddTag` on `(x, t)` has a dot that no `RemoveTag` on `(x, t)` lists. Adds win over concurrent removes.

**Device registry.** For each client `c`:

- `dev_pk` comes from its `RegisterDevice`.
- Its name is the name in the latest of its `RegisterDevice` and `SetDeviceName` ops. A client's own events are totally ordered, so "latest" is well defined.
- It is **retired** iff some `RetireClient(c, …)` exists. If there are several, the lowest `last_seq` applies.
- **Changes flagged for review:** the ops of a retired client with `seq > last_seq`, and every op of a suspect device (§7.2). The UI lists them by device and offers to revert them, which writes ordinary new ops restoring the values they replaced. Flagging never changes what the merge computes.

The UI shows the registry as the device list, and attributes changes to devices through each op's dot.

> **Design note: why retirement isn't retroactive.** Ignoring a retired device's later ops inside the merge looks safer, but it breaks reduction. A device may already have dropped an op because the retired device's later op superseded it (§9.3). Once that later op is ignored, the dropped op is gone for good. Avoiding that would need every compaction to wait until all devices have seen everything, and devices joining mid-way would still leave gaps. Flag-and-revert keeps the merge order-independent and compaction always safe. Rotation already stops a revoked device from reading anything new, and every change it makes is signed and attributed. Automatic revert is OPEN-14.

### 9.3 Reduction (which ops may be dropped)

An op may be dropped from the set without changing any of the results in §9.2 when one of these holds:

| Op | May be dropped when |
|---|---|
| `SetField w` on `(x, f)` | some `w'` on the same `(x, f)` has `w → w'` |
| `KeepEntry k` | some `w ∈ Writes(x)` has `k → w` |
| `DeleteEntry d` | some `w ∈ Writes(x)` has `d → w`, or some `d' ∈ Deletes(x)` has `d → d'` |
| `AddTag a` on `(x, t)` | some `RemoveTag` on the same `(x, t)` lists its dot |
| `SetDeviceName n` | a later `SetDeviceName` exists from the same client |
| `RemoveTag`, `RetireClient`, `RegisterDevice` | never (v1) |

**Why this preserves the results:** happened-before is transitive, and a dropped op is always dominated by an op that is kept. Every dropped op is therefore replaced by a witness that gives the same answer for "deleted", "unanswered delete" and "candidates", both now and for any op that arrives later. A consequence is that **the union of two reduced sets, re-reduced, equals the reduction of the union**. Snapshots can be combined freely, and replaying an event that is already covered changes nothing.

### 9.4 Rollback, fork and replay detection

Every device keeps a **high-water mark** for each client in its local state: `HWM[c] = (seq, H(c, seq))`. On each sync:

- **Rollback.** The event `(c, HWM[c].seq)` is missing, and no snapshot watermark covers it, or the highest event or watermark for `c` is lower than `HWM[c].seq`.
- **Fork.** The file at `(c, HWM[c].seq)` has a different hash, any hash-chain link fails, or a file name the writer is about to create already exists.
- **Replay and relocation.** These are caught by the AAD binding. A copied or renamed file fails AEAD authentication or the name check. A re-uploaded file that a snapshot already covers is ignored.
- **Forgery.** An AEAD-valid file with a bad device signature (§6.4).

On an alarm, the device stops writing to the remote, keeps working from its local copy, and shows the user what failed. Recovery is a user decision. Automatic recovery is out of scope for v1.

A device whose local state is lost or restored from a backup MUST become a new client with a fresh `client_id`. Reusing a `client_id` with a rewound seq counter is indistinguishable from a fork. Android backup is already disabled. Writers MUST durably persist `next_seq` before uploading an event.

## 10. Snapshots

### 10.1 Format

File name: `snapshots/<snapshotId>.snap`.

```
[0..4)    magic "STSN"
[4..6)    LE16 format_version = 1
[6..8)    LE16 flags = 0
[8..24)   vault_id
[24..40)  snapshot_id
[40..56)  creator client_id
[56..60)  LE32 epoch                      the current epoch when it was written
[60..84)  nonce
[84..N-64)  Seal(snapshot_key_epoch, nonce, padded(body), aad = [0..84))
[N-64..N)   signature by the creator over [0..N-64) (§6.4)        N = file length
```

The retained ops keep their original dots, so the UI can still attribute them, but not their original signatures. That attribution rests on the snapshot creator, a registered device whose own signature is checked.

```
SnapshotBody = {
  1: [* [bstr .size 16, uint, bstr .size 32]]   ; watermark: (client_id, seq, H(c, seq)).
                                                ; The creator's applied vector clock.
  2: [* VectorClock]                            ; vector-clock table
  3: [* RetainedOp]                             ; the reduced op set (§9.3)
}
RetainedOp = [client_id bstr16, seq uint, op_index uint, hlc uint, vc_index uint, Op]
```

Watermark entries are sorted by `client_id`, with no duplicates and no zero seqs. Every `vc_index` must point into the vector-clock table. Every vector clock and op follows the rules in §8.2.

### 10.2 Loading

1. Decrypt and validate the snapshot as in §9.1, steps 1 to 3: the envelope, decryption, and the creator's signature.
2. Check its watermark against the HWM (§9.4). A watermark below the HWM for any client is a rollback alarm.
3. Take the union of its retained ops with the device's op set and re-reduce.
4. Raise the HWM to the watermark.

Because union is safe (§9.3), a device MAY load several snapshots in any order.

### 10.3 Writing and garbage collection

- Any client MAY write a snapshot of its reduced op set.
- Clients that only read SHOULD write an empty heartbeat event at most once a day after their applied vector clock advances. That keeps watermarks moving and makes it visible which clients are still active.
- **Garbage collection.**
  - Event files covered by a snapshot watermark MAY be deleted once that snapshot has existed for 30 days. The grace period is OPEN-9.
  - A snapshot whose watermark is ≤ another snapshot's MAY be deleted after the same grace period.

> **Design note.** A snapshot doesn't have to wait until every known client has seen the events it folds in. Snapshots keep the causal metadata of the ops they retain, so merging stays exact with any concurrent event. Compaction is correct at any time. The grace period exists only so that devices in the middle of a sync don't see files disappear.

### 10.4 Purge

A purge permanently removes an entry. The client:

1. Removes every op on the entry and writes a new snapshot.
2. Deletes all event files and every other snapshot.
3. Rotates the epoch (§7).

The rotation keeps copies the attacker already has from leading to future data. Those copies stay readable to the attacker forever, because data that has already been uploaded can't be taken back. Details: OPEN-10.

## 11. Local state (per device, never uploaded)

The layout is implementation-defined. Local state is never shared, so it isn't part of the interoperable format. It MUST contain:

**Unlock record.** Readable before unlock:

- `vault_id` and `client_id`.
- The pin `(e_p, key_id_p)` (§6.3): the newest epoch this device has verified, and its key ID. It is cleartext because unlock checks slots against it before anything can be decrypted. Key IDs aren't secret, and the pin is bound into the state record's associated data, so changing it breaks the state record.
- Local slots, each laid out as a §6.2 slot record of kind 4 with magic `"STLS"`. The protector blob comes from `PlatformProtector.wrap(slot_id, S)`. `protector_id` values:

  | `protector_id` | Protector |
  |---|---|
  | 1 | Android Keystore |
  | 2 | Windows Hello |
  | 3 | macOS Secure Enclave |
  | 4 | Linux TPM 2.0 |
  | 5 | Linux Secret Service |

**State record.** XChaCha20-Poly1305 under `local_key_{e_p}`, with associated data covering the whole unlock record. It holds:

- the device signing key `dev_sk` (§6.4)
- `next_seq`
- the HWM table
- the applied vector clock
- the local op set or cache
- pending outgoing events

Any decrypted cache of vault contents MUST live only inside this record.

A platform key that has been invalidated (for example, because biometric enrollment changed) makes `unwrap` fail with `KeyInvalidated`. The core treats that as "slot gone": delete the local slot, fall back to a synced protector, and offer to re-enroll.

## 12. Versioning

Every envelope carries `format_version = 1` and `flags = 0`.

- **Strict compatibility.** There are no ignorable extensions. Any new field, op type or semantic change bumps `format_version`. Letting older readers skip unknown ops risks devices on different versions silently computing different vault contents.
- **A newer version is not an alarm.** A reader that sees `format_version` above what it supports reports **"update required"**. It stops writing to the remote and keeps the local copy readable. Something that could also be an attacker planting a fake newer file is, at worst, the same denial of service as deleting files.
- **Anything else is malformed.** A version of 0, nonzero flags, or a version too old to be valid is rejected (§2).
- **Migration** to a new version is a full rewrite: a new snapshot plus a rotation.

## 13. What the remote learns

The remote learns:

- the vault ID
- the number of clients and the number of events per client
- file timestamps, which show when edits happen
- padded sizes, which leak O(log log n) bits of each true size (Padmé)
- the number of slots, their kinds and their Argon2 parameters
- the recovery public key `pk`, which would link vaults that shared a recovery key (forbidden, §6.2.1)
- the number of epochs and their cutover vectors
- the fact that a snapshot or purge happened

It does not learn entry contents, titles, URLs, tags, the number of entries (beyond what padded snapshot sizes reveal), or which entries changed.

## 14. Test requirements

### 14.1 Test vectors

Vectors are stored as JSON in `core/strata-core/tests/vectors/`. The reference implementation generates them, then an **independent implementation** recomputes them before they are frozen. That implementation is `core/tools/vectors/check.py`, built on Python libraries that share no code with the Rust crates. The official IETF vector for Strata's exact HPKE suite (draft-ietf-hpke-pq-04, A.5.1) is kept alongside them, and both implementations must reproduce it. Required vectors:

1. HKDF derivations for every label in §6.1 and the slot KEK.
2. Argon2id `S` for a password slot, with a non-ASCII password to exercise NFC normalization.
3. A complete slot file (each of kinds 1 to 3), an epoch record (epoch 0 and epoch 1), an event file and a snapshot file, all with fixed nonces. The kind-2 vector also fixes the HPKE ephemeral key, plus `DeriveKeyPair(R)` and the recovery anchor.
4. Padmé for body lengths at the boundaries: 0, 252, 253, 1000 and 1 MiB.
5. A merge fixture: a set of events and the expected materialized state, covering a secret conflict, LWW, delete versus concurrent edit, `KeepEntry`, tag add/remove, and device registration and renaming.
6. Ed25519 signatures over the full files in item 3. Ed25519 is deterministic, so these are fixed.

### 14.2 Property tests and fuzzing

- **Convergence.** Random op sets shuffled into any order, split across simulated clients, combined with snapshot and union at random points, MUST produce identical state. Reduction MUST NOT change what the materialized state looks like.
- **Fuzzing.** Fuzz every parser: each envelope, the CBOR bodies, the padding check, and file-name parsing.

### 14.3 Negative tests

Each of these MUST fail loudly:

| Category | Case | Expected result |
|---|---|---|
| Tampered events | any bit flipped in the envelope, ciphertext or tag | rejected |
| | renamed file (client ID or seq) | rejected |
| | wrong `vault_id` | rejected |
| | non-canonical CBOR | rejected |
| | non-zero padding | rejected |
| Swapped slots | slot copied from another vault | AEAD failure |
| | slot moved to another `slot_id` or epoch | AEAD failure |
| | substituted slot that opens to a different key | `key_id` mismatch or pin alarm |
| | fabricated vault with a recovery slot encrypted to the real `pk` | anchor check fails, slot-substitution alarm (on a fresh device too) |
| | recovery slot with its `anchor_epoch` or `anchor_tag` altered | anchor check fails |
| Replayed events | event copied to another seq | rejected |
| | old event re-uploaded after GC | ignored, state unchanged |
| | event from a retired client with `s > last_seq` | merged, flagged for review |
| | old-epoch event from a client not in the cutover | merged, device marked suspect |
| | old-epoch event from a known client, after the rotation | accepted (signature verified) |
| Forgery | AEAD-valid event with a bad signature | forgery alarm |
| | event for client `c` signed with another device's key | forgery alarm |
| | `RegisterDevice` missing from `(c, 1)`, repeated later, or naming another client | rejected |
| | snapshot or epoch record signed by a retired device after its `last_seq` | rejected |
| Rollback | highest seq lowered | rollback alarm |
| | event removed from the middle of a chain | rollback alarm |
| | older snapshot restored | rollback alarm |
| | epoch record removed | rollback alarm |
| Forks | two events with the same `(c, s)` but different content | fork alarm |

## 15. Open questions

1. ~~Rotation needs every protector present.~~ **Resolved 2026-10-11:** recovery slots use HPKE with the X-Wing post-quantum hybrid KEM, plus an anchor (§3, §6.2.1). FIDO2 tokens still have to be present at rotation, or their slots are dropped and offered for re-enrollment.
2. **Concurrent rotations** produce two records for the same epoch. A proposed rule: the record with the bytewise-lowest `key_id` wins. The losing creator unlocks the winner with a synced protector, re-issues its events from the losing epoch, and writes no further events in that epoch.
3. ~~Recovery key format.~~ **Resolved 2026-10-11:** 256 bits, shown as a 24-word BIP39 mnemonic (§6.2.1).
4. **FIDO2.** RP ID, whether user verification is required, and whether to require a resident (discoverable) credential.
5. ~~Strength thresholds.~~ **Resolved 2026-10-11:** passwords of any strength may sync. The UI warns and requires confirmation below about 10^10 estimated guesses (§6.2). PINs remain local-only.
6. **TOFU fingerprint.** Should a short `key_id` fingerprint be shown so the user can compare it across devices on first enrollment?
7. ~~Per-device signing keys.~~ **Resolved 2026-10-11:** every device signs its events, snapshots and epoch records with Ed25519 (§6.4). Late old-epoch events are attributed to their device, and only flagged when that device is retired or suspect (§7.2).
8. ~~Forward compatibility.~~ **Resolved 2026-10-11:** strict. A newer version reports "update required" rather than an alarm (§12).
9. **Garbage collection.** Is 30 days the right grace period, and should GC be automatic or user-triggered?
10. **Purge details.** Ordering and crash safety of "write snapshot, delete everything else, rotate".
11. ~~CBOR crate choice.~~ **Resolved 2026-10-11:** `minicbor`. The re-encode check (§4) is still mandatory.
12. **Attachments.** Out of scope for v1. The 1 MiB body limit excludes them.
13. **Hardware-backed device keys.** `dev_sk` is a software key in encrypted local state. Platform keystores that can do Ed25519 could hold it instead, and so could Android Keystore on newer API levels. That's a later improvement, and it doesn't change the format.
14. **Automatic revert.** When a device learns of a retirement or a suspect device, it could revert the flagged changes itself instead of waiting for the user. Concurrent reverts by several devices write the same values, so they need to be harmless (identical values shouldn't show as a conflict). That would make revocation self-cleaning.

## 16. References

- RFC 2104 (HMAC). RFC 5869 (HKDF). RFC 8032 (Ed25519). RFC 9106 (Argon2). RFC 8439 (ChaCha20-Poly1305). draft-irtf-cfrg-xchacha (XChaCha20). RFC 8949 (CBOR). RFC 9180 (HPKE).
- FIPS 203 (ML-KEM). draft-connolly-cfrg-xwing-kem (X-Wing). draft-ietf-hpke-pq (post-quantum KEMs for HPKE, X-Wing codepoint `0x647a`).
- Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs", PETS 2019 (Padmé).
- Kulkarni et al., "Logical Physical Clocks and Consistent Snapshots in Globally Distributed Databases", 2014 (HLC).
- Shapiro et al., "Conflict-free Replicated Data Types", 2011. Almeida et al., "Delta State Replicated Data Types", 2018.
- Len, Grubbs and Ristenpart, "Partitioning Oracle Attacks", USENIX Security 2021.
- LUKS2 on-disk format specification. The age file format specification (C2SP).
