# Strata implementation plan

This plan builds the vault described in [spec.md](spec.md) (draft 0.3). Each phase ends with exit criteria. Phases are ordered by dependency; §4 shows what can run in parallel.

Ground rules (from CLAUDE.md):

- Implement against the spec. When the spec is unclear or wrong, change the spec first, then the code.
- Secrets stay in Rust memory and are zeroized. On the Kotlin side they are `ByteArray`/`CharArray`, never `String`.
- The FFI stays coarse-grained.
- **Review checkpoints.** Phases that touch crypto end with a review in a fresh context (a separate review agent or `/security-review`) that checks the phase's code against the spec. Findings are fixed before the next phase starts. Nothing waits on the project owner's approval.
- **Real passwords.** Until the external review in Phase 13, treat every vault as test data.

## 1. Milestones

| Milestone | Outcome | Phases |
|---|---|---|
| **M1: Single-device vault** | Create a vault in a local folder on desktop, add, edit and delete entries, lock, and unlock with the password or the recovery key | 0–4, 8 (minimal), 9 (minimal) |
| **M2: Multi-device sync** | Two or more devices share one folder (Syncthing, Dropbox and so on) and converge. Rollback, fork and replay alarms work | 5, 6 |
| **M3: Key management** | Change the password, regenerate the recovery key, add and remove slots, revoke a device by rotation | 7 |
| **M4: Platform unlock** | Biometric or keystore unlock on Windows, Android and Linux, with macOS as far as signing allows. Android app at parity | 10, 11 |
| **M5: Import/export** | KDBX import and export | 12 |
| **M6: Ready for real passwords** | Fuzzing campaign and an external review of the spec and crypto | 13 |

## 2. Decisions needed and when

These are the open questions from spec §15, ordered by the phase that needs them.

| Question | Needed by | Why then |
|---|---|---|
| OPEN-6: key-ID fingerprint | Phase 9 (UI) | It's UI-only, so it can come late. |
| OPEN-9: GC grace period | Phase 6 | |
| OPEN-10: purge details | Phase 6 | |
| OPEN-2: concurrent rotations | Phase 7 | |
| OPEN-4: FIDO2 details | Phase 10 | Starts with a research spike. |
| OPEN-12: attachments | After v1 | |
| OPEN-13: hardware-backed device keys | After v1 | Doesn't change the format. |

Resolved: OPEN-1 (HPKE recovery slot), OPEN-3 (BIP39), OPEN-5 (passwords warn, not block), OPEN-7 (Ed25519 device keys), OPEN-8 (strict versioning), OPEN-11 (`minicbor`).

**Not in the spec yet:**

- **Which remotes to support.** The plan assumes "a local folder that the user syncs with any tool" for v1, plus Android's Storage Access Framework (SAF) for folders on Android. WebDAV, S3 and similar are product decisions for later.
- **Auto-lock and clipboard policy:** timeouts, and clearing the clipboard after copying a secret. These are UI decisions for Phase 9.

## 3. Phases

### Phase 0: Groundwork (S)

- **Crate structure** in `core/strata-core/src/`:

  | Module | Contents |
  |---|---|
  | `crypto/` | `aead.rs`, `kdf.rs`, `hpke.rs`, `sign.rs`, `secret.rs` |
  | `encoding/` | `reader.rs`, `cbor.rs`, `padding.rs` |
  | `format/` | `names.rs`, `vault_info.rs`, `slot.rs`, `epoch.rs`, `event.rs`, `snapshot.rs` |
  | `keys/` | key chain and pinning |
  | `model/` | ops, dots, vector clocks, HLC |
  | `merge/` | op set, reduction, materialization |
  | `sync/` | sync engine |
  | `local/` | device-local state |
  | `vault.rs` | high-level API |
  | `ffi.rs` | UniFFI exports |
  | `platform/` | platform protectors |

- **Dependencies:**
  - Runtime: `chacha20poly1305`, `argon2`, `hkdf`, `sha2`, `hmac`, `hpke` (X-Wing via its `mlkem` feature), `ed25519-dalek`, `subtle`, `zeroize`, `getrandom`, `unicode-normalization`, `minicbor`, `bip39`. Default features are trimmed to what the spec uses. `zxcvbn` is added in Phase 3, where it's first used.
  - Dev: `proptest`. `serde_json`, `hex` and `tempfile` are added when first used.
- **Secret types:** `SecretKey`, plus `SecretBytes` wrapping `Zeroizing<Vec<u8>>`.
  - They implement `ZeroizeOnDrop`, and their `Debug` prints `[redacted]`.
  - They don't implement `Clone`, except where explicit.
  - Equality compares in constant time through `subtle`.
- **Errors:** one `CoreError` enum that separates:
  - `Rejected { what, why }`: malformed or unauthenticated input
  - `Alarm { kind }`: rollback, fork, substitution or forgery
  - `UpdateRequired`: the vault uses a newer format version (spec §12). This is not an alarm.
  - `Locked`, `Io`, `Policy`
- **CI additions:**
  - `cargo deny` (licenses and advisories)
  - a nightly job that builds the fuzz targets and runs each for 60 seconds
  - the test-vector cross-check (Phase 1)
- **Rust linting:** `#![forbid(unsafe_code)]` in the format and merge modules. Platform modules may opt out where FFI calls need `unsafe`.

**Exit:** the crate structure compiles, and CI runs the new jobs, even though they're still empty.

**Status: done (2026-10-11).**

- **Code:**
  - `SecretKey` and `SecretBytes` are in `crypto/secret.rs`.
  - `CoreError` and `AlarmKind` are in `error.rs`.
  - The bounds-checked `Reader` is in `encoding/reader.rs`, with a property test and the first fuzz target (`core/fuzz`, target `reader`).
- **Tooling:**
  - `core/deny.toml` allows only GPL-compatible licenses. `minicbor` is BlueOak-1.0.0, which is permissive.
  - CI has new `deny` and `fuzz` jobs.
- **Deferred to Phase 1:** the test-vector cross-check job, because there are no vectors yet.

### Phase 1: Crypto primitives and encodings (M) · spec §2–4, §6.1, §6.2.1

All pure functions with no I/O.

- **`kdf.rs`:**
  - one constant per HKDF label (§6.1), plus the slot KEK
  - Argon2id with the parameter bounds, NFC-normalizing the password and zeroizing intermediate values
- **`aead.rs`:** XChaCha20-Poly1305 seal and open with an explicit AAD. Nonces come from `getrandom`; tests can inject them.
- **`hpke.rs`:**
  - `DeriveKeyPair(R)`, plus seal and open for the recovery suite
  - the recovery anchor computation and its constant-time check
- **`sign.rs`:** Ed25519 sign with the `"strata v1 signature"` prefix, and strict verification (`verify_strict`).
- **Recovery key encoding:** BIP39 encode and decode of `R`. Decoding gives distinct errors for a wrong word, a wrong word count, and a bad checksum.
- **`padding.rs`:** `padme` and the padding check (§4).
- **`cbor.rs`:** deterministic encode and decode, the re-encode-and-compare check, and the allowed-types restriction.
- **`reader.rs`:** a bounds-checked byte reader for envelopes. It never panics on bad input.

**Tests:**

- Unit tests per function.
- **Test vectors** for §14.1 items 1, 2 and 4, and the HPKE and anchor parts of item 3, in `core/strata-core/tests/vectors/*.json`.
- **Independent cross-check.** `core/tools/vectors/check.py` recomputes every vector with Python `cryptography`, `argon2-cffi` and `cbor2`. CI runs it on Ubuntu. Python isn't installed on the Windows dev machine, so it runs in CI only, unless Python is installed later.
  - **X-Wing HPKE needs a second implementation that supports KEM `0x647a`.** Finding one is the first task of Phase 1. Candidates are Go's HPKE packages (for example `filippo.io/hpke`) or a Python package, if a maintained one exists. If none fits, cross-check against the draft's published test vectors instead.

**Exit:** the vectors pass in Rust and in Python. Then a **review checkpoint: crypto primitives.**

### Phase 2: File formats (M) · spec §5, §6.2, §7.1, §8.1–8.2, §10.1

- **Parse and serialize** each envelope and body, enforcing every size limit before allocating:
  - `strata-vault`
  - slot files (kinds 1–3 in `slots/`; kind 4 only in the local `"STLS"` form)
  - epoch records
  - events
  - snapshots
- **Signatures:** the trailing signature on events, snapshots and epoch records (spec §2, signature rule), split off and checked by the format layer.
- **Version handling:** a newer `format_version` produces `UpdateRequired`, not `Rejected`.
- **File-name parsing** with exact patterns, and the check that a file's name matches its contents.
- **Op and body schemas** as Rust types. Each round-trips through CBOR.
- **Fuzz targets** (`core/fuzz/`): one per envelope parser, the body decoders, the padding check, and name parsing.

**Tests:**

- §14.1 items 3 and 6: full-file vectors for every type, signatures included.
- §14.3 "tampered events":
  - a bit flip at every offset of a sample file must fail
  - renamed file
  - wrong `vault_id`
  - non-canonical CBOR
  - non-zero padding

**Exit:** the vectors and negative tests pass, and each fuzz target runs for 10 minutes without crashing. **Formats are frozen** for v1 from here on; changing them means updating the spec and the vectors.

### Phase 3: Keys, slots, unlock and local state (M) · spec §6.2–6.3, §7.1, §11

- **Vault creation:**
  - write `strata-vault` and the epoch 0 record
  - create a password slot and a recovery slot, with the anchor
  - generate the BIP39 recovery key
  - generate this device's `client_id` and Ed25519 device key. The first event registers the device.
- **Unlock** with the password or the recovery key: the full §6.3 procedure, including the `key_id` check, pinning, the chain walk and the anchor check.
- **Policy:** enforce `check_slot_policy` when creating slots, and the password strength estimate (`zxcvbn`) that the UI uses for its warning.
- **Local state:**
  - the unlock record (cleartext: `client_id` and local slots)
  - the state record, encrypted under `local_key_e`, with atomic writes
  - a `LocalStore` trait whose default implementation is the filesystem
  - platform paths for where local state lives (`%LOCALAPPDATA%`, the XDG data directory, Application Support, Android `filesDir`)

**Tests** (§14.3 "swapped slots" and the anchor cases):

- slot copied from another vault
- slot moved to another slot ID or epoch
- substituted slot
- fabricated vault opened with the real recovery key
- altered anchor
- stale slot below the pinned epoch

**Exit:** unlock works and every negative test fails loudly with the right alarm. Then a **review checkpoint: key handling and unlock.**

### Phase 4: Data model and merge (M) · spec §8.2–8.3, §9.2–9.3

This phase is pure logic with no crypto, so it can start right after Phase 0, in parallel with Phases 1–3.

- **Model:** dots, vector clocks (compare, merge, dominate), and HLC generation and checks.
- **Op set:** happened-before, the reduction rules (§9.3), and union.
- **Materialization:**
  - entries and fields
  - secret conflicts, presented as candidate sets
  - last-writer-wins for non-secret fields
  - deleted entries and unanswered deletes
  - tags
  - the device registry: keys, names and retirement
- **Edit API:** `EditBatch` → ops. For example, "set fields", "delete entry", "keep entry", "resolve conflict" and "add/remove tag" each become ops carrying the correct dots and vector clocks.

**Tests:**

- §14.2 convergence property tests: shuffle, split across simulated clients, union at random points. Reduction must not change the result.
- §14.1 item 5: merge fixtures, including concurrent password changes, delete versus concurrent edit, `KeepEntry`, and tag add/remove.

**Exit:** the property tests pass with at least 10,000 cases each, and the fixtures are frozen.

### Phase 5: Event log and sync engine (L) · spec §5, §6.4, §7.2 (old-epoch events), §9.1, §9.4

- **`RemoteStore` trait:** `list`, `read`, `create_exclusive`, `delete`.
  - **Filesystem implementation:** write a temp file starting with `.`, then do a no-overwrite rename. The mechanism differs per OS:

    | OS | No-overwrite rename |
    |---|---|
    | Windows | `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` |
    | Linux | `renameat2(RENAME_NOREPLACE)`, falling back to `link` + `unlink` |
    | macOS | `renamex_np(RENAME_EXCL)` |

  - **Adversarial in-memory store for tests:** it can delete, roll back, replay, reorder, delay and duplicate files, and inject sync-provider conflict copies.
- **Writing events:**
  1. Persist `next_seq` durably.
  2. Encrypt, then `create_exclusive`.
  3. If the name already exists, raise a fork alarm.
- **Sync pipeline** (§9.1):
  - validate events, including signatures against the device registry
  - hold events until their causal dependencies arrive, with a warning after 7 days
  - run the retirement check
  - run the old-epoch rule: accept events from devices known at the rotation, quarantine the rest
  - track the applied vector clock and the HWM
- **Alarms:** rollback, fork, substitution and forgery. After an alarm the device makes no further writes and stays readable from local state.
- **Client identity:** detect lost or restored local state and generate a new `client_id`.

**Tests:**

- §14.3 replay, rollback, fork and forgery cases, run against the adversarial store. The forgery cases include a simulated malicious device that holds the vault key.
- Multi-client simulation: N clients with random edits and random sync schedules converge. This is the convergence property test from Phase 4, run end to end through the file format.

**Exit:** the simulations converge, every adversarial case is caught, and there are no false alarms in honest runs. **M2 needs Phase 6 as well.**

### Phase 6: Snapshots, garbage collection and purge (M) · spec §10

- Write snapshots from the reduced op set. Load them (union) with the watermark-versus-HWM check.
- Choose when to snapshot automatically, for example after N events or when the event file count passes a threshold.
- GC after the grace period (OPEN-9). Delete old snapshots that a newer one dominates.
- Purge (OPEN-10): snapshot without the entry, delete everything else, then rotate (rotation comes in Phase 7, so purge lands after it).

**Tests:**

- Property: snapshot plus the remaining events gives the same result as all events, with snapshots taken at random points and by random clients.
- Restoring an older snapshot raises a rollback alarm.
- A replay after GC is ignored.

**Exit:** properties and negative tests pass, and the GC grace period is decided.

### Phase 7: Rotation and slot management (M) · spec §7.2

- **Rotation procedure:**
  - new epoch record with a cutover vector
  - re-wrap every kept slot: prompt for the password, re-wrap the recovery slot to its public key, drop absent FIDO2 slots
  - re-wrap this device's local slots, then delete the old slots
- **Operations built on it:** change password, add slot, remove slot (which always rotates), regenerate recovery key, revoke device (`RetireClient` plus rotation).
- **Other devices:** after a rotation they fall back to the password once, then re-wrap their local slots silently.
- **Quarantine UX hooks:** list quarantined events, apply or discard them, and re-issue this device's own quarantined events.
- **Concurrent rotations,** per the OPEN-2 decision.

**Tests:**

- A retired device's events past `last_seq` are rejected.
- Old-epoch events from a device unknown at the rotation are quarantined.
- A revoked device can't read new events.
- A replayed old password slot doesn't open the current epoch.
- An offline device that was known at the rotation and not revoked has its late events accepted.

**Exit:** the tests pass. Then a **review checkpoint: rotation and revocation.**

### Phase 8: FFI surface (M)

Built in stages:

- **M1 subset:** create, unlock, list, edit, lock.
- **Later stages:** sync (Phase 5), slots and rotation (Phase 7).

The API is coarse-grained, as CLAUDE.md requires:

- **Vault handle:** a `Vault` UniFFI object.
  - Lifecycle: `create(dir, password, …)` and `open(dir)`.
  - Unlock: `unlock_password(bytes)`, `unlock_recovery(words)`, `unlock_local(protector)`.
  - `lock()`.
- **Reading:**
  - `entries() -> List<EntrySummary>`: no secrets in summaries.
  - `entry(id) -> EntryDetail`: secret fields show only a placeholder.
  - `reveal(id, field) -> ByteArray`: the caller zeroes the result.
- **Changes and status:**
  - `apply(EditBatch)`
  - `sync() -> SyncReport`
  - `status() -> VaultStatus`, which covers alarms, conflicts, unanswered deletes and quarantine
- **Key management:** `password_strength(bytes)`, `slots()`, `add_slot`, `remove_slot`, `change_password`, `regenerate_recovery_key`, `revoke_device`.

Implementation notes:

- Use UniFFI async for anything slow (Argon2, sync) so it never runs on the UI thread.
- Kotlin `actual`s in `jvmMain` and `androidMain` wrap the generated API behind the `expect` declarations in `NativeCore.kt`.

**Tests:** `:shared:jvmTest` covers each call against the real library, including checking that revealed `ByteArray`s can be zeroed and that no API returns a secret as a `String`.

### Phase 9: UI (L, in stages alongside 5–8)

- **M1 screens:**
  - create vault (with the weak-password warning and confirmation, OPEN-5)
  - show the recovery key once as BIP39 words, then confirm it
  - unlock
  - entry list and search, entry detail with reveal and copy, entry edit
  - lock and auto-lock
  - clipboard auto-clear
- **M2 screens:**
  - sync status
  - secret-conflict resolution (show the candidates, pick one or enter a new value)
  - "deleted on another device: keep or delete?"
  - the alarm screen
- **M3 screens:** slot management, change password, recovery-key regeneration, revoke device, quarantine review.
- **Android:** reuse the shared UI. Release builds keep `FLAG_SECURE`, and the recovery-key screen especially needs it.
- **Key fingerprint:** if OPEN-6 is approved, show the key-ID fingerprint at enrollment.

### Phase 10: Platform protectors (L) · spec §6.2, CLAUDE.md "Platform protectors"

One at a time, each under 200 lines with no policy logic, each reporting its `ProtectorCaps` honestly:

1. **Windows Hello** (Rust, `windows` crate): the HWND is passed from Kotlin. This is the dev machine, so it goes first.
2. **Android Keystore** (Kotlin foreign trait): StrongBox, falling back to TEE; `BiometricPrompt` with a `CryptoObject`; check `KeyInfo.securityLevel`. Tested on the emulator, then a real device.
3. **Linux:** TPM 2.0 (`tss-esapi`) with a PIN. When there's no TPM, use Secret Service (`keyring`), reported as not rate-limited, so the policy refuses PIN slots on it.
4. **macOS Secure Enclave** (`security-framework`): needs a signed build with entitlements. It's blocked until a Mac and a signing identity are available, but CI keeps it compiling.
5. **FIDO2 `hmac-secret`:** a research spike first (OPEN-4). The Windows WebAuthn API and Android's FIDO2/PRF support differ, and a direct CTAP crate may be needed on desktop.

**Tests:** in-process fake protectors cover the core logic: `KeyInvalidated` meaning "slot gone", user cancellation, and capability reporting. Each real protector also gets a manual test checklist.

### Phase 11: Android storage and parity (M)

- `RemoteStore` as a Kotlin foreign trait over the Storage Access Framework (SAF), so the user can pick a synced folder.
- Checks for no-overwrite rename on SAF providers, falling back to create-exclusive by name. Behavior varies by provider, so a manual test matrix is needed.
- Background sync with WorkManager, while the vault is unlocked or using the local slot.

### Phase 12: KDBX import/export (M)

- Use the `keepass` crate.
  - **Field mapping:** KDBX "protected" maps to `secret`.
  - **Unknown fields** round-trip as `kdbx:` fields.
  - **History:** imported as events.
- **Export** writes a KDBX file the user chooses, with a warning that it is not protected by Strata.
- **Tests:** round-trip fixtures from KeePassXC files, checking that unknown fields survive.

### Phase 13: Hardening and review (M)

- A long fuzzing campaign: hours per target, with the corpora committed.
- Audit memory hygiene: no secrets in `Debug` output, logs, panics or error messages, and zeroization on every path, including error paths.
- Walk through the threat model: each claim in spec §1 is mapped to the test that demonstrates it.
- **External review** of the spec and the crypto code by someone qualified in applied cryptography. This is the step before trusting Strata with real passwords. When it's done, the spec's status changes to "Reviewed".

## 4. Order and parallelism

```
Phase 0 ──┬─> Phase 1 ─> Phase 2 ─> Phase 3 ─┬─> Phase 5 ─> Phase 6 ─┐
          │                                  │                       ├─> Phase 7 ─> (purge)
          └─> Phase 4 ───────────────────────┘                       │
                                                                     │
Phase 8 / Phase 9: in stages, M1 subset after Phases 3 + 4, then following 5–7
Phase 10: after 8. Windows first; Android needs 11 for a full app
Phase 12: any time after 8.   Phase 13: last; fuzzing starts in Phase 2
```

**Suggested first session:** Phase 0, then Phase 1 up to the HKDF, AEAD and padding vectors. Nothing blocks starting.
