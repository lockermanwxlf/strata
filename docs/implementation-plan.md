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
  | `crypto/` | `aead.rs`, `kdf.rs`, `recovery.rs`, `sign.rs`, `secret.rs` |
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
- **`recovery.rs`:**
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
- **Independent cross-check.** `core/tools/vectors/check.py` recomputes every vector with libraries that share no code with the Rust crates: the Python standard library, `argon2-cffi`, PyNaCl (libsodium), `mnemonic`, `cryptography` (OpenSSL ML-KEM and X25519) and `kyber-py`. X-Wing and HPKE are written out from the drafts and first validated against the official IETF vector. Run it with `uv run core/tools/vectors/check.py`; uv supplies Python, so nothing needs installing besides uv. CI runs it too.
- **The official IETF vector** for the exact HPKE suite (draft-ietf-hpke-pq-04, A.5.1) must be reproduced by both implementations.

**Exit:** the vectors pass in Rust and in Python. Then a **review checkpoint: crypto primitives.**

**Status: done (2026-10-11).**

- **Tests:** 46 Rust tests pass. The frozen vectors in `tests/vectors/` pass the independent Python check (51 checks). Both implementations reproduce the IETF X-Wing vector A.5.1.
- **Review checkpoint:** a high-effort code review produced 7 findings, and 6 are fixed:
  - a panic on a malformed recovery public key
  - HKDF/HMAC state not zeroized (fixed with the `sha2`/`hmac` `zeroize` features)
  - a buffer reallocation in BIP39 parsing
  - NFC normalization buffers (avoided entirely for passwords that are already NFC)
  - missing fuzz targets for `unpad` and `decode_strict`
  - possible overflow in `padded_len`
- **Skipped:** copying the file to prepend the signature prefix, because dalek's streaming verifier skips the strict small-order checks.
- **Rename:** `hpke.rs` from the plan is `recovery.rs`. It also holds the BIP39 code.

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

**Status: done (2026-10-11).**

- **Modules:** `format/` has `body`, `names`, `vault_info`, `slot`, `epoch`, `event` and `snapshot`. Every parser enforces its size limit before allocating, and a newer `format_version` yields `UpdateRequired`.
- **Tamper tests:** a bit flip at every offset of a slot, epoch record, event and snapshot is caught. Renamed files, wrong vault IDs, non-canonical CBOR, nonzero padding, and well-formed bodies that break a rule are all rejected.
- **Vectors:** `files.json` has a vector for every file type. `check.py` rebuilds each one byte for byte from the spec (60 checks in total).
- **Fuzz targets:** `reader`, `padding`, `envelopes`, `bodies` and `names`.
- **Fuzzing:** each target ran 10 minutes in WSL under AddressSanitizer, starting from seeds generated from the vectors (`core/fuzz/seeds`). About 1.5 billion executions, no crashes. Windows can't link the fuzz targets, so use `core/tools/fuzz/run-wsl.sh` or CI.

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

**Status: done (2026-10-12).**

- **Modules:** `keys/create.rs` (vault creation), `keys/unlock.rs` (spec §6.3 and the recovery path of §6.2.1), `keys/strength.rs` (zxcvbn, input capped at 100 characters), `local/` (local state, `FsLocalStore` and its platform data directories), and the minimal `sync/store.rs` (`RemoteStore` with size-capped reads, plus `MemoryStore`).
- **Spec changes:** the pin moved to the cleartext unlock record, bound into the state record's associated data, so unlock can check slots before decrypting anything. It advances to the newest verified epoch. Unlock tries at most 8 slots, and only those whose epoch has a record.
- **Tests:** all the cases listed above pass, plus rotation through the chain, a newer unreachable epoch, tampered local state, an oversized planted file, a decoy epoch record, and update-required.
- **Review checkpoint:** a high-effort code review found 6 issues and 5 are fixed:
  - the chain walk now tries every record with a matching key ID
  - local-state saves fsync the directory on Unix
  - zxcvbn input is capped
  - the number of key files is capped
  - `LocalState::seal` checks the key against the pin
- **Kept as is:** a folder left by interrupted setup is refused with a clear message rather than cleaned up automatically.
- **Deferred to Phase 5:** checking epoch-record signatures, which needs the device registry from events (spec §6.4).

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

**Status: done (2026-10-12).**

- **Modules:**
  - `model/hlc.rs`: HLC generation, counter carry, far-future check
  - `model/clock.rs`: vector-clock `observe`, `merge` and `covers`
  - `merge/mod.rs`: `OpSet` with idempotent `apply_event`, `union`, happened-before, and §9.3 reduction in one pass
  - `merge/view.rs`: the materialized view, borrowing secret values from the op set
  - `merge/edit.rs`: `Edit` turned into ops. `RemoveTag` lists the adds it observed, and `password`/`otp` are always secret.
- **Spec changes:** a "conflict" in which every candidate is null is no conflict, and the field is absent. A `RemoveTag` drops an add only for the same `(x, t)`.
- **Tests:**
  - One scenario per §9.2 rule, each also checked under reduction.
  - Two property tests: three simulated devices edit, sync and reduce at random, and the shuffled full log must match. Reduced overlapping parts, unioned, must match the whole. Both pass at 10,000 cases (8 s), and a deliberately injected reduction bug makes both fail.
  - Views are compared with their secret values included, not just through `Debug`, which redacts them.
- **Vector:** `merge.json` covers events from 3 devices across 4 entries. The frozen view matches a hand derivation, and `check.py` recomputes it with an independent Python implementation of §9.2 (61 checks in total).

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
  - flag rather than reject: changes by retired devices after their `last_seq`, and devices registered under an old key after a rotation (suspect), go on a review list (spec §7.2, §9.2)
  - track the applied vector clock and the HWM
- **Alarms:** rollback, fork, substitution and forgery. After an alarm the device makes no further writes and stays readable from local state.
- **Client identity:** detect lost or restored local state and generate a new `client_id`.

**Tests:**

- §14.3 replay, rollback, fork and forgery cases, run against the adversarial store. The forgery cases include a simulated malicious device that holds the vault key.
- Multi-client simulation: N clients with random edits and random sync schedules converge. This is the convergence property test from Phase 4, run end to end through the file format.

**Exit:** the simulations converge, every adversarial case is caught, and there are no false alarms in honest runs. **M2 needs Phase 6 as well.**

**Status: done (2026-10-12).**

- **Modules:**
  - `sync/fs_store.rs`: publishes through a hard link from a dot-prefixed temp file, which is atomic and never overwrites. Falls back to `create_new` where hard links aren't supported. Reads are size-capped, paths are confined to the vault, and the directory is fsynced on Unix.
  - `sync/session.rs`: `Session` with `sync`, `write` and `review`.
- **The pipeline (spec §9.1):** parse and name check; epoch key, with the event held if the key is unknown; decrypt and validate; causal delivery; device signature (forgery alarm); `prev_hash` (fork alarm); clock and HLC monotonicity.
- **Detection (spec §9.4):** on every sync each high-water mark is checked against the store (rollback, fork) and against what was applied. Epoch-record signatures are checked once the creator is registered.
- **Writing:** the seq and the sealed event are persisted as pending before upload, and failed uploads are retried. Stale local state, as after a backup restore, turns the device into a new client.
- **Design change:** retirement and old-epoch late events are flagged for review rather than ignored or quarantined. Order-dependent rejection broke convergence, and retroactive ignoring broke reduction (spec §9.2 design note, OPEN-14).
- **Review checkpoint:** a high-effort code review found 4 issues and 3 are fixed:
  - after a rotation, a session stops writing until it unlocks again (`KeyRotated`), and pending events are re-sealed under the new key
  - nothing is uploaded after an alarm
  - the device name is checked up front
- **Kept as is:** one session per device at a time is documented, for the app layer to enforce.
- **Tests:** 21 sync tests, covering two devices, restarts on disk, rollback, fork, a reused seq, backup restore, relocated or foreign events, forgery of events and epoch records, held dependencies, retried uploads, review flags, suspect devices, rotation, and a convergence property test through the store.

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

**Status: done (2026-10-12), except purge, which moved to Phase 7.**

- **Session API:**
  - `write_snapshot`: reduces the op set and writes a snapshot with the watermark and a vector-clock table.
  - `collect_garbage(grace)`: deletes events under this device's own ripe snapshots, and its own dominated snapshots, keeping the newest of equal ones.
  - `snapshot_due`: true from 512 event files.
  - `GC_GRACE_MS` is 30 days (OPEN-9).
- **Loading:** checks the creator's signature (trusting its own registration on first use), checks the watermark against applied events (fork alarm), takes the union, and counts the watermark as applied, with watermark hashes standing in for compacted predecessors.
- **Spec fixes:**
  - an older snapshot is not a rollback; rollback is detected through coverage by snapshots still in the store
  - a device deletes only on the strength of its own snapshots
  - high-water marks that only an unreadable newer-epoch snapshot could cover are reported as unverified, not raised as an alarm
- **Bugs caught by tests:** coverage counted snapshots deleted since loading, and two equal snapshots deleted each other.
- **Tests:** a fresh device after compaction, GC rules and grace, a restored older snapshot (rollback), a replayed compacted event, a contradicting snapshot (fork), a bad snapshot signature (forgery), unverified integrity across a rotation, and a property test with random snapshots and GC whose late joiner must match. The store-level property tests pass at 200 cases.

### Phase 7: Rotation and slot management (M) · spec §7.2

- **Rotation procedure:**
  - new epoch record with a cutover vector
  - re-wrap every kept slot: prompt for the password, re-wrap the recovery slot to its public key, drop absent FIDO2 slots
  - re-wrap this device's local slots, then delete the old slots
- **Operations built on it:** change password, add slot, remove slot (which always rotates), regenerate recovery key, revoke device (`RetireClient` plus rotation).
- **Other devices:** after a rotation they fall back to the password once, then re-wrap their local slots silently.
- **Review UX hooks:** list flagged changes by device (`Session::review`), and revert them as ordinary new ops. Automatic revert is OPEN-14.
- **Concurrent rotations,** per the OPEN-2 decision.
- **Purge** (moved here from Phase 6, because it needs rotation): write a snapshot without the entry, delete every other file, then rotate (spec §10.4, OPEN-10).

**Tests:**

- A retired device's events past `last_seq` are rejected.
- Old-epoch events from a device unknown at the rotation mark it suspect, and its changes are flagged.
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
  - `status() -> VaultStatus`, which covers alarms, conflicts, unanswered deletes, flagged changes and "key rotated, unlock again"
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
- **M3 screens:** slot management, change password, recovery-key regeneration, revoke device, review of flagged changes.
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
