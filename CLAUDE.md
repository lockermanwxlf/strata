# Strata

Cross-platform password vault. Targets: Windows 11, macOS, Linux, Android. iOS is out of scope for now (no test device), but nothing should rule it out.

## Architecture

- **`core/strata-core` (Rust):** everything security-critical: vault format, crypto, CRDT merge, sync, slot policy. Secrets live in Rust memory and are wiped with `zeroize`. The core's global allocator (`alloc.rs`) also zeroes every heap block on free, which covers copies `zeroize` can't reach: grown `Vec`s and UniFFI's transfer buffers.
- **UniFFI** generates the Kotlin bindings (`dev.lockermanwxlf.strata.core.ffi`) from the built library. Never edit generated code. Change the Rust and rebuild.
- **`shared` (Kotlin Multiplatform + Compose Multiplatform):** UI in `commonMain`: `ui/VaultController.kt` holds the state and makes every vault call; the screens only render it. Platform specifics (folder picker, clipboard, secure window) come in through `AppHost`, implemented in `desktopApp` and `androidApp`. Common code uses the platform-neutral API in `commonMain/.../Vault.kt` (`StrataCore`, `VaultHandle`). Its one implementation, `src/jna/kotlin/.../NativeVault.kt`, compiles into both `jvmMain` and `androidMain` together with the generated bindings (they use JNA), and runs every call on `Dispatchers.IO`.
- **`desktopApp`:** Compose Desktop entry point and packaging (jpackage).
- **`androidApp`:** Android entry point. AGP 9 forbids an application module from also being a KMP module, which is why it's separate. It cross-compiles the core with cargo-ndk into jniLibs.
- **Android vault folders** come from the system folder picker (Storage Access Framework) as content URIs, not paths. `androidApp/.../SafFolder.kt` implements the common `VaultFolder`, which reaches the core as the `ForeignFolder` foreign trait (`sync/foreign_store.rs`). The core validates paths and re-checks names and sizes, so `SafFolder` only moves bytes. SAF has no create-exclusive, so `create` checks the name afterwards (spec §5).

Keep the FFI API coarse-grained, e.g. "decrypted list view", "apply edit", "sync". Never make one call per field. The surface is `ffi.rs`: one `Vault` object per open vault. Secrets cross only as `ByteArray`, revealed one value at a time, and the Kotlin wrapper wipes every `ByteArray` argument once the core has it.

## Key hierarchy (LUKS / age style)

- **Vault key:** random 256-bit, one per key epoch. HKDF derives the key ID and the event, snapshot, epoch-chain and local-state keys from it. There is no MAC subkey; AEAD associated data binds all context.
- **Slots:** each slot wraps the vault key under a KEK derived from one protector: password (Argon2id), FIDO2 `hmac-secret`/YubiKey, or platform keystore. The exception is the 256-bit recovery key, which is an X-Wing key pair (HPKE; X25519 + ML-KEM-768 hybrid, so files harvested today stay safe against future quantum computers). Rotation can re-wrap to its public key without the user producing the recovery key, and an anchor MAC stops a fabricated vault from opening with it (spec §6.2.1).
- **Slot scope:** `Synced` slots live in `slots/` on the remote. `Local` slots live only on the device and are never uploaded.
- **Policy** (`policy.rs`, enforced in core, not only in the UI): PINs (weak protectors) are never synced, and locally they require a hardware-backed **and** rate-limited keystore. Passwords sync whatever their strength (the user's choice), but the UI warns about weak ones and requires confirmation.
- **Slot-substitution defense:** store a key commitment / key ID, pin it locally on first enrollment, and refuse slots that unwrap to a different key.
- **Device signing keys:** each device has an Ed25519 key, registered in its first event. It signs that device's events, snapshots and epoch records, so no key holder can forge another device's changes (spec §6.4).
- **Revocation = rotation:** key epochs. New events use the new epoch key, and old epoch keys are stored wrapped under the new one. Removing a slot does not revoke a device that has already unlocked.

## Platform protectors

`PlatformProtector` (in `protector.rs`) is a UniFFI foreign trait: `capabilities`, async `wrap`/`unwrap`, `delete`.

- Protectors only ever see a random per-slot **slot secret**. The core derives the KEK from it and wraps the vault key itself, so the vault key never crosses FFI. Zero buffers on both sides immediately.
- **Android (Kotlin, `androidApp/.../KeystoreProtector.kt`):** one Keystore AES-GCM key for the app, `setIsStrongBoxBacked(true)` with TEE fallback, `setUserAuthenticationRequired(true)`, wrap and unwrap via the platform `BiometricPrompt` + `CryptoObject`, slot ID as associated data. Verify `KeyInfo.securityLevel` before reporting `hardwareBacked`.
- **Shared keys:** a protector may use one hardware key for every slot, binding the slot ID into each wrap; then `delete` is a no-op. While unlocked, the core keeps the slot secret so it can re-wrap local slots after a key change without another prompt (spec §11).
- **Windows (Rust, `windows` crate, `protector/windows_hello.rs`):** one Hello `KeyCredentialManager` credential for the app signs a fixed per-slot challenge; a hash of that deterministic (RSA PKCS#1 v1.5) signature wraps the slot secret. There is no window-parented API for Hello keys, so while the prompt opens the protector brings the "Credential Dialog Xaml Host" window to the front.
- **macOS (Rust, `security-framework`):** Secure Enclave P-256 key with `biometryCurrentSet`/`userPresence`, `SecKeyCreateEncryptedData` (ECIES). Requires a signed app with entitlements.
- **Linux (Rust, `protector/linux.rs`):** TPM 2.0 (`tss-esapi`) seal with PIN auth, which counts as rate-limited; the app asks for the PIN itself. Otherwise Secret Service (`keyring`), reported as **not** rate-limited. Test both with `core/tools/linux-protectors.sh` (software TPM and a throwaway keyring; WSL or CI).
- **Implementations stay thin** (<200 lines): wrap, unwrap, delete. No policy or format logic.
- An invalidated key (biometric enrollment changed) means "slot gone": fall back to the master password and offer re-enrollment.
- **Screenshots (Android):** release builds always set `FLAG_SECURE`. Debug builds allow screenshots (`BuildConfig.ALLOW_SCREENSHOTS`, set per build type), so never use a debug build with a real vault.

## Vault format (event-sourced)

A vault is a directory of immutable files. Clients only create new uniquely named files, so there are no write conflicts and no locks.

```
vault/
  strata-vault               # vault ID, format version (written once)
  epochs/<epoch>-<clientId>.epoch   # key ID, previous epoch key wrapped under this one
  slots/<slotId>.slot        # synced slots
  events/<clientId>-<seq>.evt
  snapshots/<snapshotId>.snap
```

- **Each event:** ID, hybrid logical clock timestamp, causal info (vector clock or parents), an AEAD payload, and the writing device's signature. The vault ID, event ID and epoch are bound in as associated data.
- **Merge** is deterministic and order-independent (CRDT-style): per-field registers, tombstones for deletes, sets for tags.
- **Secret fields don't use LWW.** Concurrent password changes keep both values and surface a conflict to the user.
- **Compaction:** snapshots keep the causal metadata of the ops they retain, so compaction is exact at any time. Event files a snapshot covers are deleted after a grace period. True purge rewrites history and rotates the epoch.
- **Rollback/fork detection:** each client hash-chains its own events. Every device stores the last-seen seq per client, and a regression raises an alarm.
- **Size padding:** pad payloads to size buckets.
- **This device's copy** (`sync/mirror.rs`, spec §9.5): every device keeps a copy of the vault files in its state directory, updated after each healthy sync, so a wiped or rolled-back folder can be restored. The copy follows deliberate deletions (GC, purge, old slots), so a restore never undoes a purge.
- **KDBX is import/export only** (`kdbx/`, spec §8.2.1). Preserve unknown fields on round trips: KeePass data without a Strata field travels in `kdbx:` fields, which the entry screens hide. The `keepass` crate brings KDBX's own crypto (AES, Twofish, ChaCha20, Argon2d); it only ever touches the KeePass file, never the vault.

## Rules for working on crypto

- **Spec first.** `docs/spec.md` is the source of truth for byte layouts, KDFs, parameters, and AEAD associated data. Implement against it and never invent constructions.
- **Vetted, high-level primitives only:** XChaCha20-Poly1305, Argon2id, HKDF-SHA256, HMAC-SHA256, HPKE with X-Wing for recovery slots, and Ed25519 for device signatures, from RustCrypto or libsodium bindings. No raw AES modes, no hand-rolled constructions.
- **Required tests:**
  - property tests that shuffle event order and assert convergence
  - parser fuzzing
  - fixed test vectors
  - negative tests: tampered events, swapped slots, replayed events, and rolled-back sequence numbers must each fail loudly
- Never convert secrets to Kotlin `String`. Use `ByteArray`/`CharArray` and zero them. Password fields go straight from Compose's `TextFieldState` to UTF-8 bytes (`takeUtf8` in `ui/Secrets.kt`), and existing secrets are never pre-filled into an editor. The only exceptions are drawing a revealed value on screen and handing it to the clipboard, because those platform APIs take nothing else: keep such strings in screen state that dies with the screen, and go through `SecretClipboard`, which marks the copy sensitive (Android) or keeps it out of clipboard history (Windows) and clears it after 30 seconds.

## Commands

- `./gradlew :desktopApp:run`: build the core and bindings, then run the desktop app
- `./gradlew :shared:jvmTest`: Kotlin tests against the real native library
- `./gradlew :androidApp:installDebug`: build with cargo-ndk and install to a device or emulator
- `./gradlew :desktopApp:packageDistributionForCurrentOS`: installer for this OS
- `cd core && cargo test && cargo clippy`: Rust tests and lints
- `wsl -d Ubuntu -- bash /mnt/d/src/strata/core/tools/kdbx-check.sh`: has KeePassXC open Strata's KeePass export and checks what it sees (also in CI). The import fixtures come from `core/strata-core/tests/fixtures/kdbx/make.sh`, which uses KeePassXC too
- `uv run core/tools/vectors/check.py`: recompute the test vectors with independent (non-Rust) implementations
- `cd core && STRATA_WRITE_VECTORS=1 cargo test --test vectors`: regenerate vectors after a deliberate spec change; then run the check above
- `wsl -d Ubuntu -- bash /mnt/d/src/strata/core/tools/fuzz/minimize-wsl.sh`: after a long fuzzing run, merges what it found into `core/fuzz/corpus` (committed). Seeds for `local_state` and `kdbx` come from `STRATA_WRITE_SEEDS=1 cargo test fuzz_seeds`
- `wsl -d Ubuntu -- bash /mnt/d/src/strata/core/tools/fuzz/run-wsl.sh 600`: fuzz every parser for 10 minutes in WSL, starting from `core/fuzz/seeds` (regenerate with `uv run core/tools/fuzz/make_seeds.py`). Fuzzing is Linux or CI only; see Gotchas. `docs/threat-model.md` maps each security claim to its tests: keep it current when adding one

## Gotchas

- **Don't strip symbols from the release profile.** UniFFI reads its metadata from the library's exported symbols (`strip = "debuginfo"` only).
- **Fuzzing doesn't link on Windows.** strata-core is also a cdylib, and Windows DLLs can't leave libFuzzer's coverage hooks unresolved. Fuzz in CI or WSL instead.
- **Library naming:** JNA loads the desktop library from the classpath at `<jna-prefix>/` (e.g. `win32-x86-64/strata_core.dll`). `bundleHostNative` puts it there.
- **Windows:** dev environment is Windows with the repo on a Dev Drive (`D:\src\strata`); `CARGO_HOME`, `RUSTUP_HOME` and `GRADLE_USER_HOME` point to `D:\packages`.
