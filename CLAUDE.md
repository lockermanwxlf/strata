# Strata

Cross-platform password vault. Targets: Windows 11, macOS, Linux, Android. iOS is out of scope for now (no test device), but nothing should rule it out.

## Architecture

- **`core/strata-core` (Rust):** everything security-critical: vault format, crypto, CRDT merge, sync, slot policy. Secrets live in Rust memory and are wiped with `zeroize`.
- **UniFFI** generates the Kotlin bindings (`dev.lockermanwxlf.strata.core.ffi`) from the built library. Never edit generated code. Change the Rust and rebuild.
- **`shared` (Kotlin Multiplatform + Compose Multiplatform):** UI in `commonMain`. Bindings compile into `jvmMain` and `androidMain` (they use JNA). Common code reaches the core through `expect` declarations in `NativeCore.kt`.
- **`desktopApp`:** Compose Desktop entry point and packaging (jpackage).
- **`androidApp`:** Android entry point. AGP 9 forbids an application module from also being a KMP module, which is why it's separate. It cross-compiles the core with cargo-ndk into jniLibs.

Keep the FFI API coarse-grained, e.g. "decrypted list view", "apply edit", "sync". Never make one call per field.

## Key hierarchy (LUKS / age style)

- **Vault key:** random 256-bit, one per key epoch. HKDF derives the key ID and the event, snapshot, epoch-chain and local-state keys from it. There is no MAC subkey; AEAD associated data binds all context.
- **Slots:** each slot wraps the vault key under a KEK derived from one protector: password (Argon2id), FIDO2 `hmac-secret`/YubiKey, or platform keystore. The exception is the 256-bit recovery key, which is an X25519 key pair (HPKE). Rotation can re-wrap to its public key without the user producing the recovery key, and an anchor MAC stops a fabricated vault from opening with it (spec §6.2.1).
- **Slot scope:** `Synced` slots live in `slots/` on the remote. `Local` slots live only on the device and are never uploaded.
- **Policy** (`policy.rs`, enforced in core, not only in the UI): PINs (weak protectors) are never synced, and locally they require a hardware-backed **and** rate-limited keystore. Passwords sync whatever their strength (the user's choice), but the UI warns about weak ones and requires confirmation.
- **Slot-substitution defense:** store a key commitment / key ID, pin it locally on first enrollment, and refuse slots that unwrap to a different key.
- **Device signing keys:** each device has an Ed25519 key, registered in its first event. It signs that device's events, snapshots and epoch records, so no key holder can forge another device's changes (spec §6.4).
- **Revocation = rotation:** key epochs. New events use the new epoch key, and old epoch keys are stored wrapped under the new one. Removing a slot does not revoke a device that has already unlocked.

## Platform protectors

`PlatformProtector` (in `protector.rs`) is a UniFFI foreign trait: `capabilities`, async `wrap`/`unwrap`, `delete`.

- Protectors only ever see a random per-slot **slot secret**. The core derives the KEK from it and wraps the vault key itself, so the vault key never crosses FFI. Zero buffers on both sides immediately.
- **Android (Kotlin):** Keystore AES-GCM key, `setIsStrongBoxBacked(true)` with TEE fallback, `setUserAuthenticationRequired(true)`, unwrap via `BiometricPrompt` + `CryptoObject`. Verify `KeyInfo.securityLevel` before reporting `hardwareBacked`.
- **Windows (Rust, `windows` crate):** Hello `KeyCredentialManager` signs a fixed per-slot challenge; the hash of that deterministic signature is the KEK. Pass the HWND from Kotlin so the prompt isn't hidden.
- **macOS (Rust, `security-framework`):** Secure Enclave P-256 key with `biometryCurrentSet`/`userPresence`, `SecKeyCreateEncryptedData` (ECIES). Requires a signed app with entitlements.
- **Linux (Rust):** TPM 2.0 (`tss-esapi`) seal with PIN auth, which counts as rate-limited. Otherwise Secret Service (`keyring`), reported as **not** rate-limited.
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
- **KDBX is import/export only.** Preserve unknown fields on round trips.

## Rules for working on crypto

- **Spec first.** `docs/spec.md` is the source of truth for byte layouts, KDFs, parameters, and AEAD associated data. Implement against it and never invent constructions.
- **Vetted, high-level primitives only:** XChaCha20-Poly1305, Argon2id, HKDF-SHA256, HMAC-SHA256, HPKE (X25519) for recovery slots, and Ed25519 for device signatures, from RustCrypto or libsodium bindings. No raw AES modes, no hand-rolled constructions.
- **Required tests:**
  - property tests that shuffle event order and assert convergence
  - parser fuzzing
  - fixed test vectors
  - negative tests: tampered events, swapped slots, replayed events, and rolled-back sequence numbers must each fail loudly
- Never convert secrets to Kotlin `String`. Use `ByteArray`/`CharArray` and zero them.

## Commands

- `./gradlew :desktopApp:run`: build the core and bindings, then run the desktop app
- `./gradlew :shared:jvmTest`: Kotlin tests against the real native library
- `./gradlew :androidApp:installDebug`: build with cargo-ndk and install to a device or emulator
- `./gradlew :desktopApp:packageDistributionForCurrentOS`: installer for this OS
- `cd core && cargo test && cargo clippy`: Rust tests and lints

## Gotchas

- **Don't strip symbols from the release profile.** UniFFI reads its metadata from the library's exported symbols (`strip = "debuginfo"` only).
- **Library naming:** JNA loads the desktop library from the classpath at `<jna-prefix>/` (e.g. `win32-x86-64/strata_core.dll`). `bundleHostNative` puts it there.
- **Windows:** dev environment is Windows with the repo on a Dev Drive (`D:\src\strata`); `CARGO_HOME`, `RUSTUP_HOME` and `GRADLE_USER_HOME` point to `D:\packages`.
