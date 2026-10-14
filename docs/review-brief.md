# External review brief

Strata is a password vault. Its vault is a folder of immutable, encrypted files that any sync tool can carry between devices (Syncthing, a cloud drive, a network share). This brief is for the reviewer of its cryptography and format: what to look at, what to run, and the questions the project most wants answered. It accompanies [spec.md](spec.md), which is the source of truth, and [threat-model.md](threat-model.md), which maps every security claim to its tests.

**Status:** spec draft 0.3, implemented in full (implementation plan, phases 0–12). No external review yet. Until one is done and its findings are fixed, the spec says "not yet safe for real passwords". After that, its status changes to "Reviewed".

## Scope

**In scope**

| What | Where |
|---|---|
| The format and constructions | `docs/spec.md` §2–§13. §15 lists the open questions |
| Primitives, key derivation, AEAD, signatures, recovery (X-Wing HPKE, anchor MAC) | `core/strata-core/src/crypto/` |
| File formats and their parsers | `core/strata-core/src/format/`, `encoding/` |
| Unlock, slot checks, key-ID pinning | `core/strata-core/src/keys/` |
| Sync, validation, rollback/fork/forgery detection, rotation, purge, snapshots | `core/strata-core/src/sync/session.rs` and `sync/session/` |
| Merge (CRDT) and what may be dropped | `core/strata-core/src/merge/` |
| Local state and slot policy | `core/strata-core/src/local/`, `policy.rs` |
| The zeroing allocator | `core/strata-core/src/alloc.rs` |
| The FFI surface (what crosses into Kotlin) | `core/strata-core/src/ffi.rs` |

**Lighter touch:** the platform protectors (`protector/`, `androidApp/.../KeystoreProtector.kt`). They only wrap and unwrap a random per-slot secret with a hardware key, and the core derives everything else. KeePass import and export (`kdbx/`, spec §8.2.1) use the KeePass file's own crypto through the `keepass` crate and never touch vault keys.

**Out of scope:** the Kotlin UI, beyond how it handles secrets (CLAUDE.md, "Rules for working on crypto").

## Primitives

All from RustCrypto or dalek, with versions pinned in `core/Cargo.lock`. The details are in spec §3.

| Purpose | Primitive | Crate |
|---|---|---|
| AEAD | XChaCha20-Poly1305, random 192-bit nonces | `chacha20poly1305` 0.11 |
| Password hashing | Argon2id, 64 MiB / t=3 / p=4 by default, bounded on read | `argon2` 0.6 |
| Key derivation | HKDF-SHA256 | `hkdf` 0.13, `sha2` 0.11 |
| Recovery slots | HPKE base mode, X-Wing KEM (draft codepoint `0x647a`), HKDF-SHA256, ChaCha20-Poly1305 | `hpke` 0.14 |
| Recovery anchor | HMAC-SHA256 | `hmac` 0.13 |
| Device signatures | Ed25519, `verify_strict` | `ed25519-dalek` 3.0 |

## Questions for the reviewer

1. **Key hierarchy and domain separation** (§6.1). Every subkey comes from the epoch key through HKDF with distinct labels, and there is no MAC key. Is the separation sound, and are the labels unambiguous?
2. **Associated data** (§7.1, §8.1, §10.1, §11). Each file's header, which includes the vault ID, name fields and epoch, is the AAD. Does any field that matters escape authentication? Is a moved, renamed or cross-vault file always rejected?
3. **Random XChaCha nonces** under long-lived epoch keys. Is the volume of encryptions per key ever a concern?
4. **Recovery slot and anchor** (§6.2.1). Rotation re-wraps the vault key to the recovery public key without the recovery secret. The anchor MAC stops a fabricated vault from opening with the real recovery key. Does the anchor bind enough (vault ID, anchor epoch, key ID, public key)? Is the reliance on a draft X-Wing codepoint acceptable, given that test vectors pin it?
5. **Slot substitution and TOFU** (§6.3). The key ID is pinned on first unlock. Is the first-unlock window acceptable, and should the key-ID fingerprint (OPEN-6) be shown?
6. **Device signatures** (§6.4). The signing prefix, small-order key rejection, and registration only in a device's first event. Can one device forge or reattribute another's changes, including through snapshots, which keep dots but not signatures (§10.1)?
7. **Rotation and revocation** (§7.2). Each epoch record wraps the previous key under the next. Concurrent rotations resolve by lowest key ID. A revoked device's later writes are flagged, not dropped. Is there an interleaving where a revoked device reads new data, or where its writes go unflagged?
8. **Rollback, fork and replay detection** (§9.4, §10.2). There are high-water marks per client, hash chains, and snapshot watermarks standing in for deleted events, plus an "unverified" state when a snapshot sits under a key not yet held. Can a storage attacker hide deletions or substitute history without an alarm?
9. **Merge and reduction** (§9.2–§9.3). The merge is order-independent and reduction is exact. Are there security consequences, for example a delete that silently loses data, or a conflict that can be suppressed?
10. **Metadata** (§13). Is the list complete? Padmé padding covers bodies; is it applied everywhere it should be?
11. **Local state** (§11). The pin is cleartext but bound into the AAD. Local slots and the PIN policy require hardware with rate limiting (`policy.rs`).
12. **Implementation hygiene:**
    - Zeroing every heap block on free (`alloc.rs`) plus `zeroize`.
    - Constant-time comparisons where secrets are compared.
    - No secrets in errors or `Debug` output (`tests/hygiene.rs`).

## What to run

From a checkout:

```
cd core && cargo test && cargo clippy --all-targets -- -D warnings
uv run core/tools/vectors/check.py          # recomputes every test vector with independent Python libraries
cargo deny check                            # licenses and advisories
```

On Linux (or WSL):

```
core/tools/linux-protectors.sh               # the suite again, with a software TPM and a keyring
core/tools/fuzz/run-wsl.sh 600              # every fuzz target, 10 minutes each
core/tools/kdbx-check.sh                    # KeePassXC opens Strata's KeePass export
```

The vectors are frozen in `core/strata-core/tests/vectors/`, and `check.py` derives them independently of the Rust code. A change to either side shows up there.

## Known limitations

These are listed in [threat-model.md](threat-model.md#what-strata-does-not-protect-against): what Strata doesn't protect against, memory outside the core's control, and what hasn't run on real hardware yet.

## What the project needs back

- Findings with severity, each tied to a spec section or file.
- For format-level changes, the project bumps `format_version` (§12) rather than patching in place.
- A short statement of what was reviewed, so the spec status can say "Reviewed" with that scope.
