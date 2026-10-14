# Threat model: claims and the tests behind them

Every claim in [spec §1](spec.md#1-goals-and-threat-model) is listed here with the mechanism that delivers it and the tests that demonstrate it (implementation plan, Phase 13). Test names are Rust unless marked otherwise; paths are relative to `core/strata-core/src`. The whole suite runs with `cd core && cargo test`, and on Linux with `core/tools/linux-protectors.sh`.

## An attacker who controls the remote storage

They can read, delete, reorder and replay files, roll them back to older versions, and write arbitrary files.

| Claim | Mechanism | Tests |
|---|---|---|
| Can't read contents | XChaCha20-Poly1305 under per-epoch keys (§3, §6.1); padding (§4) | `ffi/tests.rs::the_remote_learns_no_contents_and_only_padded_sizes` scans every vault and local-state file for titles, usernames, URLs, passwords and tags. `crypto/aead.rs::rejects_wrong_key_nonce_aad_or_tampering`. `tests/vectors.rs::aead`, cross-checked by `core/tools/vectors/check.py` |
| Learns only the metadata in §13 | File names carry only IDs and sequence numbers; Padmé padding | `ffi/tests.rs::the_remote_learns_no_contents_and_only_padded_sizes` (no contents in file names; 1- and 40-byte titles give the same event size). `encoding/padding.rs::spec_boundaries`, `padme_bounds`, `tests/vectors.rs::padding` |
| Can't forge or alter contents | AEAD with the vault ID, file name and epoch as associated data; device signatures (§6.4) | `format/event.rs::every_bit_flip_is_caught`, `format/epoch.rs::every_bit_flip_is_caught`, `format/snapshot.rs::round_trip_and_every_bit_flip_is_caught`, `format/slot.rs::rejects_moved_tampered_or_misplaced_slots`, `format/event.rs::rejects_bad_plaintext_even_when_authentic` |
| Copied, moved or renamed files don't apply | Name and vault ID bound into the AAD | `sync/session/tests.rs::copied_or_renamed_events_are_set_aside`, `format/event.rs::name_and_vault_must_match`, `keys/unlock/tests.rs::moved_slots_dont_open`, `slots_copied_from_another_vault_are_set_aside` |
| Arbitrary files are harmless | Strict parsers with size caps; fuzzing | `keys/unlock/tests.rs::oversized_files_are_set_aside_unread`, `sync/fs_store.rs::reads_are_capped_and_paths_stay_inside`, `sync/foreign_store.rs::read_limit_holds_even_if_the_folder_ignores_it`, `bad_paths_never_reach_the_folder`. Fuzz targets `envelopes`, `bodies`, `reader`, `padding`, `names` (see "Fuzzing" below) |
| Reordering changes nothing | Order-independent merge (§9.2), causal delivery (§9.1) | `merge/tests.rs::devices_converge` (property test over shuffled delivery), `reduced_parts_union_to_the_whole`, `sync/session/tests.rs::devices_converge_through_the_store`, `events_wait_for_their_dependencies`, `compaction_never_changes_the_vault`, `tests/vectors.rs::merge` |
| Replays are caught | AAD binding; covered events ignored (§9.4) | `sync/session/tests.rs::replaying_a_compacted_event_changes_nothing`, `a_replayed_old_password_slot_opens_only_the_old_epoch` |
| Rollback is detected (deleting files, restoring old copies) | High-water marks per client (§9.4) | `sync/session/tests.rs::a_deleted_event_is_a_rollback`, `restoring_an_older_snapshot_is_a_rollback`, `a_vanished_epoch_record_is_a_rollback`, `keys/unlock/tests.rs::stale_slots_are_ignored_and_a_missing_epoch_is_a_rollback`, `a_planted_copy_of_an_epoch_record_cant_hide_the_real_one` |
| Forks are detected | Hash chains per client; no-overwrite writes (§5, §9.4) | `sync/session/tests.rs::a_replaced_event_is_a_fork`, `a_reused_seq_is_a_fork_for_the_writer`, `a_snapshot_contradicting_an_applied_event_is_a_fork`, `restored_local_state_becomes_a_new_client`. Android: the planted-name collision on the emulator (plan, Phase 11) |
| Slot substitution is detected | Key ID pinned on first unlock; recovery anchor MAC (§6.2.1, §6.3) | `keys/unlock/tests.rs::a_substituted_key_raises_an_alarm_on_a_pinned_device`, `a_fabricated_vault_doesnt_open_with_the_real_recovery_key`, `an_altered_anchor_doesnt_open`, `crypto/recovery.rs::anchor_binds_every_input` |
| After an alarm, nothing is written | Writes refused while an alarm stands (§9.4) | `sync/session/tests.rs::nothing_is_uploaded_after_an_alarm`, `ffi/tests.rs::an_alarm_is_reported_not_thrown` |

## An attacker who steals a locked device

| Claim | Mechanism | Tests |
|---|---|---|
| Local state is encrypted and authenticated | State record under the local-state key; unlock record in its AAD (§11) | `local/mod.rs::unlock_record_is_authenticated`, `refuses_to_seal_with_another_epochs_keys`, `keys/unlock/tests.rs::tampered_local_state_is_rejected`, `ffi/tests.rs::the_remote_learns_no_contents_and_only_padded_sizes` (scans the state folder too). Fuzz target `local_state` |
| PINs only behind hardware with rate limiting; never synced | Slot policy in the core (§6.2, `policy.rs`) | `policy.rs::weak_local_requires_hardware_rate_limiting`, `weak_never_syncs_even_with_hardware`, `ffi/tests.rs::the_policy_refuses_weak_protectors_without_hardware_rate_limiting` |
| Local slots are bound to the device's keystore | Protector wraps a per-slot secret; slot ID bound into each wrap | `protector/linux/tests.rs::tpm_seals_to_the_pin`, `secret_service_wraps_per_slot` (software TPM and keyring in CI). Manual: Windows Hello and Android checklists (plan, Phase 10) |
| Biometric changes invalidate device unlock | `KeyInvalidated` means "slot gone" (§11) | `ffi/tests.rs::a_local_slot_unlocks_and_cancel_or_invalidation_fall_back`. Manual: Android checklist step 2 (needs a real device) |
| Passwords are expensive to guess | Argon2id with bounded parameters (§6.2) | `crypto/kdf.rs::argon2_bounds`, `tests/vectors.rs::argon2id` |

## A revoked device

| Claim | Mechanism | Tests |
|---|---|---|
| Can't read anything written after the rotation | Revocation rotates the epoch key (§7.2) | `sync/session/tests.rs::a_revoked_device_reads_nothing_new_and_its_late_changes_can_be_reverted`, `changing_the_password_rotates_and_other_devices_follow`, `after_a_rotation_an_old_session_stops_writing_until_it_unlocks_again` |
| Its later writes are signed, attributed and flagged, not dropped | `RetireClient`; flag-and-revert (§9.2) | `sync/session/tests.rs::a_retired_devices_later_changes_are_flagged_not_dropped`, `merge/tests.rs::a_retired_devices_later_ops_still_merge_the_same_in_any_order`, and the revert in `a_revoked_device_reads_nothing_new_and_its_late_changes_can_be_reverted` |
| Can't sneak back in under an old key | Suspect devices; rival rotations (§7.2) | `sync/session/tests.rs::a_device_appearing_under_an_old_key_after_a_rotation_is_suspect`, `a_revoked_device_cant_win_the_current_epoch_after_the_fact` |

## One device impersonating another

| Claim | Mechanism | Tests |
|---|---|---|
| Events, snapshots and epoch records carry the writer's Ed25519 signature | §6.4 | `sync/session/tests.rs::an_event_signed_by_another_device_is_a_forgery`, `a_snapshot_with_a_bad_signature_is_a_forgery`, `a_tampered_epoch_record_signature_is_a_forgery`, `format/event.rs::signature_from_another_device_fails`, `crypto/sign.rs::signature_covers_the_prefix`, `rejects_small_order_public_key`, `tests/vectors.rs::ed25519` |
| Registration is fixed to a device's first event | §6.4 | `format/body.rs::event_body_round_trip_and_validation`, `rejects_bad_bodies` |

## Secret handling (no spec claim, but the premise of all of the above)

| Rule (CLAUDE.md) | Tests and checks |
|---|---|
| No secrets in `Debug` output or error messages | `tests/hygiene.rs::debug_output_never_shows_secrets`, `errors_never_show_secrets`, `crypto/secret.rs::debug_never_prints_contents`. FFI types that carry secrets (`EntryEdit`, `NewVault`, `ConflictCandidate`, `ExportedFile`) don't implement `Debug` |
| Freed heap memory is zeroed | `alloc.rs` (verified in the release assembly, Phase 8) |
| Secrets cross the FFI only as byte arrays, wiped on both sides | `shared/.../VaultTest.kt` (Kotlin) checks that arguments are wiped |
| Concurrent secret edits keep both values | `merge/tests.rs::concurrent_secret_writes_conflict_until_resolved`, `ffi/tests.rs::two_devices_sync_and_see_conflicts` |

## What Strata does not protect against

These are the limits in spec §1, and the residual risks found in the Phase 13 audit.

- **A compromised, unlocked device** holds the keys. Its changes are attributed to it and show in the device list (`merge/tests.rs::device_registry_names_and_retirement`), and nothing more is claimed.
- **A fresh device's first sync** is trust-on-first-use (§6.3), except with the recovery key, whose anchor is checked (`keys/unlock/tests.rs::recovery_words_unlock_a_fresh_device`, `a_fabricated_vault_doesnt_open_with_the_real_recovery_key`).
- **Attribution inside snapshots** rests on the snapshot creator (§10.1).
- **Memory outside the core's control:**
  - Platform UI text buffers (Compose `TextFieldState`) can't be wiped, only cleared.
  - Revealed values and clipboard copies become platform strings: the documented exception in CLAUDE.md.
  - On Android, reading a key file goes through stream buffers that aren't wiped.
  - Third-party crypto crates may leave stack copies the allocator can't reach.
- **KeePass files** are only as safe as their own password. The KeePass parser (`keepass` crate) isn't fuzzed: every run would pay for a key derivation. Strata checks the file's key-derivation cost before parsing (`kdbx/header.rs`), and fuzzes that check. Once a file is decrypted, the crate decompresses its contents without a size limit, so a file the user can open could still exhaust memory. That can only be a file the user picked and holds the password to.
- **Untested on hardware so far:**
  - Android Keystore on a real device (the emulator's keystore is software-only, and the policy correctly refuses it).
  - The macOS Secure Enclave.
  - SAF cloud providers.

## Fuzzing

Every parser of untrusted bytes has a target in `core/fuzz/fuzz_targets`. Each run starts from `core/fuzz/seeds` and the minimized corpora in `core/fuzz/corpus`.

| Target | Parses |
|---|---|
| `envelopes` | every vault file: vault info, slots, epoch records, events, snapshots |
| `bodies` | decrypted event and snapshot bodies |
| `local_state` | the device's local state file and decrypted state record |
| `reader`, `padding`, `names` | the byte reader, padding, file names |
| `kdbx` | the KeePass header check, and `kdbx:entry` |

Campaign results are recorded in the implementation plan, Phase 13.
