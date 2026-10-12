//! Every file parser on arbitrary bytes (spec §5–§10). The first input byte picks
//! the file type. Parsers must never panic; whatever they accept is then pushed
//! through signature checks and decryption with fixed keys, which must not panic
//! either.

#![no_main]

use libfuzzer_sys::fuzz_target;
use strata_core::crypto::SecretKey;
use strata_core::format::epoch::EpochRecord;
use strata_core::format::event::SealedEvent;
use strata_core::format::slot::SlotFile;
use strata_core::format::snapshot::SealedSnapshot;
use strata_core::format::vault_info::VaultInfo;
use strata_core::policy::SlotScope;

const VAULT: [u8; 16] = [0; 16];

fuzz_target!(|data: &[u8]| {
    let Some((&which, bytes)) = data.split_first() else {
        return;
    };
    let key = SecretKey::from_slice(&[0; 32]).unwrap();
    let pk = [0u8; 32];
    match which % 6 {
        0 => {
            if let Ok(info) = VaultInfo::parse(bytes) {
                assert_eq!(info.encode(), bytes);
            }
        }
        1 | 2 => {
            let scope = if which % 6 == 1 {
                SlotScope::Synced
            } else {
                SlotScope::Local
            };
            if let Ok(slot) = SlotFile::parse(bytes, &VAULT, scope) {
                let _ = slot.open_with_kek(&key);
                let _ = slot.file_name();
            }
        }
        3 => {
            if let Ok(record) = EpochRecord::parse(bytes, &VAULT) {
                let _ = record.signature_valid(&pk);
                let _ = record.open_chain(&key);
            }
        }
        4 => {
            if let Ok(event) = SealedEvent::parse(bytes, &VAULT) {
                let _ = event.signature_valid(&pk);
                let _ = event.open(&key);
            }
        }
        _ => {
            if let Ok(snapshot) = SealedSnapshot::parse(bytes, &VAULT) {
                let _ = snapshot.signature_valid(&pk);
                let _ = snapshot.open(&key);
            }
        }
    }
});
