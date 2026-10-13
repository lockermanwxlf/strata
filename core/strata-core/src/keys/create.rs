//! Creating a vault (spec §5–§8): the epoch 0 record, a password slot, a recovery
//! slot with its anchor, and this device's first event, which registers it.

use sha2::{Digest, Sha256};

use crate::crypto::kdf::{self, Argon2Params, EpochKeys};
use crate::crypto::recovery::{self, RecoveryKeyPair};
use crate::crypto::sign::DeviceKey;
use crate::crypto::{SecretBytes, SecretKey, fill_random, random_id};
use crate::error::{CoreError, Result};
use crate::format::Id;
use crate::format::body::{EventBody, Op, VectorClock};
use crate::format::epoch::NewEpoch;
use crate::format::event::EventHeader;
use crate::format::names::FileName;
use crate::format::slot::{self, SlotParams};
use crate::format::vault_info::VaultInfo;
use crate::local::{LocalState, LocalStore, Pin, StateRecord};
use crate::model::hlc;
use crate::policy::{ProtectorStrength, SlotScope, check_slot_policy};
use crate::sync::RemoteStore;

pub struct NewVault {
    pub vault_id: Id,
    pub client_id: Id,
    /// The 24 recovery words. Shown to the user once; never stored.
    pub recovery_words: SecretBytes,
}

/// Creates a vault in an empty `store`. `password` is UTF-8; the UI has already
/// shown the strength warning if it applied (`strength::password_strength`).
pub fn create_vault(
    store: &dyn RemoteStore,
    local: &dyn LocalStore,
    password: &[u8],
    device_name: &str,
) -> Result<NewVault> {
    let argon = Argon2Params::DEFAULT;
    // This includes the leftovers of an interrupted setup. They're never deleted
    // automatically: a folder missing only `strata-vault` could just as well be a real
    // vault that lost that file.
    if store.list()?.iter().any(|p| FileName::parse(p).is_some()) {
        return Err(CoreError::rejected(
            "vault",
            "the folder already holds vault files (perhaps from an interrupted setup); choose an empty folder",
        ));
    }
    // Both slots are synced; the policy allows that for passwords and recovery keys.
    check_slot_policy(ProtectorStrength::Strong, SlotScope::Synced, None)?;

    let vault_id = random_id()?;
    let client_id = random_id()?;
    let ek0 = SecretKey::generate()?;
    let keys0 = EpochKeys::derive(&vault_id, &ek0);
    let device = DeviceKey::generate()?;
    let r = recovery::generate()?;
    let keypair = RecoveryKeyPair::derive(&r);

    let epoch0 = NewEpoch {
        vault_id,
        epoch: 0,
        creator: client_id,
        key_id: keys0.key_id,
        recovery_pk_hash: recovery::pk_hash(keypair.public_key()),
        cutover: &VectorClock::default(),
        chain: None,
    }
    .seal(&device)?;

    let password_slot_id = random_id()?;
    let mut salt = [0u8; 16];
    fill_random(&mut salt)?;
    let slot_secret = kdf::password_slot_secret(password, &salt, argon)?;
    let password_slot = slot::seal_with_kek(
        &vault_id,
        &password_slot_id,
        0,
        &SlotParams::Password { argon, salt },
        &kdf::slot_kek(&vault_id, &password_slot_id, &slot_secret),
        &ek0,
    )?;

    let recovery_slot_id = random_id()?;
    let recovery_slot = slot::seal_recovery(
        &vault_id,
        &recovery_slot_id,
        0,
        &SlotParams::Recovery {
            pk: Box::new(*keypair.public_key()),
            anchor_epoch: 0,
            anchor_tag: recovery::anchor_tag(&r, &vault_id, 0, &keys0.key_id, keypair.public_key()),
        },
        &ek0,
        None,
    )?;

    let first_event_header = EventHeader {
        vault_id,
        client_id,
        seq: 1,
        epoch: 0,
    };
    let first_event = first_event_header.seal(
        &EventBody {
            hlc: hlc::next(0, hlc::now_ms())?,
            clock: VectorClock(vec![(client_id, 1)]),
            prev_hash: [0; 32],
            ops: vec![Op::RegisterDevice {
                client_id,
                dev_pk: device.public_key(),
                name: device_name.to_string(),
            }],
        },
        &keys0.event,
        &device,
        None,
    )?;

    // `strata-vault` goes last: until it exists the folder isn't a vault, so a crash
    // part-way through leaves nothing that looks complete.
    let writes = [
        (
            FileName::Epoch {
                epoch: 0,
                creator: client_id,
            },
            &epoch0,
        ),
        (
            FileName::Slot {
                slot_id: password_slot_id,
            },
            &password_slot,
        ),
        (
            FileName::Slot {
                slot_id: recovery_slot_id,
            },
            &recovery_slot,
        ),
        (first_event_header.file_name(), &first_event),
        (FileName::VaultInfo, &VaultInfo { vault_id }.encode()),
    ];
    for (name, bytes) in writes {
        store.create(&name.to_path(), bytes)?;
    }

    let state = LocalState {
        vault_id,
        client_id,
        pin: Pin {
            epoch: 0,
            key_id: keys0.key_id,
        },
        local_slots: Vec::new(),
        record: StateRecord {
            device_seed: device.seed(),
            next_seq: 2,
            high_water: vec![(client_id, 1, Sha256::digest(&first_event).into())],
            pending: Vec::new(),
            snapshots: Vec::new(),
        },
    };
    local.save(&vault_id, &state.seal(&keys0)?)?;

    Ok(NewVault {
        vault_id,
        client_id,
        recovery_words: recovery::to_words(&r),
    })
}
