//! Device-local state (spec §11): never uploaded, one file per vault.
//!
//! The layout is ours to choose (it isn't part of the interoperable format):
//!
//! ```text
//! "STLC" || LE16 version 1 || LE16 flags 0
//! vault_id[16] || client_id[16] || LE32 pin_epoch || pin_key_id[32]     unlock record
//! LE16 n || n × (LE32 len || local slot file)                           (cleartext)
//! nonce[24] || XChaCha20-Poly1305(local_key_{pin_epoch}, state record)   AAD = every byte before
//! ```
//!
//! The state record is deterministic CBOR: `{1: device seed, 2: next_seq, 3: HWM}`.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use minicbor::decode::{self, Decoder};
use minicbor::encode::{self, Encoder, Write};
use minicbor::{Decode, Encode};

use crate::crypto::SecretKey;
use crate::crypto::aead::{self, NONCE_LEN, random_nonce};
use crate::crypto::kdf::EpochKeys;
use crate::encoding::{Reader, cbor};
use crate::error::{CoreError, Result};
use crate::format::Id;

const MAGIC: &[u8; 4] = b"STLC";
const VERSION: u16 = 1;
const WHAT: &str = "local state";
const MAX_LOCAL_SLOTS: usize = 64;
const MAX_LOCAL_SLOT_LEN: usize = 4096;

/// The newest epoch this device has verified, and its key ID (spec §6.3, §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pin {
    pub epoch: u32,
    pub key_id: [u8; 32],
}

/// The encrypted part of local state.
#[derive(Debug, PartialEq, Eq)]
pub struct StateRecord {
    /// Seed of this device's Ed25519 signing key (spec §6.4).
    pub device_seed: SecretKey,
    /// The seq this device will give its next event.
    pub next_seq: u64,
    /// High-water marks `(client, seq, H(c, seq))`, sorted by client (spec §9.4).
    pub high_water: Vec<(Id, u64, [u8; 32])>,
    /// Sealed events not yet confirmed in the store (spec §11). Saved before the
    /// upload, so a failed upload is retried with the same seq instead of leaving
    /// a gap in this device's chain.
    pub pending: Vec<Vec<u8>>,
    /// Snapshots this device wrote, with when (Unix ms). Garbage collection measures
    /// its grace period from here, not from file times a sync tool may rewrite.
    pub snapshots: Vec<(Id, u64)>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct LocalState {
    pub vault_id: Id,
    pub client_id: Id,
    pub pin: Pin,
    /// Local slot files (magic `STLS`), parsed when a platform protector unlocks.
    pub local_slots: Vec<Vec<u8>>,
    pub record: StateRecord,
}

impl LocalState {
    /// Encrypts the state record with the pinned epoch's local-state key. `pin_keys`
    /// must be that epoch's keys; anything else is refused, because state sealed under
    /// another epoch's key could never be opened again.
    pub fn seal(&self, pin_keys: &EpochKeys) -> Result<Vec<u8>> {
        if pin_keys.key_id != self.pin.key_id {
            return Err(CoreError::rejected(
                WHAT,
                "sealed with a key other than the pin's",
            ));
        }
        self.seal_with_nonce(&pin_keys.local_state, &random_nonce()?)
    }

    fn seal_with_nonce(&self, local_key: &SecretKey, nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>> {
        if self.local_slots.len() > MAX_LOCAL_SLOTS
            || self
                .local_slots
                .iter()
                .any(|s| s.len() > MAX_LOCAL_SLOT_LEN)
        {
            return Err(CoreError::rejected(
                WHAT,
                "too many or too large local slots",
            ));
        }
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.client_id);
        out.extend_from_slice(&self.pin.epoch.to_le_bytes());
        out.extend_from_slice(&self.pin.key_id);
        out.extend_from_slice(&(self.local_slots.len() as u16).to_le_bytes());
        for slot in &self.local_slots {
            out.extend_from_slice(&(slot.len() as u32).to_le_bytes());
            out.extend_from_slice(slot);
        }
        out.extend_from_slice(nonce);
        let plaintext = cbor::encode(&self.record);
        let ct = aead::seal(local_key, nonce, &plaintext, &out);
        out.extend_from_slice(&ct);
        Ok(out)
    }
}

/// Local state whose unlock record has been read but whose state record is still
/// encrypted. This is what unlock works from.
#[derive(Debug)]
pub struct SealedLocalState<'a> {
    pub vault_id: Id,
    pub client_id: Id,
    pub pin: Pin,
    pub local_slots: Vec<Vec<u8>>,
    aad: &'a [u8],
    nonce: [u8; NONCE_LEN],
    ciphertext: &'a [u8],
}

impl<'a> SealedLocalState<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, WHAT);
        r.magic(MAGIC)?;
        if r.u16_le()? != VERSION || r.u16_le()? != 0 {
            return Err(CoreError::rejected(WHAT, "unsupported version"));
        }
        let vault_id = r.array()?;
        let client_id = r.array()?;
        let pin = Pin {
            epoch: r.u32_le()?,
            key_id: r.array()?,
        };
        let count = r.u16_le()? as usize;
        if count > MAX_LOCAL_SLOTS {
            return Err(CoreError::rejected(WHAT, "too many local slots"));
        }
        let mut local_slots = Vec::with_capacity(count);
        for _ in 0..count {
            let len = r.u32_le()? as usize;
            if len > MAX_LOCAL_SLOT_LEN {
                return Err(CoreError::rejected(WHAT, "local slot too large"));
            }
            local_slots.push(r.take(len)?.to_vec());
        }
        let nonce = r.array()?;
        let aad_len = r.position();
        Ok(Self {
            vault_id,
            client_id,
            pin,
            local_slots,
            aad: &bytes[..aad_len],
            nonce,
            ciphertext: r.rest(),
        })
    }

    /// Decrypts the state record with the local-state key of `self.pin.epoch`.
    pub fn open(self, local_key: &SecretKey) -> Result<LocalState> {
        let plaintext = aead::open(local_key, &self.nonce, self.ciphertext, self.aad, WHAT)?;
        let record: StateRecord = cbor::decode_strict(plaintext.expose(), WHAT)?;
        if !record.high_water.windows(2).all(|w| w[0].0 < w[1].0) {
            return Err(CoreError::rejected(WHAT, "high-water marks not sorted"));
        }
        Ok(LocalState {
            vault_id: self.vault_id,
            client_id: self.client_id,
            pin: self.pin,
            local_slots: self.local_slots,
            record,
        })
    }
}

type EncResult<W> = core::result::Result<(), encode::Error<<W as Write>::Error>>;

impl<C> Encode<C> for StateRecord {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, _: &mut C) -> EncResult<W> {
        e.map(5)?
            .u8(1)?
            .bytes(self.device_seed.expose())?
            .u8(2)?
            .u64(self.next_seq)?
            .u8(3)?
            .array(self.high_water.len() as u64)?;
        for (client, seq, hash) in &self.high_water {
            e.array(3)?.bytes(client)?.u64(*seq)?.bytes(hash)?;
        }
        e.u8(4)?.array(self.pending.len() as u64)?;
        for event in &self.pending {
            e.bytes(event)?;
        }
        e.u8(5)?.array(self.snapshots.len() as u64)?;
        for (id, created_ms) in &self.snapshots {
            e.array(2)?.bytes(id)?.u64(*created_ms)?;
        }
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for StateRecord {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> core::result::Result<Self, decode::Error> {
        let malformed = || decode::Error::message("malformed state record");
        if d.map()? != Some(5) || d.u8()? != 1 {
            return Err(malformed());
        }
        let device_seed = SecretKey::from_slice(d.bytes()?).map_err(|_| malformed())?;
        if d.u8()? != 2 {
            return Err(malformed());
        }
        let next_seq = d.u64()?;
        if d.u8()? != 3 {
            return Err(malformed());
        }
        let n = d.array()?.ok_or_else(malformed)?;
        let mut high_water = Vec::new();
        for _ in 0..n {
            if d.array()? != Some(3) {
                return Err(malformed());
            }
            let client = d.bytes()?.try_into().map_err(|_| malformed())?;
            let seq = d.u64()?;
            let hash = d.bytes()?.try_into().map_err(|_| malformed())?;
            high_water.push((client, seq, hash));
        }
        if d.u8()? != 4 {
            return Err(malformed());
        }
        let n = d.array()?.ok_or_else(malformed)?;
        let mut pending = Vec::new();
        for _ in 0..n {
            pending.push(d.bytes()?.to_vec());
        }
        if d.u8()? != 5 {
            return Err(malformed());
        }
        let n = d.array()?.ok_or_else(malformed)?;
        let mut snapshots = Vec::new();
        for _ in 0..n {
            if d.array()? != Some(2) {
                return Err(malformed());
            }
            let id = d.bytes()?.try_into().map_err(|_| malformed())?;
            snapshots.push((id, d.u64()?));
        }
        Ok(StateRecord {
            device_seed,
            next_seq,
            high_water,
            pending,
            snapshots,
        })
    }
}

/// Where a device keeps its local state, one entry per vault.
pub trait LocalStore: Send + Sync {
    fn load(&self, vault_id: &Id) -> Result<Option<Vec<u8>>>;

    /// Replaces the state atomically: after a crash either the old or the new state
    /// is there, never a mix.
    fn save(&self, vault_id: &Id, bytes: &[u8]) -> Result<()>;
}

/// Local state as files in a directory: `<dir>/<vault_id hex>.state`.
#[derive(Debug, Clone)]
pub struct FsLocalStore {
    dir: PathBuf,
}

impl FsLocalStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The platform's per-user data directory (spec §11). Android has none to
    /// discover from here; the app passes its `filesDir` to `new` instead.
    pub fn default_dir() -> Option<PathBuf> {
        let env = |k| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        if cfg!(windows) {
            env("LOCALAPPDATA").map(|d| d.join("Strata"))
        } else if cfg!(target_os = "macos") {
            env("HOME").map(|h| h.join("Library/Application Support/Strata"))
        } else {
            env("XDG_DATA_HOME")
                .or_else(|| env("HOME").map(|h| h.join(".local/share")))
                .map(|d| d.join("strata"))
        }
    }

    fn path(&self, vault_id: &Id) -> PathBuf {
        let name: String = vault_id.iter().map(|b| format!("{b:02x}")).collect();
        self.dir.join(format!("{name}.state"))
    }
}

impl LocalStore for FsLocalStore {
    fn load(&self, vault_id: &Id) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.path(vault_id)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, vault_id: &Id, bytes: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let path = self.path(vault_id);
        let tmp = path.with_extension("state.tmp");
        write_synced(&tmp, bytes)?;
        // Replaces the old file in one step on every platform.
        std::fs::rename(&tmp, &path)?;
        // On Unix (including Android) the rename itself is only durable once the
        // directory is synced. Without it a crash could bring back the old state and
        // an old next_seq, which would reuse a seq and look like a fork (spec §9.4).
        #[cfg(unix)]
        std::fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }
}

fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Local state in memory, for tests.
#[derive(Debug, Default)]
pub struct MemoryLocalStore {
    entries: Mutex<std::collections::HashMap<Id, Vec<u8>>>,
}

impl MemoryLocalStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl LocalStore for MemoryLocalStore {
    fn load(&self, vault_id: &Id) -> Result<Option<Vec<u8>>> {
        Ok(self.entries.lock().unwrap().get(vault_id).cloned())
    }

    fn save(&self, vault_id: &Id, bytes: &[u8]) -> Result<()> {
        self.entries
            .lock()
            .unwrap()
            .insert(*vault_id, bytes.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }

    fn pin_keys() -> EpochKeys {
        EpochKeys::derive(&[1; 16], &key(10))
    }

    fn sample() -> LocalState {
        LocalState {
            vault_id: [1; 16],
            client_id: [2; 16],
            pin: Pin {
                epoch: 3,
                key_id: pin_keys().key_id,
            },
            local_slots: vec![vec![5; 40], vec![6; 7]],
            record: StateRecord {
                device_seed: key(7),
                next_seq: 9,
                high_water: vec![([1; 16], 4, [8; 32]), ([2; 16], 8, [9; 32])],
                pending: vec![vec![3; 500]],
                snapshots: vec![([4; 16], 1234)],
            },
        }
    }

    #[test]
    fn round_trip() {
        let bytes = sample().seal(&pin_keys()).unwrap();
        let sealed = SealedLocalState::parse(&bytes).unwrap();
        assert_eq!(sealed.pin, sample().pin);
        assert_eq!(sealed.open(&pin_keys().local_state).unwrap(), sample());
        assert!(
            SealedLocalState::parse(&bytes)
                .unwrap()
                .open(&key(11))
                .is_err()
        );
    }

    #[test]
    fn refuses_to_seal_with_another_epochs_keys() {
        let other = EpochKeys::derive(&[1; 16], &key(11));
        assert!(sample().seal(&other).is_err());
    }

    #[test]
    fn unlock_record_is_authenticated() {
        let bytes = sample().seal(&pin_keys()).unwrap();
        // Change the pin epoch, the pinned key ID, the client ID, a local slot.
        for offset in [8, 24, 40, 44, 82] {
            let mut bad = bytes.clone();
            bad[offset] ^= 1;
            let opened =
                SealedLocalState::parse(&bad).and_then(|s| s.open(&pin_keys().local_state));
            assert!(opened.is_err(), "offset {offset}");
        }
    }

    #[test]
    fn fs_store_round_trip_and_replace() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsLocalStore::new(dir.path().join("nested"));
        assert_eq!(store.load(&[1; 16]).unwrap(), None);
        store.save(&[1; 16], b"first").unwrap();
        store.save(&[1; 16], b"second").unwrap();
        assert_eq!(store.load(&[1; 16]).unwrap().unwrap(), b"second");
        assert_eq!(store.load(&[2; 16]).unwrap(), None);
    }
}
