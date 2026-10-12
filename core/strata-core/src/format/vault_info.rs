//! `strata-vault` (spec §5.1): the vault ID and format version, written once.
//!
//! Not authenticated. Every key derivation and AAD binds `vault_id`, so a tampered
//! file makes every later check fail.

use super::{Id, read_preamble, write_preamble};
use crate::encoding::Reader;
use crate::error::Result;

pub const MAGIC: &[u8; 4] = b"STVT";
pub const LEN: usize = 24;
const WHAT: &str = "strata-vault";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultInfo {
    pub vault_id: Id,
}

impl VaultInfo {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, WHAT);
        read_preamble(&mut r, MAGIC, WHAT)?;
        let vault_id = r.array()?;
        r.finish()?;
        Ok(Self { vault_id })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LEN);
        write_preamble(&mut out, MAGIC);
        out.extend_from_slice(&self.vault_id);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CoreError;

    #[test]
    fn round_trip_and_version_handling() {
        let info = VaultInfo { vault_id: [7; 16] };
        let bytes = info.encode();
        assert_eq!(bytes.len(), LEN);
        assert_eq!(VaultInfo::parse(&bytes).unwrap(), info);

        let mut newer = bytes.clone();
        newer[4] = 2;
        assert!(matches!(
            VaultInfo::parse(&newer),
            Err(CoreError::UpdateRequired { found: 2 })
        ));
        let mut zero = bytes.clone();
        zero[4] = 0;
        assert!(matches!(
            VaultInfo::parse(&zero),
            Err(CoreError::Rejected { .. })
        ));
        let mut flags = bytes.clone();
        flags[6] = 1;
        assert!(VaultInfo::parse(&flags).is_err());
        assert!(VaultInfo::parse(&bytes[..23]).is_err());
        let mut longer = bytes;
        longer.push(0);
        assert!(VaultInfo::parse(&longer).is_err());
    }
}
