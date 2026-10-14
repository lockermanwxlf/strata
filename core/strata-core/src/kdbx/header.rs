//! A look at a KeePass file's outer header before it is opened (spec §8.2.1): the
//! file chooses its own key-derivation cost, and a hostile one could ask for more
//! memory than the device has, which aborts the process. This reads only the
//! unencrypted header, refuses costs past the limits below, and lets the `keepass`
//! crate do the real parsing afterwards.

use super::KdbxError;

/// Argon2 memory, in bytes. KeePassXC's default is 64 MiB; its settings go to 1 GiB
/// on most machines.
pub const MAX_ARGON2_MEMORY: u64 = 1 << 30;
pub const MAX_ARGON2_ITERATIONS: u64 = 10_000;
pub const MAX_ARGON2_PARALLELISM: u64 = 64;
/// Argon2 memory times iterations: about a minute of work. KeePassXC's default
/// (64 MiB, a second's worth of iterations) is far below it.
pub const MAX_ARGON2_WORK: u128 = 1 << 35;
/// AES-KDF rounds (KDBX 3.1, and KDBX 4 with AES-KDF): a few minutes at most.
pub const MAX_AES_ROUNDS: u64 = 1 << 32;

const SIGNATURE_1: u32 = 0x9AA2_D903;
const SIGNATURE_2_KDBX: u32 = 0xB54B_FB67;
/// KeePass 1.x (`.kdb`) and KeePass 2 pre-releases: not read (spec §8.2.1).
const SIGNATURES_2_OLD: [u32; 2] = [0xB54B_FB65, 0xB54B_FB66];
const END_OF_HEADER: u8 = 0;
const TRANSFORM_ROUNDS: u8 = 6;
const KDF_PARAMETERS: u8 = 11;

/// Checks the header's key-derivation parameters. Malformed headers pass: the
/// `keepass` crate rejects them with a proper message, and this only guards cost.
pub fn check(file: &[u8]) -> Result<(), KdbxError> {
    let mut r = Reader(file);
    let (Some(sig1), Some(sig2), Some(_minor), Some(major)) = (r.u32(), r.u32(), r.u16(), r.u16())
    else {
        return Ok(());
    };
    if sig1 != SIGNATURE_1 {
        return Ok(());
    }
    if SIGNATURES_2_OLD.contains(&sig2) {
        return Err(KdbxError::Unreadable(
            "files from KeePass 1 aren't supported; save it as KDBX 4 in KeePass 2 or KeePassXC first".into(),
        ));
    }
    if sig2 != SIGNATURE_2_KDBX {
        return Ok(());
    }
    if !(3..=4).contains(&major) {
        return Err(KdbxError::Unreadable(format!(
            "KDBX version {major} isn't supported; save it as KDBX 4 in KeePass first"
        )));
    }
    loop {
        let Some(id) = r.u8() else { return Ok(()) };
        let len = if major == 3 {
            r.u16().map(u32::from)
        } else {
            r.u32()
        };
        let Some(value) = len.and_then(|n| r.take(n as usize)) else {
            return Ok(());
        };
        match id {
            END_OF_HEADER => return Ok(()),
            TRANSFORM_ROUNDS => {
                if let Some(rounds) = Reader(value).u64() {
                    limit("AES rounds", rounds, MAX_AES_ROUNDS)?;
                }
            }
            KDF_PARAMETERS => check_kdf(value)?,
            _ => {}
        }
    }
}

/// The KDBX 4 `VariantDictionary` of KDF parameters: version, then typed items.
fn check_kdf(dictionary: &[u8]) -> Result<(), KdbxError> {
    let mut r = Reader(dictionary);
    if r.u16().is_none() {
        return Ok(());
    }
    let (mut memory, mut iterations) = (0u64, 0u64);
    loop {
        let item = r.u8().filter(|kind| *kind != 0).and_then(|kind| {
            let name = r.u32().and_then(|n| r.take(n as usize))?;
            let value = r.u32().and_then(|n| r.take(n as usize))?;
            Some((kind, name, value))
        });
        let Some((kind, name, value)) = item else {
            // Each limit alone allows hours of work together.
            let work = u128::from(memory) * u128::from(iterations);
            if work > MAX_ARGON2_WORK {
                return Err(KdbxError::Unreadable(format!(
                    "this file asks for more key-derivation work than Strata allows (Argon2 \
                     memory {memory} times {iterations} iterations); lower it in KeePass first"
                )));
            }
            return Ok(());
        };
        let number = match (kind, value.len()) {
            (0x04, 4) => Reader(value).u32().map(u64::from),
            (0x05, 8) => Reader(value).u64(),
            _ => None,
        };
        let Some(number) = number else { continue };
        match name {
            b"M" => {
                limit("Argon2 memory", number, MAX_ARGON2_MEMORY)?;
                memory = number;
            }
            b"I" => {
                limit("Argon2 iterations", number, MAX_ARGON2_ITERATIONS)?;
                iterations = number;
            }
            b"P" => limit("Argon2 parallelism", number, MAX_ARGON2_PARALLELISM)?,
            b"R" => limit("AES rounds", number, MAX_AES_ROUNDS)?,
            _ => {}
        }
    }
}

fn limit(what: &str, value: u64, max: u64) -> Result<(), KdbxError> {
    if value > max {
        return Err(KdbxError::Unreadable(format!(
            "this file asks for more key-derivation work than Strata allows ({what} {value}, \
             at most {max}); lower it in KeePass first"
        )));
    }
    Ok(())
}

/// Little-endian reads that stop at the end instead of panicking.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
    }

    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A KDBX 4 header whose KDF dictionary holds `items` (name, type, value).
    fn kdbx4(items: &[(&str, u8, &[u8])]) -> Vec<u8> {
        let mut dict = vec![0x00, 0x01];
        for (name, kind, value) in items {
            dict.push(*kind);
            dict.extend((name.len() as u32).to_le_bytes());
            dict.extend(name.as_bytes());
            dict.extend((value.len() as u32).to_le_bytes());
            dict.extend(*value);
        }
        dict.push(0);
        let mut out = Vec::new();
        out.extend(SIGNATURE_1.to_le_bytes());
        out.extend(SIGNATURE_2_KDBX.to_le_bytes());
        out.extend(1u16.to_le_bytes());
        out.extend(4u16.to_le_bytes());
        out.push(KDF_PARAMETERS);
        out.extend((dict.len() as u32).to_le_bytes());
        out.extend(dict);
        out.extend([END_OF_HEADER, 0, 0, 0, 0]);
        out
    }

    #[test]
    fn refuses_costs_past_the_limits() {
        let mib = |n: u64| (n << 20).to_le_bytes();
        let ok = kdbx4(&[
            ("M", 0x05, &mib(64)),
            ("I", 0x05, &10u64.to_le_bytes()),
            ("P", 0x04, &2u32.to_le_bytes()),
        ]);
        assert!(check(&ok).is_ok());
        assert!(
            check(&kdbx4(&[
                ("M", 0x05, &mib(1024)),
                ("I", 0x05, &16u64.to_le_bytes())
            ]))
            .is_ok()
        );
        // Each within its limit, together too much work.
        let slow = kdbx4(&[
            ("M", 0x05, &mib(1024)),
            ("I", 0x05, &10_000u64.to_le_bytes()),
        ]);
        assert!(matches!(check(&slow), Err(KdbxError::Unreadable(_))));
        for bad in [
            kdbx4(&[("M", 0x05, &mib(1025))]),
            kdbx4(&[("M", 0x05, &u64::MAX.to_le_bytes())]),
            kdbx4(&[("I", 0x05, &10_001u64.to_le_bytes())]),
            kdbx4(&[("P", 0x04, &65u32.to_le_bytes())]),
            kdbx4(&[("R", 0x05, &((1u64 << 32) + 1).to_le_bytes())]),
        ] {
            assert!(matches!(check(&bad), Err(KdbxError::Unreadable(_))));
        }
    }

    #[test]
    fn real_files_pass_and_garbage_is_left_to_the_parser() {
        for file in [
            &include_bytes!("../../tests/fixtures/kdbx/keepassxc.kdbx")[..],
            &include_bytes!("../../tests/fixtures/kdbx/keepassxc-keyfile.kdbx")[..],
        ] {
            assert!(check(file).is_ok());
        }
        assert!(check(b"").is_ok());
        assert!(check(b"not a keepass file at all").is_ok());
        let mut truncated = kdbx4(&[("M", 0x05, &(2u64 << 30).to_le_bytes())]);
        truncated.truncate(20);
        assert!(check(&truncated).is_ok());
        // KDBX 2, KeePass 2 pre-releases and KeePass 1.
        let mut old = kdbx4(&[]);
        old[10..12].copy_from_slice(&2u16.to_le_bytes());
        assert!(check(&old).is_err());
        for signature in SIGNATURES_2_OLD {
            let mut old = kdbx4(&[]);
            old[4..8].copy_from_slice(&signature.to_le_bytes());
            assert!(check(&old).is_err());
        }
    }

    #[test]
    fn kdbx3_transform_rounds() {
        let header = |rounds: u64| {
            let mut out = Vec::new();
            out.extend(SIGNATURE_1.to_le_bytes());
            out.extend(SIGNATURE_2_KDBX.to_le_bytes());
            out.extend(1u16.to_le_bytes());
            out.extend(3u16.to_le_bytes());
            out.push(TRANSFORM_ROUNDS);
            out.extend(8u16.to_le_bytes());
            out.extend(rounds.to_le_bytes());
            out.extend([END_OF_HEADER, 0, 0]);
            out
        };
        assert!(check(&header(60_000)).is_ok());
        assert!(check(&header(u64::MAX)).is_err());
    }
}
