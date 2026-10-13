//! Password generation: characters drawn uniformly from the OS CSPRNG.

use zeroize::Zeroizing;

use super::{SecretBytes, fill_random};
use crate::error::{CoreError, Result};

const LETTERS_AND_DIGITS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
/// Symbols that type on common keyboard layouts and need no escaping in most forms.
const SYMBOLS: &[u8] = b"!#$%&*+-=?@^_~";

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 128;

/// A random password of `length` ASCII characters. Each character is uniform over
/// the alphabet: random bytes at or above the largest multiple of its size are
/// rejected rather than reduced, which would favour the first characters.
pub fn password(length: usize, symbols: bool) -> Result<SecretBytes> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return Err(CoreError::rejected("password length", "must be 8 to 128"));
    }
    let alphabet: Vec<u8> = if symbols {
        [LETTERS_AND_DIGITS, SYMBOLS].concat()
    } else {
        LETTERS_AND_DIGITS.to_vec()
    };
    let n = alphabet.len();
    let limit = 256 - 256 % n;
    // Sized up front: a reallocation would leave a copy behind.
    let mut out = Vec::with_capacity(length);
    let mut pool = Zeroizing::new([0u8; 64]);
    let mut used = pool.len();
    while out.len() < length {
        if used == pool.len() {
            fill_random(&mut pool[..])?;
            used = 0;
        }
        let b = pool[used] as usize;
        used += 1;
        if b < limit {
            out.push(alphabet[b % n]);
        }
    }
    Ok(SecretBytes::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_and_alphabet_are_respected() {
        for symbols in [false, true] {
            let p = password(40, symbols).unwrap();
            assert_eq!(p.len(), 40);
            assert!(
                p.expose()
                    .iter()
                    .all(|c| LETTERS_AND_DIGITS.contains(c) || (symbols && SYMBOLS.contains(c)))
            );
        }
        assert!(password(7, true).is_err());
        assert!(password(129, true).is_err());
    }

    #[test]
    fn every_character_shows_up_roughly_evenly() {
        // 76 characters over 76,000 draws: about 1,000 each. Losing the rejection
        // step would skew the first 28 by a third, far outside these bounds.
        let mut counts = [0usize; 256];
        for _ in 0..(76_000 / 100) {
            for &c in password(100, true).unwrap().expose() {
                counts[c as usize] += 1;
            }
        }
        for &c in LETTERS_AND_DIGITS.iter().chain(SYMBOLS) {
            assert!(
                (800..1200).contains(&counts[c as usize]),
                "{} drawn {} times",
                c as char,
                counts[c as usize]
            );
        }
    }
}
