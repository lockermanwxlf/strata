//! Size padding for encrypted bodies (spec §4): Padmé with a 256-byte minimum.
//!
//! `plaintext = LE32(len(body)) || body || zeros`, padded to `padme(max(4 + len, 256))`.
//! Unpadding accepts only that exact canonical form.
//!
//! Body lengths are `u32` throughout, matching the 4-byte length prefix, so none of
//! the arithmetic below can overflow.

use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

pub const MIN_PADDED_LEN: u64 = 256;
const LEN_PREFIX: usize = 4;

/// Padmé (Nikitin et al., PETS 2019), for `2 <= len <= 2^33`. Every caller goes
/// through `padded_len`, which stays inside that range.
fn padme(len: u64) -> u64 {
    debug_assert!((2..=1 << 33).contains(&len));
    let e = u64::from(63 - len.leading_zeros()); // floor(log2 len)
    let s = u64::from(63 - e.leading_zeros()) + 1; // floor(log2 e) + 1
    let mask = (1u64 << (e - s)) - 1;
    (len + mask) & !mask
}

/// The padded plaintext length for a body of `body_len` bytes.
pub fn padded_len(body_len: u32) -> u64 {
    padme((LEN_PREFIX as u64 + u64::from(body_len)).max(MIN_PADDED_LEN))
}

/// Pads `body` for encryption. The result can contain secrets, so it is zeroized on drop.
pub fn pad(body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let body_len =
        u32::try_from(body.len()).map_err(|_| CoreError::rejected("body", "too large to pad"))?;
    let total = usize::try_from(padded_len(body_len))
        .map_err(|_| CoreError::rejected("body", "too large to pad"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(&body_len.to_le_bytes());
    out.extend_from_slice(body);
    out.resize(total, 0);
    Ok(out)
}

/// The body inside a decrypted, padded plaintext. Rejects anything that isn't the
/// canonical padding of its body: a wrong length, or a nonzero padding byte.
pub fn unpad(plaintext: &[u8]) -> Result<&[u8]> {
    let reject = |why| CoreError::rejected("padding", why);
    let (prefix, rest) = plaintext
        .split_first_chunk::<LEN_PREFIX>()
        .ok_or(reject("too short"))?;
    let body_len = u32::from_le_bytes(*prefix);
    if plaintext.len() as u64 != padded_len(body_len) {
        return Err(reject("not the canonical padded length"));
    }
    // padded_len(n) >= 4 + n, so the body fits once the length check has passed.
    let (body, padding) = rest.split_at(body_len as usize);
    if padding.iter().any(|&b| b != 0) {
        return Err(reject("nonzero padding"));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn spec_boundaries() {
        // spec §14.1 item 4
        assert_eq!(padded_len(0), 256);
        assert_eq!(padded_len(252), 256);
        assert_eq!(padded_len(253), 272);
        assert_eq!(padded_len(1000), 1024);
        assert_eq!(padded_len(1 << 20), 1_081_344);
    }

    #[test]
    fn padme_small_values() {
        assert_eq!(padme(2), 2);
        assert_eq!(padme(3), 3);
        assert_eq!(padme(256), 256);
        assert_eq!(padme(257), 272);
    }

    #[test]
    fn unpad_rejects_non_canonical_forms() {
        let padded = pad(b"hello").unwrap();
        assert_eq!(unpad(&padded).unwrap(), b"hello");

        let mut nonzero = padded.to_vec();
        *nonzero.last_mut().unwrap() = 1;
        assert!(unpad(&nonzero).is_err());

        let mut longer = padded.to_vec();
        longer.extend_from_slice(&[0; 16]);
        assert!(unpad(&longer).is_err());

        assert!(unpad(&padded[..padded.len() - 1]).is_err());

        let mut huge_len = padded.to_vec();
        huge_len[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(unpad(&huge_len).is_err());

        assert!(unpad(&[1, 0]).is_err());
    }

    proptest! {
        #[test]
        fn round_trip(body in proptest::collection::vec(any::<u8>(), 0..5000)) {
            let padded = pad(&body).unwrap();
            prop_assert_eq!(padded.len() as u64, padded_len(body.len() as u32));
            prop_assert!(padded.len() >= 256);
            prop_assert_eq!(unpad(&padded).unwrap(), &body[..]);
        }

        #[test]
        fn padme_bounds(len in 2u64..(1 << 33)) {
            let p = padme(len);
            prop_assert!(p >= len);
            // Padmé's overhead is at most about 12%.
            prop_assert!((p - len) as f64 <= len as f64 * 0.12 + 1.0);
            prop_assert_eq!(padme(p), p);
        }

        #[test]
        fn unpad_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = unpad(&bytes);
        }
    }
}
