//! Bounds-checked reader for fixed-layout envelopes (spec §4, layer 1).
//!
//! Envelopes are parsed before anything is authenticated, so this must never
//! panic, whatever the input: every read checks its length first and returns
//! `Rejected` on truncation.

use crate::error::{CoreError, Result};

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    /// Names the structure being parsed, for error messages.
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8], what: &'static str) -> Self {
        Self { buf, pos: 0, what }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// The next `n` bytes, borrowed from the input.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(CoreError::rejected(self.what, "truncated"));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub fn u16_le(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64_le(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// Consumes 4 bytes if they equal `magic`. Like every other read, a failed check
    /// leaves the position where it was.
    pub fn magic(&mut self, magic: &[u8; 4]) -> Result<()> {
        let start = self.pos;
        if &self.array::<4>()? != magic {
            self.pos = start;
            return Err(CoreError::rejected(self.what, "wrong magic"));
        }
        Ok(())
    }

    /// Everything not yet read. Consumes the reader.
    pub fn rest(self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Succeeds only if every byte was read. Trailing bytes are rejected, never ignored.
    pub fn finish(self) -> Result<()> {
        if self.remaining() != 0 {
            return Err(CoreError::rejected(self.what, "trailing bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn reads_little_endian_fields_in_order() {
        let buf = [b'S', b'T', b'E', b'V', 1, 0, 0x34, 0x12, 0, 0, 7, 8, 9];
        let mut r = Reader::new(&buf, "test");
        r.magic(b"STEV").unwrap();
        assert_eq!(r.u16_le().unwrap(), 1);
        assert_eq!(r.u32_le().unwrap(), 0x1234);
        assert_eq!(r.position(), 10);
        assert_eq!(r.take(2).unwrap(), &[7, 8]);
        assert_eq!(r.rest(), &[9]);
    }

    #[test]
    fn rejects_truncation_and_leaves_position() {
        let mut r = Reader::new(&[1, 2, 3], "test");
        assert!(matches!(
            r.u32_le(),
            Err(CoreError::Rejected {
                what: "test",
                why: "truncated"
            })
        ));
        assert_eq!(r.position(), 0);
        assert_eq!(r.u16_le().unwrap(), 0x0201);
    }

    #[test]
    fn rejects_wrong_magic_and_trailing_bytes() {
        assert!(Reader::new(b"STEX", "t").magic(b"STEV").is_err());
        let mut r = Reader::new(&[0, 0], "t");
        r.u8().unwrap();
        assert!(matches!(
            r.finish(),
            Err(CoreError::Rejected {
                why: "trailing bytes",
                ..
            })
        ));
    }

    #[test]
    fn take_huge_length_does_not_overflow() {
        let mut r = Reader::new(&[0; 4], "t");
        r.u8().unwrap();
        assert!(r.take(usize::MAX).is_err());
    }

    proptest! {
        /// Any sequence of reads over any input either succeeds within bounds or
        /// returns `Rejected`; it never panics, and the position never passes the end.
        #[test]
        fn never_panics(buf in proptest::collection::vec(any::<u8>(), 0..64),
                        ops in proptest::collection::vec((0u8..7, any::<u16>()), 0..32)) {
            let mut r = Reader::new(&buf, "prop");
            for (op, n) in ops {
                let before = r.position();
                let ok = match op {
                    0 => r.u8().is_ok(),
                    1 => r.u16_le().is_ok(),
                    2 => r.u32_le().is_ok(),
                    3 => r.u64_le().is_ok(),
                    4 => r.array::<16>().is_ok(),
                    5 => r.magic(b"STEV").is_ok(),
                    _ => r.take(n as usize).is_ok(),
                };
                prop_assert!(r.position() <= buf.len());
                if !ok {
                    prop_assert_eq!(r.position(), before);
                }
            }
        }
    }
}
