//! Deterministic CBOR for authenticated bodies (spec §4, layer 2).
//!
//! Bodies are decoded and then re-encoded, and the two byte strings must match.
//! That single check rejects everything the spec forbids: unknown or duplicate map
//! keys, keys out of order, non-shortest integers, indefinite lengths, and trailing
//! bytes. The encoder only ever produces the deterministic form, so a body that
//! survives a round trip unchanged was deterministic to begin with.

use minicbor::{Decode, Encode};

use crate::error::{CoreError, Result};

pub fn encode<T: Encode<()>>(value: &T) -> Vec<u8> {
    minicbor::to_vec(value).expect("encoding into a Vec cannot fail")
}

pub fn decode_strict<T>(bytes: &[u8], what: &'static str) -> Result<T>
where
    T: for<'b> Decode<'b, ()> + Encode<()>,
{
    let value: T =
        minicbor::decode(bytes).map_err(|_| CoreError::rejected(what, "malformed CBOR"))?;
    if encode(&value) != bytes {
        return Err(CoreError::rejected(
            what,
            "CBOR is not in deterministic form",
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use minicbor::{Decode, Encode};

    #[derive(Debug, PartialEq, Encode, Decode)]
    #[cbor(map)]
    struct Sample {
        #[n(1)]
        hlc: u64,
        #[n(2)]
        #[cbor(with = "minicbor::bytes")]
        id: Vec<u8>,
        #[n(3)]
        names: Vec<String>,
    }

    fn sample() -> Sample {
        Sample {
            hlc: 500,
            id: vec![1, 2, 3],
            names: vec!["a".into()],
        }
    }

    #[test]
    fn round_trip() {
        let bytes = encode(&sample());
        // {1: 500, 2: h'010203', 3: ["a"]}
        assert_eq!(
            bytes,
            [
                0xa3, 0x01, 0x19, 0x01, 0xf4, 0x02, 0x43, 1, 2, 3, 0x03, 0x81, 0x61, b'a'
            ]
        );
        assert_eq!(decode_strict::<Sample>(&bytes, "t").unwrap(), sample());
    }

    #[test]
    fn rejects_non_deterministic_forms() {
        let cases: &[(&str, &[u8])] = &[
            // 500 as an 8-byte integer instead of 2 bytes
            (
                "non-shortest int",
                &[
                    0xa3, 0x01, 0x1b, 0, 0, 0, 0, 0, 0, 0x01, 0xf4, 0x02, 0x43, 1, 2, 3, 0x03,
                    0x81, 0x61, b'a',
                ],
            ),
            // keys 2 and 1 swapped
            (
                "unsorted keys",
                &[
                    0xa3, 0x02, 0x43, 1, 2, 3, 0x01, 0x19, 0x01, 0xf4, 0x03, 0x81, 0x61, b'a',
                ],
            ),
            // extra key 4
            (
                "unknown key",
                &[
                    0xa4, 0x01, 0x19, 0x01, 0xf4, 0x02, 0x43, 1, 2, 3, 0x03, 0x81, 0x61, b'a',
                    0x04, 0x00,
                ],
            ),
            // key 1 twice
            (
                "duplicate key",
                &[
                    0xa4, 0x01, 0x19, 0x01, 0xf4, 0x01, 0x19, 0x01, 0xf4, 0x02, 0x43, 1, 2, 3,
                    0x03, 0x81, 0x61, b'a',
                ],
            ),
            // indefinite-length array for key 3
            (
                "indefinite length",
                &[
                    0xa3, 0x01, 0x19, 0x01, 0xf4, 0x02, 0x43, 1, 2, 3, 0x03, 0x9f, 0x61, b'a', 0xff,
                ],
            ),
            (
                "trailing bytes",
                &[
                    0xa3, 0x01, 0x19, 0x01, 0xf4, 0x02, 0x43, 1, 2, 3, 0x03, 0x81, 0x61, b'a', 0x00,
                ],
            ),
            (
                "invalid UTF-8",
                &[
                    0xa3, 0x01, 0x19, 0x01, 0xf4, 0x02, 0x43, 1, 2, 3, 0x03, 0x81, 0x61, 0xff,
                ],
            ),
            ("truncated", &[0xa3, 0x01, 0x19, 0x01]),
        ];
        for (name, bytes) in cases {
            assert!(
                decode_strict::<Sample>(bytes, "t").is_err(),
                "{name} was accepted"
            );
        }
    }
}
