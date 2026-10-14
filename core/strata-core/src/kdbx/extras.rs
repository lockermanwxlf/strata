//! The `kdbx:entry` field (spec §8.2.1): what a KeePass entry carries that has no
//! Strata field of its own, as a CBOR map, so an export puts it back.

use minicbor::{Decoder, Encoder};

/// The KeePass-only parts of an entry. Every part is optional; an absent part
/// exports as KeePass's default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extras {
    pub uuid: Option<[u8; 16]>,
    pub icon: Option<u64>,
    pub foreground: Option<String>,
    pub background: Option<String>,
    pub override_url: Option<String>,
    /// `false` turns KeePass's password quality check off; `true` is the default.
    pub quality_check: bool,
    pub created: Option<i64>,
    pub expiry: Option<i64>,
    pub expires: bool,
    pub autotype: Option<AutoType>,
    pub custom_data: Vec<(String, String)>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AutoType {
    pub enabled: bool,
    pub sequence: Option<String>,
    pub use_clipboard: bool,
    pub associations: Vec<(String, String)>,
}

/// KeePass's defaults: nothing set, and the quality check on.
impl Default for Extras {
    fn default() -> Self {
        Self {
            uuid: None,
            icon: None,
            foreground: None,
            background: None,
            override_url: None,
            quality_check: true,
            created: None,
            expiry: None,
            expires: false,
            autotype: None,
            custom_data: Vec::new(),
        }
    }
}

impl Extras {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        let count = [
            self.uuid.is_some(),
            self.icon.is_some(),
            self.foreground.is_some(),
            self.background.is_some(),
            self.override_url.is_some(),
            !self.quality_check,
            self.created.is_some(),
            self.expiry.is_some(),
            self.expires,
            self.autotype.is_some(),
            !self.custom_data.is_empty(),
        ]
        .iter()
        .filter(|present| **present)
        .count();
        // Writing to a Vec can't fail.
        let _ = (|| -> Result<(), minicbor::encode::Error<std::convert::Infallible>> {
            e.map(count as u64)?;
            if let Some(uuid) = &self.uuid {
                e.u8(1)?.bytes(uuid)?;
            }
            if let Some(icon) = self.icon {
                e.u8(2)?.u64(icon)?;
            }
            if let Some(c) = &self.foreground {
                e.u8(3)?.str(c)?;
            }
            if let Some(c) = &self.background {
                e.u8(4)?.str(c)?;
            }
            if let Some(url) = &self.override_url {
                e.u8(5)?.str(url)?;
            }
            if !self.quality_check {
                e.u8(6)?.bool(false)?;
            }
            if let Some(t) = self.created {
                e.u8(7)?.i64(t)?;
            }
            if let Some(t) = self.expiry {
                e.u8(8)?.i64(t)?;
            }
            if self.expires {
                e.u8(9)?.bool(true)?;
            }
            if let Some(a) = &self.autotype {
                let count = 1
                    + usize::from(a.sequence.is_some())
                    + usize::from(a.use_clipboard)
                    + usize::from(!a.associations.is_empty());
                e.u8(10)?.map(count as u64)?;
                e.u8(1)?.bool(a.enabled)?;
                if let Some(s) = &a.sequence {
                    e.u8(2)?.str(s)?;
                }
                if a.use_clipboard {
                    e.u8(3)?.bool(true)?;
                }
                if !a.associations.is_empty() {
                    e.u8(4)?;
                    pairs(&mut e, &a.associations)?;
                }
            }
            if !self.custom_data.is_empty() {
                e.u8(11)?;
                pairs(&mut e, &self.custom_data)?;
            }
            Ok(())
        })();
        e.into_writer()
    }

    /// Reads what it can: unknown keys are skipped, and anything malformed gives
    /// `None`, so export falls back to defaults (spec §8.2.1).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut d = Decoder::new(bytes);
        let mut out = Self::default();
        let n = d.map().ok()??;
        for _ in 0..n {
            match d.u64().ok()? {
                1 => out.uuid = Some(d.bytes().ok()?.try_into().ok()?),
                2 => out.icon = Some(d.u64().ok()?),
                3 => out.foreground = Some(d.str().ok()?.to_string()),
                4 => out.background = Some(d.str().ok()?.to_string()),
                5 => out.override_url = Some(d.str().ok()?.to_string()),
                6 => out.quality_check = d.bool().ok()?,
                7 => out.created = Some(d.i64().ok()?),
                8 => out.expiry = Some(d.i64().ok()?),
                9 => out.expires = d.bool().ok()?,
                10 => out.autotype = Some(decode_autotype(&mut d)?),
                11 => out.custom_data = decode_pairs(&mut d)?,
                _ => d.skip().ok()?,
            }
        }
        (d.position() == bytes.len()).then_some(out)
    }
}

fn pairs<W: minicbor::encode::Write>(
    e: &mut Encoder<W>,
    pairs: &[(String, String)],
) -> Result<(), minicbor::encode::Error<W::Error>> {
    e.array(pairs.len() as u64)?;
    for (a, b) in pairs {
        e.array(2)?.str(a)?.str(b)?;
    }
    Ok(())
}

fn decode_pairs(d: &mut Decoder<'_>) -> Option<Vec<(String, String)>> {
    let n = d.array().ok()??;
    (0..n)
        .map(|_| {
            (d.array().ok()? == Some(2)).then_some(())?;
            Some((d.str().ok()?.to_string(), d.str().ok()?.to_string()))
        })
        .collect()
}

fn decode_autotype(d: &mut Decoder<'_>) -> Option<AutoType> {
    let mut a = AutoType::default();
    let n = d.map().ok()??;
    for _ in 0..n {
        match d.u64().ok()? {
            1 => a.enabled = d.bool().ok()?,
            2 => a.sequence = Some(d.str().ok()?.to_string()),
            3 => a.use_clipboard = d.bool().ok()?,
            4 => a.associations = decode_pairs(d)?,
            _ => d.skip().ok()?,
        }
    }
    Some(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_tolerates_unknown_keys() {
        let full = Extras {
            uuid: Some([7; 16]),
            icon: Some(12),
            foreground: Some("#FF0000".into()),
            background: Some("#00FF00".into()),
            override_url: Some("cmd://x".into()),
            quality_check: false,
            created: Some(1_600_000_000),
            expiry: Some(-5),
            expires: true,
            autotype: Some(AutoType {
                enabled: false,
                sequence: Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".into()),
                use_clipboard: true,
                associations: vec![("*Firefox*".into(), "{PASSWORD}".into())],
            }),
            custom_data: vec![("KPXC_x".into(), "y".into())],
        };
        assert_eq!(Extras::decode(&full.encode()), Some(full));
        assert_eq!(
            Extras::decode(&Extras::default().encode()),
            Some(Extras::default())
        );

        // {1: h'07'*16, 99: "future"} decodes, ignoring key 99.
        let mut e = Encoder::new(Vec::new());
        e.map(2).unwrap().u8(1).unwrap().bytes(&[7; 16]).unwrap();
        e.u8(99).unwrap().str("future").unwrap();
        let decoded = Extras::decode(e.writer()).unwrap();
        assert_eq!(decoded.uuid, Some([7; 16]));

        for bad in [
            &b""[..],
            b"\xa1\x01\x41\x00",
            b"\x80",
            b"\xa1\x02\x02trailing",
        ] {
            assert_eq!(Extras::decode(bad), None, "{bad:?}");
        }
    }
}
