//! Hybrid logical clocks (spec §8.3): 48 bits of Unix milliseconds, 16 bits of counter.
//!
//! An HLC only orders concurrent non-secret writes and labels history. Causality is
//! the vector clocks' job.

use crate::error::{CoreError, Result};

const COUNTER_BITS: u32 = 16;
const MS_MASK: u64 = (1 << 48) - 1;
/// Readers warn about HLCs further than this ahead of their own clock (spec §8.3).
pub const MAX_FUTURE_MS: u64 = 24 * 60 * 60 * 1000;

/// The HLC with this many milliseconds and a zero counter.
pub fn from_ms(ms: u64) -> u64 {
    (ms & MS_MASK) << COUNTER_BITS
}

pub fn ms(hlc: u64) -> u64 {
    hlc >> COUNTER_BITS
}

/// The HLC for a new event: strictly above `latest` (the highest HLC this device
/// has applied or written) and no earlier than the wall clock, i.e.
/// `max(latest + 1, now_ms << 16)`. A full counter carries into the milliseconds on
/// its own, because the counter is the low bits.
pub fn next(latest: u64, now_ms: u64) -> Result<u64> {
    let after = latest.checked_add(1).ok_or(CoreError::rejected(
        "clock",
        "hybrid logical clock exhausted",
    ))?;
    Ok(after.max(from_ms(now_ms)))
}

/// The wall clock in milliseconds.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Whether `hlc` is suspiciously far ahead of `now_ms` (spec §8.3: warn, don't reject).
pub fn is_far_future(hlc: u64, now_ms: u64) -> bool {
    ms(hlc) > now_ms.saturating_add(MAX_FUTURE_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_the_wall_clock_and_never_goes_back() {
        assert_eq!(next(0, 1000).unwrap(), from_ms(1000));
        // A clock behind the latest HLC: the counter moves instead.
        let latest = from_ms(5000) + 3;
        assert_eq!(next(latest, 1000).unwrap(), latest + 1);
        // Counter overflow carries into the milliseconds.
        let full = from_ms(5000) + 0xffff;
        assert_eq!(next(full, 1000).unwrap(), from_ms(5001));
        assert!(next(u64::MAX, 0).is_err());
    }

    #[test]
    fn far_future() {
        assert!(!is_far_future(from_ms(1000 + MAX_FUTURE_MS), 1000));
        assert!(is_far_future(from_ms(1001 + MAX_FUTURE_MS), 1000));
    }
}
