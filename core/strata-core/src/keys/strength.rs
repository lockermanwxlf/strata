//! Password strength estimate for the UI's weak-password warning (spec §6.2).
//!
//! Advisory only: passwords of any strength are allowed (the user's choice). This
//! never blocks anything; it tells the UI when it must warn and ask for "use anyway".
//!
//! Caveat: zxcvbn copies fragments of the password into its own match structures,
//! which aren't zeroized. The estimate runs only while the user is choosing a
//! password, never during unlock.

use zxcvbn::zxcvbn;

use crate::error::{CoreError, Result};

/// Below this many estimated guesses (10^10), the UI must warn (spec §6.2).
pub const WARN_BELOW_GUESSES_LOG10: f64 = 10.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PasswordStrength {
    /// log10 of zxcvbn's estimated guesses to crack the password.
    pub guesses_log10: f64,
    /// The UI must warn and require an explicit "use anyway".
    pub warn: bool,
}

/// zxcvbn looks at this many characters at most. Its matching is superlinear in the
/// length, and anything past this is already far beyond the warning threshold.
pub const MAX_CHARS_ESTIMATED: usize = 100;

pub fn password_strength(password: &[u8]) -> Result<PasswordStrength> {
    let text = std::str::from_utf8(password)
        .map_err(|_| CoreError::rejected("password", "not valid UTF-8"))?;
    // A prefix slice, not a copy, so no new buffer holds the password.
    let end = text
        .char_indices()
        .nth(MAX_CHARS_ESTIMATED)
        .map_or(text.len(), |(i, _)| i);
    let guesses_log10 = zxcvbn(&text[..end], &[]).guesses_log10();
    Ok(PasswordStrength {
        guesses_log10,
        warn: guesses_log10 < WARN_BELOW_GUESSES_LOG10,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warns_on_weak_and_not_on_strong() {
        assert!(password_strength(b"password1").unwrap().warn);
        assert!(password_strength(b"hunter2").unwrap().warn);
        assert!(password_strength(b"").unwrap().warn);
        let strong = password_strength(b"lapel tundra viscous ozone carafe jigsaw").unwrap();
        assert!(!strong.warn, "{strong:?}");
        assert!(password_strength(&[0xff]).is_err());
        // Long input is estimated on its first 100 characters and comes back quickly.
        let long = "correct horse battery staple ".repeat(1000);
        assert!(!password_strength(long.as_bytes()).unwrap().warn);
    }
}
