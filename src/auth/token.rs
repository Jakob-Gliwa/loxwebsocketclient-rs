//! Loxone token (`validUntil` is seconds since 2009-01-01 UTC).

use crate::crypto::HashAlg;
use std::time::{SystemTime, UNIX_EPOCH};

/// Unix timestamp of 2009-01-01 00:00:00 UTC.
pub const LOXONE_EPOCH: i64 = 1_230_768_000;

/// JWT token state, held in memory only.
///
/// The token is bearer material equivalent to the user's password, so the
/// `Debug` implementation prints its length and expiry but never its value.
#[derive(Clone, Default)]
pub struct LxToken {
    pub token: String,
    pub valid_until: i64,
    pub hash_alg: HashAlg,
}

impl std::fmt::Debug for LxToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LxToken")
            .field("token", &Redacted(self.token.len()))
            .field("valid_until", &self.valid_until)
            .field("hash_alg", &self.hash_alg)
            .finish()
    }
}

/// Renders as `<redacted, N bytes>` — or `<empty>` for zero length.
pub(crate) struct Redacted(pub usize);

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 0 {
            f.write_str("<empty>")
        } else {
            write!(f, "<redacted, {} bytes>", self.0)
        }
    }
}

impl LxToken {
    pub fn new(token: impl Into<String>, valid_until: i64, hash_alg: HashAlg) -> Self {
        Self {
            token: token.into(),
            valid_until,
            hash_alg,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.token.is_empty()
    }

    /// Seconds until expiry (may be negative).
    pub fn seconds_to_expire(&self) -> i64 {
        let expiry = LOXONE_EPOCH + self.valid_until;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        expiry - now
    }

    pub fn clear(&mut self) {
        self.token.clear();
        self.valid_until = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_constant() {
        // 2009-01-01 UTC
        assert_eq!(LOXONE_EPOCH, 1_230_768_000);
    }

    #[test]
    fn far_future_positive() {
        let t = LxToken::new("x", 50 * 365 * 24 * 3600, HashAlg::Sha1);
        assert!(t.seconds_to_expire() > 0);
    }

    #[test]
    fn debug_redacts_the_token() {
        let raw = "eyJhbGciOiJIUzI1NiJ9.secret";
        let t = LxToken::new(raw, 1, HashAlg::Sha256);
        let rendered = format!("{t:?}");
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("eyJ"));
        assert!(rendered.contains(&format!("<redacted, {} bytes>", raw.len())));
        assert!(format!("{:?}", LxToken::default()).contains("<empty>"));
    }
}
