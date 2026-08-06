//! Reconnect and token-retention policy derived from the close code.

use crate::error::Error;

/// `0` means unlimited attempts (Python `CONNECT_RETRIES = 0`).
pub fn should_continue(attempt: u32, max_attempts: u32) -> bool {
    max_attempts == 0 || attempt < max_attempts
}

/// How long to wait before the next connect attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backoff {
    /// The usual short delay; the condition is expected to clear immediately.
    Normal,
    /// A condition that needs minutes, not seconds: no free event slots, a
    /// firmware update in progress, or a login block.
    Long,
}

/// Classify a close code into a reconnect delay.
pub fn backoff_for_close(code: Option<u16>) -> Backoff {
    match code {
        // Too many failed login attempts — retrying fast only extends the block.
        Some(4003) => Backoff::Long,
        // Miniserver performing an update.
        Some(4007) => Backoff::Long,
        // All 31 event slots are taken; another client has to disconnect first.
        Some(4008) => Backoff::Long,
        _ => Backoff::Normal,
    }
}

/// The error a close code the client cannot reconnect out of maps to.
///
/// 4006 says the user this client authenticates as has been disabled. Only an
/// administrator can undo that, so a retry loop would knock on the Miniserver
/// every `connect_delay_secs` for as long as the process lives and never
/// succeed. Reporting [`ClientEvent::Closed`] instead makes the condition
/// visible to the caller, who is the only one able to act on it.
///
/// [`ClientEvent::Closed`]: crate::ClientEvent::Closed
pub fn terminal_close(code: Option<u16>) -> Option<Error> {
    matches!(code, Some(4006)).then_some(Error::UserDisabled)
}

/// Whether the in-memory token stays usable after a disconnect with `code`.
///
/// Tokens are transient but survive plain transport failures — discarding them
/// on every reconnect fills the Miniserver's token storage with dead entries.
/// Only codes that mean "the user behind this token changed" invalidate it.
pub fn token_survives_close(code: Option<u16>) -> bool {
    !matches!(code, Some(4004) | Some(4005) | Some(4006))
}

/// Classify Loxone-specific WebSocket close codes.
pub fn describe_close_code(code: Option<u16>) -> &'static str {
    match code {
        Some(1000) => "normal closure",
        Some(1001) => "endpoint going away (shutdown/reboot)",
        Some(1005) => "closed without status code",
        Some(1006) => "abnormal closure (no close frame)",
        Some(1011) => "Miniserver internal error",
        Some(1012) => "Miniserver restarting",
        Some(4003) => "blocked: too many failed login attempts",
        Some(4004) => "a user has been changed",
        Some(4005) => "connected user has been changed",
        Some(4006) => "user has been disabled",
        Some(4007) => "Miniserver performing an update",
        Some(4008) => "no event slots available",
        Some(_) => "unrecognized close code",
        None => "closed without close code",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_means_unlimited() {
        assert!(should_continue(0, 0));
        assert!(should_continue(9_999, 0));
        assert!(should_continue(2, 3));
        assert!(!should_continue(3, 3));
    }

    #[test]
    fn transient_failures_keep_the_short_delay() {
        for code in [
            None,
            Some(1000),
            Some(1001),
            Some(1006),
            Some(1012),
            Some(4004),
        ] {
            assert_eq!(backoff_for_close(code), Backoff::Normal, "{code:?}");
        }
    }

    #[test]
    fn structural_refusals_get_the_long_backoff() {
        for code in [Some(4003), Some(4007), Some(4008)] {
            assert_eq!(backoff_for_close(code), Backoff::Long, "{code:?}");
        }
    }

    /// 4004/4005 describe a change the next connect picks up; 4006 describes a
    /// state only an administrator can lift, so it must not become a retry loop.
    #[test]
    fn only_a_disabled_user_ends_the_client() {
        assert!(matches!(
            terminal_close(Some(4006)),
            Some(Error::UserDisabled)
        ));
        for code in [
            None,
            Some(1000),
            Some(1006),
            Some(4003),
            Some(4004),
            Some(4005),
            Some(4008),
        ] {
            assert!(terminal_close(code).is_none(), "{code:?}");
        }
    }

    #[test]
    fn only_user_changes_invalidate_the_token() {
        for code in [Some(4004), Some(4005), Some(4006)] {
            assert!(!token_survives_close(code), "{code:?}");
        }
        for code in [
            None,
            Some(1000),
            Some(1006),
            Some(1012),
            Some(4003),
            Some(4008),
        ] {
            assert!(token_survives_close(code), "{code:?}");
        }
    }
}
