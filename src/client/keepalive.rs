//! Keepalive, timeout and liveness timing.

use tokio::time::Duration;

/// Plaintext `keepalive` period (seconds).
pub const KEEP_ALIVE_PERIOD_SECS: u64 = 60;

/// Delay between reconnect attempts (seconds).
pub const CONNECT_DELAY_SECS: u64 = 15;

/// Backoff for conditions that will not clear within seconds: exhausted event
/// slots, a Miniserver update, or a login block.
pub const LONG_BACKOFF_SECS: u64 = 5 * 60;

/// Token refresh lead time (seconds before expiry).
pub const TOKEN_REFRESH_SECONDS_BEFORE_EXPIRY: i64 = 24 * 60 * 60;

/// Fallback refresh interval when expiry is unknown / token empty.
pub const TOKEN_REFRESH_DEFAULT_SECONDS: i64 = 2 * 24 * 60 * 60;

/// How long a session must last to count as productive (seconds).
///
/// Only such a session clears the reconnect failure budget. A Miniserver that
/// accepts the handshake and drops the connection again is flapping, not
/// working, and must still run into `max_reconnect_attempts`.
pub const PRODUCTIVE_SESSION_SECS: u64 = 60;

/// Floor for the refresh delay (seconds).
///
/// A token already inside its lead time would otherwise schedule a refresh
/// immediately and, if the Miniserver keeps handing back the same expiry, spin.
pub const TOKEN_REFRESH_MIN_DELAY_SECS: i64 = 15;

/// Encrypted command response timeout.
pub const COMMAND_TIMEOUT_SECS: u64 = 30;

/// Timeout for the best-effort `killtoken` sent during shutdown.
pub const SHUTDOWN_COMMAND_TIMEOUT_SECS: u64 = 3;

/// How long `LoxClient::stop` waits for the IO task before giving up.
pub const SHUTDOWN_JOIN_TIMEOUT_SECS: u64 = 10;

/// Base reader idle timeout — no frame at all within this window means the
/// connection is dead. Must exceed [`KEEP_ALIVE_PERIOD_SECS`], otherwise a
/// healthy but quiet connection is torn down before its own keepalive answers.
pub const READ_IDLE_TIMEOUT_SECS: u64 = 2 * KEEP_ALIVE_PERIOD_SECS + 30;

/// Unanswered keepalives tolerated before the session is discarded.
pub const MAX_MISSED_KEEPALIVES: u32 = 3;

/// Throughput assumed when extending the idle timeout for an announced payload.
///
/// Deliberately pessimistic: a Miniserver on a congested link still has to beat
/// this to keep its connection, but a multi-megabyte structure file gets a
/// window measured in seconds rather than milliseconds.
const MIN_PAYLOAD_THROUGHPUT_BYTES_PER_SEC: u64 = 32 * 1024;

/// Upper bound on the extension so a bogus length field cannot park the reader
/// forever.
const MAX_PAYLOAD_EXTENSION_SECS: u64 = 10 * 60;

/// Idle timeout for the frame that carries `announced_len` payload bytes.
///
/// The message header tells us up front how much data follows — including for
/// estimated headers, where the value is a lower bound — so a large table does
/// not have to fit into the same window as a keepalive answer.
pub fn read_timeout(base: Duration, announced_len: u32) -> Duration {
    if announced_len == 0 {
        return base;
    }
    let extra = (announced_len as u64)
        .div_ceil(MIN_PAYLOAD_THROUGHPUT_BYTES_PER_SEC)
        .min(MAX_PAYLOAD_EXTENSION_SECS);
    base + Duration::from_secs(extra)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: Duration = Duration::from_secs(150);

    #[test]
    fn header_frames_use_the_base_timeout() {
        assert_eq!(read_timeout(BASE, 0), BASE);
    }

    #[test]
    fn small_payloads_add_a_single_second() {
        assert_eq!(read_timeout(BASE, 1), BASE + Duration::from_secs(1));
        assert_eq!(read_timeout(BASE, 32 * 1024), BASE + Duration::from_secs(1));
        assert_eq!(
            read_timeout(BASE, 32 * 1024 + 1),
            BASE + Duration::from_secs(2)
        );
    }

    #[test]
    fn large_payloads_scale_with_announced_length() {
        // 8 MiB of structure file at the assumed floor throughput.
        assert_eq!(
            read_timeout(BASE, 8 * 1024 * 1024),
            BASE + Duration::from_secs(256)
        );
    }

    #[test]
    fn extension_is_capped() {
        assert_eq!(
            read_timeout(BASE, u32::MAX),
            BASE + Duration::from_secs(MAX_PAYLOAD_EXTENSION_SECS)
        );
    }

    #[test]
    fn idle_timeout_outlives_a_keepalive_round() {
        const { assert!(READ_IDLE_TIMEOUT_SECS > KEEP_ALIVE_PERIOD_SECS) };
    }
}
