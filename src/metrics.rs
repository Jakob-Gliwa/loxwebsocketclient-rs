//! Connection metrics mirroring the Python `_MetricsState` / `LoxWsMetrics` API.

use crate::sync::lock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const MESSAGE_TYPE_COUNT: usize = 8;

/// Lifecycle state of the IO supervisor.
///
/// Stored as a single atomic byte so `LoxClient::state()` never blocks the
/// reader task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ConnState {
    #[default]
    Closed = 0,
    Connecting = 1,
    Connected = 2,
    Reconnecting = 3,
}

impl ConnState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "CLOSED",
            Self::Connecting => "CONNECTING",
            Self::Connected => "CONNECTED",
            Self::Reconnecting => "RECONNECTING",
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Connecting,
            2 => Self::Connected,
            3 => Self::Reconnecting,
            _ => Self::Closed,
        }
    }
}

impl std::fmt::Display for ConnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Atomic cell holding the current [`ConnState`].
#[derive(Debug, Default)]
pub(crate) struct ConnStateCell(AtomicU8);

impl ConnStateCell {
    pub fn set(&self, state: ConnState) {
        self.0.store(state as u8, Ordering::Relaxed);
    }

    pub fn get(&self) -> ConnState {
        ConnState::from_u8(self.0.load(Ordering::Relaxed))
    }
}

/// Immutable snapshot of client connection metrics.
#[derive(Debug, Clone)]
pub struct LoxMetrics {
    pub state: ConnState,
    pub connects: u64,
    pub reconnects: u64,
    pub reconnect_attempts: u64,
    pub reconnect_failures: u64,
    pub disconnects: u64,
    pub messages_received: u64,
    pub commands_sent: u64,
    pub command_timeouts: u64,
    pub command_errors: u64,
    /// Type-0 responses whose `LL.control` did not match the command the
    /// waiter was registered for.
    pub correlation_mismatches: u64,
    /// Type-0 responses that arrived with no waiter registered at all.
    pub unsolicited_responses: u64,
    /// Keepalives sent for which no type-6 answer was seen.
    pub keepalive_misses: u64,
    /// Controls refused because there was no live session to send them on.
    pub controls_rejected_offline: u64,
    /// Controls refused because the command channel had no room. Only
    /// `try_send_control` produces these; the awaiting form waits instead.
    pub controls_rejected_backpressure: u64,
    pub messages_received_by_type: [u64; MESSAGE_TYPE_COUNT],
    pub disconnects_by_close_code: HashMap<Option<u16>, u64>,
    pub connected_since_monotonic: Option<Instant>,
    pub connected_since_wall: Option<f64>,
    pub token_valid_until: Option<i64>,
    /// Last keepalive round-trip time in milliseconds (if measured).
    pub last_keepalive_rtt_ms: Option<f64>,
}

impl LoxMetrics {
    /// Seconds since the current connection was (re)established, or `0.0`.
    pub fn uptime_seconds(&self) -> f64 {
        match self.connected_since_monotonic {
            Some(t) => t.elapsed().as_secs_f64(),
            None => 0.0,
        }
    }
}

/// Shared mutable metrics store (cheap increments on the IO task).
#[derive(Debug, Default)]
pub(crate) struct MetricsState {
    pub connects: AtomicU64,
    pub reconnects: AtomicU64,
    pub reconnect_attempts: AtomicU64,
    pub reconnect_failures: AtomicU64,
    pub disconnects: AtomicU64,
    pub messages_received: AtomicU64,
    pub commands_sent: AtomicU64,
    pub command_timeouts: AtomicU64,
    pub command_errors: AtomicU64,
    pub correlation_mismatches: AtomicU64,
    pub unsolicited_responses: AtomicU64,
    pub keepalive_misses: AtomicU64,
    pub controls_rejected_offline: AtomicU64,
    pub controls_rejected_backpressure: AtomicU64,
    by_type: [AtomicU64; MESSAGE_TYPE_COUNT],
    by_close_code: Mutex<HashMap<Option<u16>, u64>>,
    connected_since: Mutex<(Option<Instant>, Option<f64>)>,
    last_keepalive_rtt_ms: Mutex<Option<f64>>,
}

impl MetricsState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn mark_connected(&self) {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        *lock(&self.connected_since) = (Some(Instant::now()), Some(wall));
    }

    pub fn mark_disconnected(&self, close_code: Option<u16>) {
        self.disconnects.fetch_add(1, Ordering::Relaxed);
        *lock(&self.by_close_code).entry(close_code).or_insert(0) += 1;
        *lock(&self.connected_since) = (None, None);
    }

    pub fn record_message(&self, msg_type: u8) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
        if (msg_type as usize) < MESSAGE_TYPE_COUNT {
            self.by_type[msg_type as usize].fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn set_keepalive_rtt_ms(&self, rtt_ms: f64) {
        *lock(&self.last_keepalive_rtt_ms) = Some(rtt_ms);
    }

    pub fn snapshot(&self, state: ConnState, token_valid_until: Option<i64>) -> LoxMetrics {
        let mut by_type = [0u64; MESSAGE_TYPE_COUNT];
        for (i, slot) in by_type.iter_mut().enumerate() {
            *slot = self.by_type[i].load(Ordering::Relaxed);
        }
        let (mono, wall) = *lock(&self.connected_since);
        LoxMetrics {
            state,
            connects: self.connects.load(Ordering::Relaxed),
            reconnects: self.reconnects.load(Ordering::Relaxed),
            reconnect_attempts: self.reconnect_attempts.load(Ordering::Relaxed),
            reconnect_failures: self.reconnect_failures.load(Ordering::Relaxed),
            disconnects: self.disconnects.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            commands_sent: self.commands_sent.load(Ordering::Relaxed),
            command_timeouts: self.command_timeouts.load(Ordering::Relaxed),
            command_errors: self.command_errors.load(Ordering::Relaxed),
            correlation_mismatches: self.correlation_mismatches.load(Ordering::Relaxed),
            unsolicited_responses: self.unsolicited_responses.load(Ordering::Relaxed),
            keepalive_misses: self.keepalive_misses.load(Ordering::Relaxed),
            controls_rejected_offline: self.controls_rejected_offline.load(Ordering::Relaxed),
            controls_rejected_backpressure: self
                .controls_rejected_backpressure
                .load(Ordering::Relaxed),
            messages_received_by_type: by_type,
            disconnects_by_close_code: lock(&self.by_close_code).clone(),
            connected_since_monotonic: mono,
            connected_since_wall: wall,
            token_valid_until,
            last_keepalive_rtt_ms: *lock(&self.last_keepalive_rtt_ms),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrips_through_the_atomic_cell() {
        let cell = ConnStateCell::default();
        assert_eq!(cell.get(), ConnState::Closed);
        for s in [
            ConnState::Connecting,
            ConnState::Connected,
            ConnState::Reconnecting,
            ConnState::Closed,
        ] {
            cell.set(s);
            assert_eq!(cell.get(), s);
            assert_eq!(cell.get().to_string(), s.as_str());
        }
    }
}
