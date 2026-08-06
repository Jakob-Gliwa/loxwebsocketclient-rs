//! Sync zero-copy event handler trait (invoked on the reader task).

use crate::error::{Error, Result};
use crate::proto::{DaytimerEvent, WeatherEvent};
use crate::uuid::LoxoneUuid;
use bytes::Bytes;
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use tracing::error;

/// Lifecycle / connection events.
#[derive(Debug, Clone)]
pub enum ClientEvent {
    Connected,
    Reconnected,
    ConnectionClosed { close_code: Option<u16> },
    Closed,
}

/// Sync callbacks invoked while the WS frame payload is still borrowed.
///
/// Implementations **must not** retain borrowed slices across `.await` points —
/// the payload lifetime ends at the next `read_frame`. Copy only what you need.
///
/// # Ordering against `ClientEvent`
///
/// A handful of state callbacks can fire *before* [`ClientEvent::Connected`].
/// `enablebinstatusupdate` makes the Miniserver start pushing, and some
/// firmwares send the first event tables before acknowledging the command; the
/// client forwards them rather than dropping the initial state of every
/// control. Handlers that key off `Connected` to reset their state should
/// therefore reset on [`ClientEvent::ConnectionClosed`] instead.
///
/// # Panics
///
/// A callback that unwinds no longer takes the client's IO task with it, but it
/// does end the session: the client delivers [`ClientEvent::Closed`], settles
/// in [`ConnState::Closed`] and does not reconnect, because the handler's own
/// state is in doubt from that point and a retry would only hit the same bug.
/// [`LoxClient::stop`] then reports [`Error::HandlerPanic`]. Built with
/// `panic = "abort"` the process still dies.
///
/// [`ConnState::Closed`]: crate::ConnState::Closed
/// [`LoxClient::stop`]: crate::LoxClient::stop
pub trait LoxHandler: Send + 'static {
    fn on_value(&mut self, _uuid: &LoxoneUuid, _value: f64) {}
    fn on_text(&mut self, _uuid: &LoxoneUuid, _icon: &LoxoneUuid, _text: &[u8]) {}
    fn on_daytimer(&mut self, _event: DaytimerEvent<'_>) {}
    fn on_weather(&mut self, _event: WeatherEvent<'_>) {}
    /// Type-0 text/JSON payload (raw bytes).
    fn on_json(&mut self, _payload: &[u8]) {}
    /// Type-1 binary file payload.
    fn on_binary(&mut self, _payload: &[u8]) {}
    fn on_keepalive(&mut self) {}
    fn on_event(&mut self, _event: ClientEvent) {}
    /// Raw Loxone payload after the header frame, before per-record walking.
    ///
    /// Useful for capture/benchmark tooling. Default is a no-op; the hot path
    /// does not pay for this unless an implementation overrides it.
    fn on_raw_payload(&mut self, _msg_type: u8, _payload: &[u8]) {}
}

/// Owned event for pull-based consumers via [`ChannelHandler`].
#[derive(Debug, Clone)]
pub enum OwnedEvent {
    Value {
        uuid: LoxoneUuid,
        value: f64,
    },
    Text {
        uuid: LoxoneUuid,
        icon: LoxoneUuid,
        text: Bytes,
    },
    Json {
        payload: Bytes,
    },
    Binary {
        payload: Bytes,
    },
    Keepalive,
    Lifecycle(ClientEvent),
}

/// Convenience adapter that clones into an `mpsc` channel (not the hot-path default).
///
/// The reader must never block, so events are dropped when the queue is full.
/// [`ChannelHandler::dropped`] makes that loss visible instead of silent.
#[derive(Debug)]
pub struct ChannelHandler {
    tx: mpsc::Sender<OwnedEvent>,
    dropped: Arc<AtomicU64>,
}

/// Counts events a [`ChannelHandler`] had to discard.
#[derive(Debug, Clone)]
pub struct DropCounter(Arc<AtomicU64>);

impl DropCounter {
    /// Events dropped so far because the receiver could not keep up.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl ChannelHandler {
    pub fn new(buffer: usize) -> (Self, mpsc::Receiver<OwnedEvent>) {
        let (tx, rx) = mpsc::channel(buffer);
        (
            Self {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    /// Handle for observing dropped events after the handler has been moved
    /// into [`crate::LoxClient::connect`].
    pub fn dropped(&self) -> DropCounter {
        DropCounter(Arc::clone(&self.dropped))
    }

    fn send(&self, event: OwnedEvent) {
        if self.tx.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl LoxHandler for ChannelHandler {
    fn on_value(&mut self, uuid: &LoxoneUuid, value: f64) {
        self.send(OwnedEvent::Value { uuid: *uuid, value });
    }

    fn on_text(&mut self, uuid: &LoxoneUuid, icon: &LoxoneUuid, text: &[u8]) {
        self.send(OwnedEvent::Text {
            uuid: *uuid,
            icon: *icon,
            text: Bytes::copy_from_slice(text),
        });
    }

    fn on_json(&mut self, payload: &[u8]) {
        self.send(OwnedEvent::Json {
            payload: Bytes::copy_from_slice(payload),
        });
    }

    fn on_binary(&mut self, payload: &[u8]) {
        self.send(OwnedEvent::Binary {
            payload: Bytes::copy_from_slice(payload),
        });
    }

    fn on_keepalive(&mut self) {
        self.send(OwnedEvent::Keepalive);
    }

    fn on_event(&mut self, event: ClientEvent) {
        self.send(OwnedEvent::Lifecycle(event));
    }
}

/// Runs consumer callbacks so that an unwinding one cannot take the client with it.
///
/// The reader loop executes inline on the supervisor task and owns the handler,
/// so a panicking [`LoxHandler`] would otherwise kill that task outright: the
/// state cell would keep reporting [`ConnState::Connected`] forever, no
/// reconnect would follow, no [`ClientEvent::Closed`] would be delivered, and
/// [`LoxClient::stop`] would only ever return a join error.
///
/// A panic is a bug in consumer code, so it is treated as terminal rather than
/// swallowed — carrying on would mean feeding events to a handler whose state
/// is now unknown. It surfaces as [`Error::HandlerPanic`].
///
/// Guarding is per *message*, never per record: [`dispatch_event`] fans a
/// single frame out into thousands of callbacks, and an unwind edge around each
/// of those would land squarely in the hot path.
///
/// This relies on unwinding. Built with `panic = "abort"` the process still
/// dies, which no library can do anything about.
///
/// [`ConnState::Connected`]: crate::ConnState::Connected
/// [`LoxClient::stop`]: crate::LoxClient::stop
/// [`dispatch_event`]: crate::client::reader::dispatch_event
pub(crate) struct HandlerGuard<H> {
    handler: H,
    panicked: bool,
}

impl<H> std::fmt::Debug for HandlerGuard<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerGuard")
            .field("panicked", &self.panicked)
            .finish_non_exhaustive()
    }
}

impl<H: LoxHandler> HandlerGuard<H> {
    pub(crate) fn new(handler: H) -> Self {
        Self {
            handler,
            panicked: false,
        }
    }

    /// Whether consumer code has unwound at some point.
    pub(crate) fn panicked(&self) -> bool {
        self.panicked
    }

    /// Call into the handler, absorbing an unwind.
    ///
    /// Returns `None` both for a fresh panic and for every call after one: once
    /// the handler's invariants are in doubt, re-entering it buys nothing.
    fn guard<R>(&mut self, during: &str, f: impl FnOnce(&mut H) -> R) -> Option<R> {
        if self.panicked {
            return None;
        }
        let handler = &mut self.handler;
        match catch_unwind(AssertUnwindSafe(|| f(handler))) {
            Ok(value) => Some(value),
            Err(payload) => {
                self.panicked = true;
                error!(during, reason = panic_reason(&payload), "handler panicked");
                None
            }
        }
    }

    /// [`Self::guard`], with the unwind reported as a session error.
    pub(crate) fn guard_or_fail<R>(
        &mut self,
        during: &str,
        f: impl FnOnce(&mut H) -> R,
    ) -> Result<R> {
        self.guard(during, f).ok_or(Error::HandlerPanic)
    }

    /// Deliver a lifecycle event, even to a handler that already panicked.
    ///
    /// [`ClientEvent::Closed`] is the only in-band notice that the client gave
    /// up, so it is worth one more attempt; a second unwind is absorbed too.
    pub(crate) fn lifecycle(&mut self, event: ClientEvent) {
        let handler = &mut self.handler;
        let passed = event.clone();
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| handler.on_event(passed))) {
            self.panicked = true;
            error!(
                ?event,
                reason = panic_reason(&payload),
                "handler panicked in on_event"
            );
        }
    }
}

/// Best-effort message out of a panic payload, which is almost always one of these two.
fn panic_reason(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic payload>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_queue_increments_the_drop_counter() {
        let (mut handler, _rx) = ChannelHandler::new(1);
        let dropped = handler.dropped();
        handler.on_keepalive();
        assert_eq!(dropped.get(), 0);
        handler.on_keepalive();
        handler.on_keepalive();
        assert_eq!(dropped.get(), 2);
    }

    #[derive(Default)]
    struct Panicky {
        values: u32,
        events: u32,
        panic_on_value: bool,
    }

    impl LoxHandler for Panicky {
        fn on_value(&mut self, _uuid: &LoxoneUuid, _value: f64) {
            self.values += 1;
            if self.panic_on_value {
                panic!("consumer bug");
            }
        }

        fn on_event(&mut self, _event: ClientEvent) {
            self.events += 1;
        }
    }

    /// The panic hook prints to stderr on every unwind, which is pure noise for
    /// tests that cause one on purpose.
    fn without_panic_output<R>(f: impl FnOnce() -> R) -> R {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let out = f();
        std::panic::set_hook(previous);
        out
    }

    #[test]
    fn a_healthy_handler_is_called_normally() {
        let mut guard = HandlerGuard::new(Panicky::default());
        let uuid = LoxoneUuid::from_bytes([0u8; 16]);

        guard
            .guard_or_fail("test", |h| h.on_value(&uuid, 1.0))
            .expect("no panic");
        assert!(!guard.panicked());
        assert_eq!(guard.handler.values, 1);
    }

    #[test]
    fn a_panicking_handler_is_absorbed_and_reported() {
        let mut guard = HandlerGuard::new(Panicky {
            panic_on_value: true,
            ..Default::default()
        });
        let uuid = LoxoneUuid::from_bytes([0u8; 16]);

        let err = without_panic_output(|| guard.guard_or_fail("test", |h| h.on_value(&uuid, 1.0)))
            .expect_err("the unwind becomes an error");

        assert!(matches!(err, Error::HandlerPanic));
        assert!(err.is_terminal(), "reconnecting cannot fix consumer code");
        assert!(guard.panicked());
    }

    #[test]
    fn nothing_re_enters_a_handler_that_panicked() {
        let mut guard = HandlerGuard::new(Panicky {
            panic_on_value: true,
            ..Default::default()
        });
        let uuid = LoxoneUuid::from_bytes([0u8; 16]);

        without_panic_output(|| {
            let _ = guard.guard_or_fail("test", |h| h.on_value(&uuid, 1.0));
            let _ = guard.guard_or_fail("test", |h| h.on_value(&uuid, 2.0));
        });

        assert_eq!(guard.handler.values, 1, "the second call never happened");
    }

    #[test]
    fn the_closing_event_still_reaches_a_handler_that_panicked() {
        let mut guard = HandlerGuard::new(Panicky {
            panic_on_value: true,
            ..Default::default()
        });
        let uuid = LoxoneUuid::from_bytes([0u8; 16]);

        without_panic_output(|| {
            let _ = guard.guard_or_fail("test", |h| h.on_value(&uuid, 1.0));
            guard.lifecycle(ClientEvent::Closed);
        });

        assert_eq!(guard.handler.events, 1);
    }
}
