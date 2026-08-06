//! Sync zero-copy event handler trait (invoked on the reader task).

use crate::proto::{DaytimerEvent, WeatherEvent};
use crate::uuid::LoxoneUuid;
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

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
}
