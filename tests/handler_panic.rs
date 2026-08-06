//! An unwinding consumer callback must close the client, not wedge it.
//!
//! The reader loop runs inline on the supervisor task and owns the handler, so
//! before the guard existed a panicking callback killed that task outright:
//! `state()` kept reporting `Connected`, no reconnect followed and `stop()`
//! could only ever report a join error.
//!
//! This file holds a single test on purpose — it swaps the process-wide panic
//! hook, which would otherwise interfere with tests running beside it.

mod common;

use common::FakeMiniserver;
use loxwebsocket::{ClientEvent, ConnState, LoxClient, LoxHandler, LoxoneUuid, MessageType};
use tokio::sync::mpsc;

struct PanicOnValue {
    events: mpsc::UnboundedSender<ClientEvent>,
}

impl LoxHandler for PanicOnValue {
    fn on_value(&mut self, _uuid: &LoxoneUuid, _value: f64) {
        panic!("consumer bug in on_value");
    }

    fn on_event(&mut self, event: ClientEvent) {
        let _ = self.events.send(event);
    }
}

#[tokio::test]
async fn a_panicking_handler_closes_the_client_instead_of_wedging_it() {
    // The unwind below is the point of the test; the default hook would dump a
    // backtrace for it and make a passing run look like a failing one.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let fake = FakeMiniserver::start_default().await;
    let (tx, mut events) = mpsc::unbounded_channel();

    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), PanicOnValue { events: tx }),
    )
    .await
    .expect("connect");
    assert_eq!(client.state(), ConnState::Connected);
    assert!(matches!(
        events.recv().await,
        Some(ClientEvent::Connected | ClientEvent::Reconnected)
    ));

    let session = fake.state.session(0).await;
    session.send_message(
        MessageType::ValueStates as u8,
        &common::value_payload(&[(common::uuid(1), 21.5)]),
    );

    // The handler still learns that the client gave up, even though it is the
    // reason for it.
    let closed = common::within(15, "the closing event", async {
        loop {
            match events.recv().await {
                Some(ClientEvent::Closed) => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await;
    assert!(closed, "the handler never saw ClientEvent::Closed");

    common::within(15, "the state to settle", async {
        while client.state() != ConnState::Closed {
            tokio::task::yield_now().await;
        }
    })
    .await;

    // A panic is a bug in consumer code, so retrying it is pointless — the
    // supervisor must not open a second session.
    assert_eq!(
        fake.state.session_count(),
        1,
        "the client reconnected after a handler panic"
    );

    // The IO task is genuinely finished rather than detached and stuck, so this
    // returns instead of hitting the join timeout.
    common::within(15, "stop", client.stop())
        .await
        .expect("stop");

    std::panic::set_hook(default_hook);
}
