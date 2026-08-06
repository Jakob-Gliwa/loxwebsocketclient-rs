//! Keepalive bookkeeping and the reader's idle window.
//!
//! The timings here are configured down to seconds through [`ConnectConfig`],
//! so the tests measure real behaviour without waiting out the production
//! constants (a 60 s keepalive period and a 150 s idle window).

mod common;

use common::{Entry, FakeConfig, FakeMiniserver, Rec, RecordingHandler};
use loxwebsocket::{ConnState, LoxClient, MessageType};
use std::time::Duration;

/// Number of keepalives the fake has answered.
fn keepalives(fake: &FakeMiniserver) -> usize {
    fake.state
        .log()
        .iter()
        .filter(|entry| matches!(entry, Entry::Keepalive { .. }))
        .count()
}

/// A type-6 answer clears the missed-keepalive counter, so a quiet but healthy
/// connection survives indefinitely.
#[tokio::test]
async fn answered_keepalives_keep_the_session_alive() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    cfg.keepalive_secs = 1;
    cfg.max_missed_keepalives = 1;
    cfg.read_idle_timeout_secs = 10;

    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");

    // Three rounds is one more than the tolerated miss count, so a liveness
    // counter that never resets would have dropped the session by now.
    fake.state
        .wait_until(20, "three answered keepalives", |log| {
            log.iter()
                .filter(|entry| matches!(entry, Entry::Keepalive { .. }))
                .count()
                >= 3
        })
        .await;

    let acks = common::collect_recs(&mut events, 10, 3, |rec| matches!(rec, Rec::Keepalive)).await;
    assert_eq!(acks.len(), 3);
    assert_eq!(client.state(), ConnState::Connected);
    assert_eq!(fake.state.session_count(), 1, "the session was replaced");
    let metrics = client.metrics();
    assert!(metrics.last_keepalive_rtt_ms.is_some());
    assert_eq!(metrics.keepalive_misses, 0);

    let _ = common::within(15, "stop", client.stop()).await;
}

/// A Miniserver that stops answering keepalives is treated as gone after
/// `max_missed_keepalives` rounds, well before the idle window would notice.
#[tokio::test]
async fn unanswered_keepalives_discard_the_session() {
    let fake = FakeMiniserver::start(FakeConfig {
        answer_keepalive: false,
        ..FakeConfig::default()
    })
    .await;
    let (handler, mut events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    cfg.keepalive_secs = 1;
    cfg.max_missed_keepalives = 2;
    // Deliberately far away: the keepalive counter has to be what ends this,
    // not the idle window.
    cfg.read_idle_timeout_secs = 60;
    cfg.connect_delay_secs = 0;

    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");

    // The session must end, either by reconnecting or by giving up.
    let rec = common::wait_rec(&mut events, 20, |rec| {
        matches!(
            rec,
            Rec::ConnectionClosed(_) | Rec::Closed | Rec::Reconnected
        )
    })
    .await;
    assert!(
        keepalives(&fake) >= 2,
        "the session ended before two keepalives went unanswered: {rec:?}"
    );

    let _ = common::within(15, "stop", client.stop()).await;
}

/// Silence longer than the idle window ends the session. The window is the
/// client's only defence against a connection that is open but dead — a
/// half-open TCP connection never reports an error.
#[tokio::test]
async fn silence_beyond_the_idle_window_ends_the_session() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    cfg.read_idle_timeout_secs = 1;
    // No keepalive traffic to reset the window.
    cfg.keepalive_secs = 3_600;
    cfg.connect_delay_secs = 0;

    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");

    let rec = common::within(
        10,
        "the idle timeout",
        common::wait_rec(&mut events, 8, |rec| {
            matches!(
                rec,
                Rec::ConnectionClosed(_) | Rec::Closed | Rec::Reconnected
            )
        }),
    )
    .await;
    assert!(
        matches!(
            rec,
            Rec::ConnectionClosed(_) | Rec::Closed | Rec::Reconnected
        ),
        "{rec:?}"
    );

    let _ = common::within(15, "stop", client.stop()).await;
}

/// An announced payload length widens the window for exactly that frame
/// (`keepalive::read_timeout`), so a large table may take its time — but the
/// bound still applies once the announcement is exhausted.
#[tokio::test]
async fn an_announced_length_widens_the_window_for_that_frame() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    cfg.read_idle_timeout_secs = 1;
    cfg.keepalive_secs = 3_600;
    cfg.connect_delay_secs = 30;

    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");
    let session = fake.state.session(0).await;

    // 8 MiB announced: 1 s base plus 256 s at the assumed floor throughput. The
    // payload never arrives, and the reader must still be waiting.
    session.send_header(MessageType::ValueStates as u8, 0, 8 * 1024 * 1024);
    session.flushed().await;

    let gave_up = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match events.recv().await {
                Some(rec) if matches!(rec, Rec::ConnectionClosed(_) | Rec::Closed) => return rec,
                Some(_) => {}
                None => return Rec::Closed,
            }
        }
    })
    .await;
    assert!(
        gave_up.is_err(),
        "the reader gave up on an announced 8 MiB payload after 3s: {gave_up:?}"
    );
    assert_eq!(client.state(), ConnState::Connected);

    // The payload finally arrives and is dispatched normally.
    session.send_raw(
        vec![common::ws::frame(
            common::ws::OP_BINARY,
            &common::value_payload(&[(common::uuid(0x42), 4.2)]),
        )],
        Duration::ZERO,
    );
    let rec = common::wait_rec(&mut events, 10, |rec| matches!(rec, Rec::Value { .. })).await;
    assert_eq!(
        rec,
        Rec::Value {
            uuid: common::uuid(0x42),
            value: 4.2
        }
    );

    let _ = common::within(15, "stop", client.stop()).await;
}

/// A header that announces a small payload keeps a small window: announcing
/// 100 bytes buys one extra second, not a free pass.
#[tokio::test]
async fn a_small_announcement_does_not_disable_the_window() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    cfg.read_idle_timeout_secs = 1;
    cfg.keepalive_secs = 3_600;
    // An idle timeout is a session *failure*, which reports no handler event of
    // its own — the observable consequence is the reconnect that follows, so it
    // must not be parked behind a delay.
    cfg.connect_delay_secs = 0;

    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");
    let session = fake.state.session(0).await;

    session.send_header(MessageType::ValueStates as u8, 0, 100);
    session.flushed().await;

    // 1 s base + 1 s for the announcement, so this has to fire well inside 8 s.
    let rec = common::wait_rec(&mut events, 8, |rec| {
        matches!(
            rec,
            Rec::ConnectionClosed(_) | Rec::Closed | Rec::Reconnected
        )
    })
    .await;
    assert!(
        matches!(
            rec,
            Rec::ConnectionClosed(_) | Rec::Closed | Rec::Reconnected
        ),
        "{rec:?}"
    );

    let _ = common::within(15, "stop", client.stop()).await;
}

/// A connection dropped without a close frame has to be noticed too.
#[tokio::test]
async fn an_aborted_connection_ends_the_session() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    cfg.connect_delay_secs = 0;
    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");

    fake.state.session(0).await.abort();

    let rec = common::wait_rec(&mut events, 15, |rec| {
        matches!(
            rec,
            Rec::ConnectionClosed(_) | Rec::Closed | Rec::Reconnected
        )
    })
    .await;
    assert!(
        matches!(
            rec,
            Rec::ConnectionClosed(_) | Rec::Closed | Rec::Reconnected
        ),
        "{rec:?}"
    );

    let _ = common::within(15, "stop", client.stop()).await;
}

/// A connection that dies without a close frame must still reconnect.
///
/// Regression test: `ever_connected` used to be set only in the `Disconnected`
/// branch, so a first session ending in a *failure* — an aborted TCP
/// connection, a read error, the idle timeout — took the `if !ever_connected`
/// exit and the client gave up for good. `SessionResult::connected` now reports
/// a completed handshake regardless of how the session then ended.
#[tokio::test]
async fn an_aborted_connection_reconnects() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    cfg.connect_delay_secs = 0;
    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");

    fake.state.session(0).await.abort();

    common::wait_rec(&mut events, 15, |rec| matches!(rec, Rec::Reconnected)).await;
    assert_eq!(client.state(), ConnState::Connected);
    assert_eq!(fake.state.session_count(), 2);

    let _ = common::within(15, "stop", client.stop()).await;
}
