//! Regression tests for the defect the reader was restructured around:
//! [`fastwebsockets::FragmentCollectorRead::read_frame`] is **not cancel-safe**.
//!
//! `parse_frame_header` consumes the two header bytes and the extended length
//! destructively from the persistent read buffer (`buffer.advance(2)`,
//! `get_u16()`) *before* it parks in `while payload_len > buffer.remaining()`
//! waiting for the payload. Dropping that future — which is what a `select!`
//! arm does on every loss — leaves the header consumed and the payload bytes at
//! the front of the buffer. The next call then reads payload as a frame header
//! and the stream is desynchronised for good.
//!
//! The invariant recorded at the `timeout` in `src/client/reader.rs` is
//! therefore: *the idle timeout is the reader's only cancellation, and it is
//! terminal*. These tests pin both halves of that statement — the raw failure
//! mode at the framing layer, and intact delivery through the real reader.

mod common;

use common::{FakeConfig, FakeMiniserver, Rec, RecordingHandler};
use fastwebsockets::{FragmentCollectorRead, OpCode, Role};
use loxwebsocket::{LoxClient, MessageType};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, DuplexStream};

/// Payload length of the split frame; 1000 needs the 16-bit extended length,
/// so the destructive header parse spans four bytes rather than two.
const SPLIT_LEN: usize = 1000;
/// Payload fill byte. `0xAA` is `1010_1010`: read as a frame header it has FIN
/// and RSV2 set, which is why the original failure surfaced as
/// `ReservedBitsNotZero` rather than as silent corruption.
const FILL: u8 = 0xAA;
const FIRST_CHUNK: usize = 400;
const GAP: Duration = Duration::from_millis(200);
const TIMER: Duration = Duration::from_millis(50);

/// Spawns the writer side: a binary frame whose payload arrives in two TCP
/// writes [`GAP`] apart. Returns the client half, already split for reading.
fn split_frame_stream() -> (
    FragmentCollectorRead<tokio::io::ReadHalf<DuplexStream>>,
    tokio::task::JoinHandle<()>,
) {
    let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);

    let writer = tokio::spawn(async move {
        let mut head = vec![0x82, 126];
        head.extend_from_slice(&(SPLIT_LEN as u16).to_be_bytes());
        head.extend_from_slice(&[FILL; FIRST_CHUNK]);
        server_io.write_all(&head).await.expect("first write");
        server_io.flush().await.expect("first flush");

        tokio::time::sleep(GAP).await;

        server_io
            .write_all(&[FILL; SPLIT_LEN - FIRST_CHUNK])
            .await
            .expect("second write");
        server_io.flush().await.expect("second flush");
        // Kept alive so the reader sees a stalled stream, not EOF.
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let (read_half, write_half) = tokio::io::split(client_io);
    let (read, _write) = fastwebsockets::after_handshake_split(read_half, write_half, Role::Client);
    (FragmentCollectorRead::new(read), writer)
}

fn noop_send() -> impl FnMut(fastwebsockets::Frame<'_>) -> std::future::Ready<std::io::Result<()>> {
    |_frame| std::future::ready(Ok(()))
}

/// The failure mode itself, at the framing layer.
///
/// Reads the split frame from a `select!` arm with a competing 50 ms timer —
/// the shape `reader.rs` must never take. The timer fires once inside the 200 ms
/// gap, the cancelled read has already eaten the frame header, and the next
/// read interprets payload as a header.
///
/// If this test ever fails because the frame arrives *intact*, `read_frame`
/// became cancel-safe upstream and the reader's invariant may be relaxed —
/// which is exactly when someone should be told.
#[tokio::test]
async fn cancelling_read_frame_in_a_select_arm_desynchronises_the_stream() {
    let (mut ws, writer) = split_frame_stream();
    let mut send_fn = noop_send();

    let mut ticks = 0u32;
    let outcome = common::within(10, "the desynchronised read", async {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(TIMER) => {
                    ticks += 1;
                    assert!(ticks < 20, "timer fired 20 times without a verdict");
                }
                result = ws.read_frame(&mut send_fn) => return result,
            }
        }
    })
    .await;

    assert!(
        ticks >= 1,
        "the timer must have cancelled at least one read"
    );
    match outcome {
        // The historical symptom: payload byte 0xAA parsed as a frame header.
        Err(e) => {
            let text = e.to_string();
            assert!(
                text.contains("Reserved bits are not zero") || text.contains("Invalid"),
                "unexpected framing error: {text}"
            );
        }
        // Any frame at all here is corruption: the real frame cannot survive
        // having had its header consumed by a dropped future.
        Ok(frame) => assert_ne!(
            frame.payload.len(),
            SPLIT_LEN,
            "read_frame appears to have become cancel-safe; \
             revisit the reader invariant in src/client/reader.rs"
        ),
    }

    writer.abort();
}

/// The production shape: `timeout` wrapping the whole read, expiry terminal.
///
/// With a 50 ms budget and a 200 ms gap the read must end in the timeout — and
/// crucially never in a half-read frame. The reader turns this into
/// `ReadOutcome::IdleTimeout` and drops the stream instead of reading on.
#[tokio::test]
async fn a_terminal_timeout_yields_no_frame_at_all() {
    let (mut ws, writer) = split_frame_stream();
    let mut send_fn = noop_send();

    let result = tokio::time::timeout(TIMER, ws.read_frame(&mut send_fn)).await;
    assert!(
        result.is_err(),
        "a 50ms budget cannot cover a 200ms gap: {:?}",
        result.map(|inner| inner.map(|frame| frame.payload.len()))
    );

    writer.abort();
}

/// The same split frame, read under a budget that covers the gap, arrives whole.
#[tokio::test]
async fn a_budget_that_covers_the_gap_reads_the_frame_whole() {
    let (mut ws, writer) = split_frame_stream();
    let mut send_fn = noop_send();

    let frame = common::within(10, "the reassembled frame", async {
        tokio::time::timeout(Duration::from_secs(5), ws.read_frame(&mut send_fn))
            .await
            .expect("must not time out")
            .expect("must not fail")
    })
    .await;

    assert_eq!(frame.opcode, OpCode::Binary);
    assert_eq!(frame.payload.len(), SPLIT_LEN);
    assert!(frame.payload.iter().all(|&byte| byte == FILL));

    writer.abort();
}

/// The regression through the real reader.
///
/// A 1000-byte type-3 payload is split across two TCP writes 1.5 s apart while
/// the client's *base* idle window is 1 s. The announced length widens the
/// window for that frame to 2 s (`keepalive::read_timeout`), so the reader is
/// entitled to wait — but only because it waits inside a single `read_frame`
/// call. Reintroduce a 1 s `select!` tick and the timer lands in the middle of
/// the gap, the header is lost, and the payload never reaches the handler.
#[tokio::test]
async fn a_payload_split_across_tcp_writes_reaches_the_handler_intact() {
    common::init_tracing();
    let fake = FakeMiniserver::start(FakeConfig::default()).await;
    let (handler, mut events) = RecordingHandler::new();

    let mut cfg = common::test_config(&fake);
    // Base window narrower than the write gap; the announced length is what
    // makes the wait legitimate.
    cfg.read_idle_timeout_secs = 1;
    cfg.keepalive_secs = 1;

    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");
    let session = fake.state.session(0).await;

    let uuid = common::uuid(0x5a);
    let icon = common::uuid(0x5b);
    // uuid + icon + length field = 36 bytes, and 964 needs no padding.
    let text = vec![b'x'; SPLIT_LEN - 36];
    let payload = common::text_payload(&[(uuid, icon, &text)]);
    assert_eq!(payload.len(), SPLIT_LEN);

    // One gap only: 600 bytes, 1.5 s, then the remaining 400. Two gaps would
    // exceed the widened window and legitimately trip the idle timeout.
    session.send_message_in_tcp_chunks(
        MessageType::TextStates as u8,
        &payload,
        SPLIT_LEN - FIRST_CHUNK,
        Duration::from_millis(1500),
    );

    let rec = common::wait_rec(&mut events, 15, |rec| matches!(rec, Rec::Text { .. })).await;
    assert_eq!(
        rec,
        Rec::Text {
            uuid,
            icon,
            text: text.clone(),
        }
    );

    let _ = common::within(15, "stop", client.stop()).await;
}
