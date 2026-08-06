//! The reader's framing state machine and every event type, driven through a
//! real WebSocket session.
//!
//! Loxone alternates an 8-byte header frame with the payload frame it
//! describes (document V17.0, "Communicating with the Miniserver"). The fake
//! puts those frames on the wire byte for byte, including the awkward cases:
//! estimated headers, zero-length headers, out-of-service, and payloads
//! fragmented over several TCP writes the way a large initial event table
//! arrives.

mod common;

use common::{FakeMiniserver, Rec, RecordingHandler};
use loxwebsocket::proto::{DaytimerEntry, WeatherEntry};
use loxwebsocket::{ConnState, LoxClient, MessageType};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;

/// Connected client plus the fake's push handle for its session.
async fn connected(
    fake: &FakeMiniserver,
) -> (
    LoxClient<RecordingHandler>,
    UnboundedReceiver<Rec>,
    common::SessionHandle,
) {
    let (handler, events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(fake), handler),
    )
    .await
    .expect("connect");
    let session = fake.state.session(0).await;
    (client, events, session)
}

#[tokio::test]
async fn value_states_arrive_record_by_record() {
    let fake = FakeMiniserver::start_default().await;
    let (client, mut events, session) = connected(&fake).await;

    let records = [
        (common::uuid(1), 0.0),
        (common::uuid(2), -273.15),
        (common::uuid(3), f64::MAX),
        (common::uuid(4), 21.5),
    ];
    session.send_message(
        MessageType::ValueStates as u8,
        &common::value_payload(&records),
    );

    let seen = common::collect_recs(&mut events, 10, records.len(), |rec| {
        matches!(rec, Rec::Value { .. })
    })
    .await;
    let expected: Vec<Rec> = records
        .iter()
        .map(|&(uuid, value)| Rec::Value { uuid, value })
        .collect();
    assert_eq!(seen, expected);

    let _ = common::within(15, "stop", client.stop()).await;
}

#[tokio::test]
async fn text_states_survive_every_alignment_remainder() {
    let fake = FakeMiniserver::start_default().await;
    let (client, mut events, session) = connected(&fake).await;

    // The record length is padded to a multiple of four, so a text of length
    // 4n, 4n+1, 4n+2 and 4n+3 each exercise a different amount of padding. If
    // the walker got the rounding wrong, every record after the first would
    // start at the wrong offset.
    let texts: Vec<Vec<u8>> = (0..4).map(|i| vec![b'a' + i as u8; 4 + i]).collect();
    let records: Vec<(_, _, &[u8])> = texts
        .iter()
        .enumerate()
        .map(|(i, text)| {
            (
                common::uuid(0x10 + i as u8),
                common::uuid(0x20 + i as u8),
                text.as_slice(),
            )
        })
        .collect();
    session.send_message(
        MessageType::TextStates as u8,
        &common::text_payload(&records),
    );

    let seen = common::collect_recs(&mut events, 10, records.len(), |rec| {
        matches!(rec, Rec::Text { .. })
    })
    .await;
    let expected: Vec<Rec> = records
        .iter()
        .map(|&(uuid, icon, text)| Rec::Text {
            uuid,
            icon,
            text: text.to_vec(),
        })
        .collect();
    assert_eq!(seen, expected);

    let _ = common::within(15, "stop", client.stop()).await;
}

#[tokio::test]
async fn an_empty_text_still_produces_a_record() {
    let fake = FakeMiniserver::start_default().await;
    let (client, mut events, session) = connected(&fake).await;

    let uuid = common::uuid(0x77);
    let icon = common::uuid(0x88);
    session.send_message(
        MessageType::TextStates as u8,
        &common::text_payload(&[(uuid, icon, b""), (uuid, icon, b"after")]),
    );

    let seen =
        common::collect_recs(&mut events, 10, 2, |rec| matches!(rec, Rec::Text { .. })).await;
    assert_eq!(
        seen,
        vec![
            Rec::Text {
                uuid,
                icon,
                text: Vec::new()
            },
            Rec::Text {
                uuid,
                icon,
                text: b"after".to_vec()
            },
        ]
    );

    let _ = common::within(15, "stop", client.stop()).await;
}

#[tokio::test]
async fn daytimer_tables_carry_all_their_entries() {
    let fake = FakeMiniserver::start_default().await;
    let (client, mut events, session) = connected(&fake).await;

    let entries: Vec<DaytimerEntry> = (0..3)
        .map(|i| DaytimerEntry::new(i, 60 * i, 60 * i + 30, i % 2, i as f64 * 1.5))
        .collect();
    let uuid_a = common::uuid(0xa1);
    let uuid_b = common::uuid(0xb2);
    // Two tables back to back, the second one empty — the walker has to move on
    // by the header size alone.
    session.send_message(
        MessageType::DaytimerStates as u8,
        &common::daytimer_payload(&[(uuid_a, 19.5, entries.clone()), (uuid_b, 0.0, Vec::new())]),
    );

    let seen = common::collect_recs(&mut events, 10, 2, |rec| {
        matches!(rec, Rec::Daytimer { .. })
    })
    .await;
    assert_eq!(
        seen,
        vec![
            Rec::Daytimer {
                uuid: uuid_a,
                default_value: 19.5,
                entries: entries
                    .iter()
                    .map(|entry| (
                        entry.mode(),
                        entry.from_minutes(),
                        entry.to_minutes(),
                        entry.need_activate(),
                        entry.value()
                    ))
                    .collect(),
            },
            Rec::Daytimer {
                uuid: uuid_b,
                default_value: 0.0,
                entries: Vec::new(),
            },
        ]
    );

    let _ = common::within(15, "stop", client.stop()).await;
}

#[tokio::test]
async fn weather_tables_carry_all_their_entries() {
    let fake = FakeMiniserver::start_default().await;
    let (client, mut events, session) = connected(&fake).await;

    let entries: Vec<WeatherEntry> = (0..2)
        .map(|i| {
            WeatherEntry::new(
                1_000 + i,
                7,
                180,
                420,
                55,
                18.5 + f64::from(i),
                17.0,
                12.0,
                0.4,
                3.2,
                1013.0,
            )
        })
        .collect();
    let uuid = common::uuid(0xc3);
    session.send_message(
        MessageType::WeatherStates as u8,
        &common::weather_payload(&[(uuid, 42, entries.clone())]),
    );

    let rec = common::wait_rec(&mut events, 10, |rec| matches!(rec, Rec::Weather { .. })).await;
    assert_eq!(
        rec,
        Rec::Weather {
            uuid,
            last_update: 42,
            entries: entries
                .iter()
                .map(|entry| (entry.timestamp(), entry.weather_type(), entry.temperature()))
                .collect(),
        }
    );

    let _ = common::within(15, "stop", client.stop()).await;
}

#[tokio::test]
async fn a_binary_file_message_is_handed_over_verbatim() {
    let fake = FakeMiniserver::start_default().await;
    let (client, mut events, session) = connected(&fake).await;

    let blob: Vec<u8> = (0..=255u8).cycle().take(3000).collect();
    session.send_message(MessageType::BinaryFile as u8, &blob);

    let rec = common::wait_rec(&mut events, 10, |rec| matches!(rec, Rec::Binary(_))).await;
    assert_eq!(rec, Rec::Binary(blob));

    let _ = common::within(15, "stop", client.stop()).await;
}

#[tokio::test]
async fn an_estimated_header_is_skipped_and_the_exact_one_is_used() {
    let fake = FakeMiniserver::start_default().await;
    let (client, mut events, session) = connected(&fake).await;

    let records = [(common::uuid(9), 1.25)];
    let payload = common::value_payload(&records);
    // The estimate is deliberately wrong; only the exact header may decide.
    session.send_estimated_then_message(MessageType::ValueStates as u8, 4096, &payload);

    let rec = common::wait_rec(&mut events, 10, |rec| matches!(rec, Rec::Value { .. })).await;
    assert_eq!(
        rec,
        Rec::Value {
            uuid: common::uuid(9),
            value: 1.25
        }
    );

    let _ = common::within(15, "stop", client.stop()).await;
}

#[tokio::test]
async fn a_zero_length_header_is_dispatched_without_a_payload_frame() {
    let fake = FakeMiniserver::start_default().await;
    let (client, mut events, session) = connected(&fake).await;

    // A keepalive answer is exactly this: a header with len == 0 and nothing
    // behind it. If the reader waited for a payload frame it would swallow the
    // following message's header.
    session.send_header(MessageType::Keepalive as u8, 0, 0);
    session.send_message(
        MessageType::ValueStates as u8,
        &common::value_payload(&[(common::uuid(5), 5.0)]),
    );

    assert_eq!(
        common::wait_rec(&mut events, 10, |rec| matches!(
            rec,
            Rec::Keepalive | Rec::Value { .. }
        ))
        .await,
        Rec::Keepalive
    );
    assert_eq!(
        common::wait_rec(&mut events, 10, |rec| matches!(rec, Rec::Value { .. })).await,
        Rec::Value {
            uuid: common::uuid(5),
            value: 5.0
        }
    );

    let _ = common::within(15, "stop", client.stop()).await;
}

#[tokio::test]
async fn out_of_service_ends_the_session_without_a_payload_frame() {
    let fake = FakeMiniserver::start_default().await;
    let mut cfg = common::test_config(&fake);
    // Keep the reconnect from racing the assertion.
    cfg.connect_delay_secs = 30;
    let (handler, mut events) = RecordingHandler::new();
    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");
    let session = fake.state.session(0).await;

    session.send_out_of_service();

    // Identifier 5 is reported as 1012 ("service restart"), the closest
    // WebSocket code, and the client goes back to reconnecting.
    let rec = common::wait_rec(&mut events, 10, |rec| {
        matches!(rec, Rec::ConnectionClosed(_))
    })
    .await;
    assert_eq!(rec, Rec::ConnectionClosed(Some(1012)));
    assert_ne!(client.state(), ConnState::Connected);

    let _ = common::within(15, "stop", client.stop()).await;
}

#[tokio::test]
async fn a_stray_payload_sized_frame_does_not_derail_the_state_machine() {
    let fake = FakeMiniserver::start_default().await;
    let (client, mut events, session) = connected(&fake).await;

    // 24 bytes where a header was expected: too long to be a header, so it is
    // dropped with a warning. The next header/payload pair must still work.
    session.send_raw(
        vec![common::ws::frame(common::ws::OP_BINARY, &[0xEE; 24])],
        Duration::ZERO,
    );
    session.send_message(
        MessageType::ValueStates as u8,
        &common::value_payload(&[(common::uuid(6), 6.5)]),
    );

    let rec = common::wait_rec(&mut events, 10, |rec| matches!(rec, Rec::Value { .. })).await;
    assert_eq!(
        rec,
        Rec::Value {
            uuid: common::uuid(6),
            value: 6.5
        }
    );

    let _ = common::within(15, "stop", client.stop()).await;
}

/// The realistic large-table case: a payload far bigger than one TCP segment,
/// delivered in many small writes.
#[tokio::test]
async fn a_large_event_table_fragmented_over_many_tcp_writes_arrives_complete() {
    let fake = FakeMiniserver::start_default().await;
    let (client, mut events, session) = connected(&fake).await;

    const RECORDS: usize = 5_000;
    let records: Vec<_> = (0..RECORDS)
        .map(|i| (common::uuid((i % 251) as u8), i as f64))
        .collect();
    let payload = common::value_payload(&records);
    assert_eq!(payload.len(), RECORDS * 24);

    session.send_message_in_tcp_chunks(
        MessageType::ValueStates as u8,
        &payload,
        1_500,
        Duration::from_millis(1),
    );

    let seen = common::collect_recs(&mut events, 20, RECORDS, |rec| {
        matches!(rec, Rec::Value { .. })
    })
    .await;
    for (index, rec) in seen.iter().enumerate() {
        assert_eq!(
            rec,
            &Rec::Value {
                uuid: common::uuid((index % 251) as u8),
                value: index as f64,
            },
            "record {index}"
        );
    }

    let _ = common::within(15, "stop", client.stop()).await;
}

/// A type-0 message with no waiting command is an unsolicited push and must
/// reach `on_json`, not a pending slot.
#[tokio::test]
async fn an_unsolicited_text_message_is_reported_as_json() {
    let fake = FakeMiniserver::start_default().await;
    let (client, mut events, session) = connected(&fake).await;

    let json = br#"{"LL":{"control":"status","value":"1","Code":"200"}}"#;
    session.send_message_with_opcode(MessageType::Text as u8, json, common::ws::OP_TEXT);

    let rec = common::wait_rec(&mut events, 10, |rec| matches!(rec, Rec::Json(_))).await;
    assert_eq!(rec, Rec::Json(json.to_vec()));
    assert_eq!(client.metrics().unsolicited_responses, 1);

    let _ = common::within(15, "stop", client.stop()).await;
}
