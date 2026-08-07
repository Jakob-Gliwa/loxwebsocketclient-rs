//! Encrypted commands: correlation, pipelining, salt rotation, visu controls.

mod common;

use common::{FakeMiniserver, Rec, RecordingHandler, SaltPrefix, TEST_VISU_PASSWORD};
use loxwebsocket::crypto::session::SALT_MAX_USE_COUNT;
use loxwebsocket::{ConnState, Error, LoxClient};
use std::collections::HashSet;
use std::time::Duration;

/// Value of `LL.value` in a fake answer, as a string.
fn ll_value(payload: &[u8]) -> String {
    let text = String::from_utf8_lossy(payload);
    let at = text.find("\"value\":").expect("a value field");
    let rest = &text[at + 8..];
    let rest = rest.trim_start().trim_start_matches('"');
    let end = rest.find('"').expect("closing quote");
    rest[..end].to_string()
}

#[tokio::test]
async fn a_command_gets_its_own_answer_back() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, _events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");

    let payload = common::within(
        10,
        "the answer",
        client.send_command("jdev/sps/io/echo-me/1"),
    )
    .await
    .expect("send_command");
    assert_eq!(ll_value(&payload), "jdev/sps/io/echo-me/1");

    // The answer's `LL.control` echoes the *encrypted* command, which is how
    // the client correlates it. A mismatch would have been counted.
    assert_eq!(client.metrics().correlation_mismatches, 0);
    assert_eq!(client.metrics().unsolicited_responses, 0);

    let _ = common::within(15, "stop", client.stop()).await;
}

/// Pipelined commands are answered in order and each caller gets its own answer.
#[tokio::test]
async fn pipelined_commands_are_correlated_in_order() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, _events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");

    // All eight are polled concurrently, so they queue up in the writer before
    // the first answer comes back.
    let answers = common::within(15, "all pipelined answers", async {
        tokio::join!(
            client.send_command("jdev/sps/io/pipe0/on"),
            client.send_command("jdev/sps/io/pipe1/on"),
            client.send_command("jdev/sps/io/pipe2/on"),
            client.send_command("jdev/sps/io/pipe3/on"),
            client.send_command("jdev/sps/io/pipe4/on"),
            client.send_command("jdev/sps/io/pipe5/on"),
            client.send_command("jdev/sps/io/pipe6/on"),
            client.send_command("jdev/sps/io/pipe7/on"),
        )
    })
    .await;

    let answers = [
        answers.0, answers.1, answers.2, answers.3, answers.4, answers.5, answers.6, answers.7,
    ];
    for (i, answer) in answers.into_iter().enumerate() {
        let payload = answer.expect("send_command");
        assert_eq!(ll_value(&payload), format!("jdev/sps/io/pipe{i}/on"));
    }
    assert_eq!(client.metrics().correlation_mismatches, 0);

    let _ = common::within(15, "stop", client.stop()).await;
}

/// The concrete bug this guards: a fire-and-forget control's acknowledgement
/// must not complete a `send_command` that is waiting at the same time.
///
/// `send_control` registers its own internal waiter, so the queue stays
/// aligned; without it the control's answer would be handed to the pending
/// `send_command` and every later answer would be off by one.
#[tokio::test]
async fn a_control_ack_does_not_steal_a_concurrent_command_answer() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, _events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");

    // Interleave: control, command, control, command, …
    let controls = async {
        for i in 0..4 {
            client
                .send_control(&format!("ctrl{i}"), "on")
                .await
                .expect("send_control");
        }
    };
    let commands = async {
        let mut out = Vec::new();
        for i in 0..4 {
            let payload = client
                .send_command(&format!("jdev/sps/io/cmd{i}/off"))
                .await
                .expect("send_command");
            out.push(ll_value(&payload));
        }
        out
    };

    let (_, values) = common::within(20, "controls and commands", async {
        tokio::join!(controls, commands)
    })
    .await;

    let expected: Vec<String> = (0..4).map(|i| format!("jdev/sps/io/cmd{i}/off")).collect();
    assert_eq!(values, expected, "a control ack was handed to a command");
    assert_eq!(client.metrics().correlation_mismatches, 0);

    // Both kinds reached the Miniserver.
    let labels: Vec<String> = fake
        .state
        .commands()
        .into_iter()
        .map(|record| record.cmd)
        .collect();
    for i in 0..4 {
        assert!(
            labels.iter().any(|cmd| cmd.contains(&format!("ctrl{i}"))),
            "control {i} missing from {labels:?}"
        );
    }

    let _ = common::within(15, "stop", client.stop()).await;
}

/// The concrete bug this guards: only a running session's writer task drains
/// the command channel, so between two sessions nobody does. Once the channel
/// filled — 32 controls by default, which one fanned-out inbound message
/// reaches easily — `send_control().await` parked until the Miniserver came
/// back, up to `long_backoff_secs` later.
///
/// The queue here holds two, so a burst of eight would have wedged the caller
/// on the third.
#[tokio::test]
async fn a_control_is_refused_between_sessions_instead_of_parking_the_caller() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    // Long enough that the whole burst below happens inside the reconnect wait.
    cfg.connect_delay_secs = 60;
    cfg.command_channel_depth = 2;
    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");

    fake.state.session(0).await.close(1000);
    common::wait_rec(&mut events, 15, |rec| {
        matches!(rec, Rec::ConnectionClosed(_))
    })
    .await;
    assert_eq!(client.state(), ConnState::Reconnecting);

    for i in 0..8 {
        let sent = tokio::time::timeout(
            Duration::from_millis(50),
            client.send_control(&format!("ctrl{i}"), "on"),
        )
        .await
        .unwrap_or_else(|_| panic!("send_control {i} parked waiting for the reconnect"));
        assert!(matches!(sent, Err(Error::NotConnected)), "{sent:?}");
    }
    assert!(matches!(
        client.try_send_control("ctrl8", "on"),
        Err(Error::NotConnected)
    ));
    assert!(matches!(
        common::within(
            1,
            "the visu control",
            client.send_visu_control("u", "on", "pw")
        )
        .await,
        Err(Error::NotConnected)
    ));
    assert!(!client.live());
    assert_eq!(client.metrics().controls_rejected_offline, 10);
    assert_eq!(client.metrics().controls_rejected_backpressure, 0);
    // Nothing was queued, so the reconnect does not replay a stale burst.
    assert_eq!(fake.state.session_count(), 1);

    let _ = common::within(15, "stop", client.stop()).await;
}

/// The non-blocking form is the whole point of `try_send_control`: on a live
/// connection it either takes the value or says the writer is behind, and it
/// never awaits either way.
#[tokio::test]
async fn try_send_control_reports_backpressure_rather_than_waiting() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, _events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    cfg.command_channel_depth = 1;
    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");

    // Synchronous, so the writer never gets a chance to drain between calls:
    // with a queue of one, the burst has to be refused before it is exhausted.
    let mut accepted = 0usize;
    let mut refused = 0usize;
    for i in 0..64 {
        match client.try_send_control(&format!("burst{i}"), "on") {
            Ok(()) => accepted += 1,
            Err(Error::Backpressure) => refused += 1,
            Err(e) => panic!("unexpected refusal: {e}"),
        }
    }
    assert!(accepted > 0, "the healthy connection took nothing");
    assert!(refused > 0, "a queue of one absorbed 64 controls");
    assert_eq!(accepted + refused, 64);
    assert_eq!(
        client.metrics().controls_rejected_backpressure,
        refused as u64
    );
    assert_eq!(client.metrics().controls_rejected_offline, 0);

    // What was accepted still reaches the Miniserver.
    fake.state
        .wait_until(10, "the accepted controls", move |log| {
            log.iter()
                .filter_map(common::Entry::as_command)
                .filter(|record| record.cmd.contains("/burst"))
                .count()
                >= accepted
        })
        .await;

    let _ = common::within(15, "stop", client.stop()).await;
}

/// After [`SALT_MAX_USE_COUNT`] uses the client rotates, and the `nextSalt`
/// prefix has to name the salt the previous command actually used — a broken
/// chain makes the Miniserver answer `401` for every later command.
#[tokio::test]
async fn the_salt_rotates_with_an_unbroken_chain() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, _events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");

    // Comfortably past the rotation point, including the handshake's own
    // commands: rotation is per session, not per caller.
    for i in 0..(SALT_MAX_USE_COUNT + 4) {
        let payload = common::within(
            10,
            "a salted answer",
            client.send_command(&format!("jdev/sps/io/salt{i}/1")),
        )
        .await
        .expect("send_command");
        assert_eq!(ll_value(&payload), format!("jdev/sps/io/salt{i}/1"));
    }

    let commands = fake.state.session_commands(0);
    let mut rotations = 0usize;
    let mut active: Option<String> = None;
    let mut seen_salts = HashSet::new();

    for record in &commands {
        match record.salt_prefix() {
            SaltPrefix::Same(salt) => {
                if let Some(active) = &active {
                    assert_eq!(active, &salt, "salt changed without a nextSalt: {record:?}");
                } else {
                    active = Some(salt.clone());
                }
                seen_salts.insert(salt);
            }
            SaltPrefix::Rotated { prev, next } => {
                assert_eq!(
                    active.as_deref(),
                    Some(prev.as_str()),
                    "nextSalt names a salt that was never in use: {record:?}"
                );
                assert_ne!(prev, next, "rotation must produce a different salt");
                rotations += 1;
                active = Some(next.clone());
                seen_salts.insert(next);
            }
            SaltPrefix::None => panic!("command without a salt prefix: {record:?}"),
        }
    }

    assert_eq!(
        rotations, 1,
        "expected exactly one rotation in {commands:?}"
    );
    assert_eq!(seen_salts.len(), 2);
    // Every command was accepted, so the fake agreed with the chain.
    assert!(commands.iter().all(|record| record.code == "200"));

    let _ = common::within(15, "stop", client.stop()).await;
}

/// A visualization-secured control fetches `getvisusalt` first and then sends
/// `jdev/sps/ios/{hash}/{uuid}/{value}` — the fake verifies the hash itself.
#[tokio::test]
async fn a_visu_control_is_hashed_with_the_visualization_password() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, _events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");

    client
        .send_visu_control(
            "0f869a64-0200-0e0d-ffff112233445566",
            "on",
            TEST_VISU_PASSWORD,
        )
        .await
        .expect("send_visu_control");

    fake.state
        .wait_until(10, "the secured control", |log| {
            log.iter()
                .filter_map(common::Entry::as_command)
                .any(|record| record.label == "jdev/sps/ios")
        })
        .await;

    let secured = fake
        .state
        .commands()
        .into_iter()
        .find(|record| record.label == "jdev/sps/ios")
        .expect("the secured control");
    assert_eq!(
        secured.code, "200",
        "the fake rejected the visu hash: {secured:?}"
    );
    assert!(
        secured
            .cmd
            .ends_with("/0f869a64-0200-0e0d-ffff112233445566/on")
    );
    assert_eq!(fake.state.count("jdev/sys/getvisusalt"), 1);

    let _ = common::within(15, "stop", client.stop()).await;
}

/// A wrong visualization password must be rejected by the Miniserver, not
/// silently accepted by the client.
#[tokio::test]
async fn a_wrong_visu_password_is_refused_by_the_miniserver() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, _events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");

    client
        .send_visu_control("uuid-1", "on", "definitely-wrong")
        .await
        .expect("queueing succeeds; the answer decides");

    fake.state
        .wait_until(10, "the rejected control", |log| {
            log.iter()
                .filter_map(common::Entry::as_command)
                .any(|record| record.label == "jdev/sps/ios")
        })
        .await;

    let secured = fake
        .state
        .commands()
        .into_iter()
        .find(|record| record.label == "jdev/sps/ios")
        .expect("the secured control");
    // The document specifies `500` for a wrong visualization password.
    assert_eq!(secured.code, "500");

    let _ = common::within(15, "stop", client.stop()).await;
}

/// A refusal is still an answer: it has to reach its caller rather than sit in
/// the pending queue until the command timeout.
#[tokio::test]
async fn an_error_answer_is_delivered_to_its_caller() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, _events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");

    // A key request for a user the Miniserver does not know: answered, but 401.
    let payload = common::within(
        10,
        "the error answer",
        client.send_command("jdev/sys/getkey2/nobody"),
    )
    .await
    .expect("send_command resolves");
    let text = String::from_utf8_lossy(&payload);
    assert!(text.contains(r#""Code":"401""#), "{text}");
    assert_eq!(client.metrics().correlation_mismatches, 0);

    let _ = common::within(15, "stop", client.stop()).await;
}

/// Events keep flowing while commands are in flight; the reader multiplexes
/// type-0 answers and event tables on the same stream.
#[tokio::test]
async fn events_and_command_answers_share_the_stream() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");
    let session = fake.state.session(0).await;

    let uuid = common::uuid(0x3c);
    let pump = async {
        for i in 0..10 {
            session.send_message(
                loxwebsocket::MessageType::ValueStates as u8,
                &common::value_payload(&[(uuid, f64::from(i))]),
            );
            session.flushed().await;
        }
    };
    let ask = async {
        let mut values = Vec::new();
        for i in 0..5 {
            let payload = client
                .send_command(&format!("jdev/sps/io/mix{i}/1"))
                .await
                .expect("send_command");
            values.push(ll_value(&payload));
        }
        values
    };

    let (_, values) =
        common::within(20, "events plus answers", async { tokio::join!(pump, ask) }).await;
    assert_eq!(
        values,
        (0..5)
            .map(|i| format!("jdev/sps/io/mix{i}/1"))
            .collect::<Vec<_>>()
    );

    let seen =
        common::collect_recs(&mut events, 15, 10, |rec| matches!(rec, Rec::Value { .. })).await;
    assert_eq!(seen.len(), 10);
    assert_eq!(client.metrics().correlation_mismatches, 0);

    let _ = common::within(15, "stop", client.stop()).await;
}
