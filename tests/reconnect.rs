//! Reconnect behaviour: token retention, close-code policy, salt reset, and the
//! shutdown handshake.

mod common;

use common::{Entry, FakeConfig, FakeMiniserver, Rec, RecordingHandler, SaltPrefix};
use loxwebsocket::{ConnState, LoxClient};
use std::time::Duration;

/// Wait until the fake has seen `count` sessions open.
async fn wait_sessions(fake: &FakeMiniserver, count: usize) {
    fake.state
        .wait_until(20, "another session", move |log| {
            log.iter()
                .filter(|entry| matches!(entry, Entry::SessionOpened { .. }))
                .count()
                >= count
        })
        .await;
}

/// The bug this pins: both disconnect branches used to call `token.clear()`, so
/// every reconnect bought a fresh token and left the old one to rot in the
/// Miniserver's storage (it keeps a few dozen at most).
///
/// After a server-side close the client must re-authenticate with the token it
/// already has — `getkey` + `authwithtoken`, never a second `getjwt`.
#[tokio::test]
async fn a_reconnect_reuses_the_token_instead_of_asking_for_a_new_one() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");

    assert_eq!(fake.state.count("jdev/sys/getjwt"), 1);
    let session = fake.state.session(0).await;
    session.close(1000);

    assert_eq!(
        common::wait_rec(&mut events, 15, |rec| matches!(
            rec,
            Rec::ConnectionClosed(_)
        ))
        .await,
        Rec::ConnectionClosed(Some(1000))
    );
    common::wait_rec(&mut events, 20, |rec| matches!(rec, Rec::Reconnected)).await;
    wait_sessions(&fake, 2).await;

    assert_eq!(
        fake.state.count("jdev/sys/getjwt"),
        1,
        "the reconnect asked for a second token: {:#?}",
        fake.state.commands()
    );
    assert_eq!(fake.state.tokens_issued(), 1);

    // The second session authenticated with the token it kept.
    let second: Vec<String> = fake
        .state
        .session_commands(1)
        .into_iter()
        .map(|record| record.label)
        .collect();
    assert!(
        second.iter().any(|label| label == "authwithtoken"),
        "session 1 commands: {second:?}"
    );
    assert_eq!(client.state(), ConnState::Connected);

    let _ = common::within(15, "stop", client.stop()).await;
}

/// A reconnect starts a new AES session, so the salt has to start over. Sending
/// `nextSalt/{oldSalt}/…` to a Miniserver that never saw `oldSalt` earns a
/// spurious `401` for every command of the new session.
#[tokio::test]
async fn a_reconnect_restarts_the_salt_chain() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");

    // Get a salt established, then drop the session under the client.
    common::within(10, "a command", client.send_command("jdev/sps/io/before/1"))
        .await
        .expect("send_command");
    let first_salt = match fake.state.session_commands(0)[0].salt_prefix() {
        SaltPrefix::Same(salt) => salt,
        other => panic!("unexpected first prefix: {other:?}"),
    };

    fake.state.session(0).await.close(1000);
    common::wait_rec(&mut events, 20, |rec| matches!(rec, Rec::Reconnected)).await;
    wait_sessions(&fake, 2).await;

    common::within(10, "a command", client.send_command("jdev/sps/io/after/1"))
        .await
        .expect("send_command");

    let second = fake.state.session_commands(1);
    let second_salt = match second[0].salt_prefix() {
        SaltPrefix::Same(salt) => salt,
        other => panic!("session 1 must start a fresh salt chain, got {other:?}"),
    };
    assert_ne!(first_salt, second_salt);
    assert!(
        second.iter().all(|record| record.code != "401"),
        "{second:#?}"
    );

    let _ = common::within(15, "stop", client.stop()).await;
}

/// 4004/4005 mean the user behind the token changed, so the token is dead and
/// the client has to acquire a new one.
#[tokio::test]
async fn a_user_change_close_code_discards_the_token() {
    for code in [4004u16, 4005] {
        let fake = FakeMiniserver::start_default().await;
        let (handler, mut events) = RecordingHandler::new();
        let client = common::within(
            20,
            "connect",
            LoxClient::connect(common::test_config(&fake), handler),
        )
        .await
        .expect("connect");

        fake.state.session(0).await.close(code);
        common::wait_rec(&mut events, 20, |rec| matches!(rec, Rec::Reconnected)).await;
        wait_sessions(&fake, 2).await;

        fake.state
            .wait_until(15, "a second token request", |log| {
                log.iter()
                    .filter_map(Entry::as_command)
                    .filter(|record| record.label == "jdev/sys/getjwt")
                    .count()
                    >= 2
            })
            .await;
        assert_eq!(fake.state.tokens_issued(), 2, "close code {code}");

        let _ = common::within(15, "stop", client.stop()).await;
    }
}

/// 4006 says the user this client authenticates as has been disabled. No
/// reconnect can lift that, so the supervisor has to report `Closed` rather
/// than knock on the Miniserver every `connect_delay_secs` until the process
/// ends.
#[tokio::test]
async fn a_disabled_user_ends_the_client_instead_of_reconnecting() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    cfg.connect_delay_secs = 0;
    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");

    fake.state.session(0).await.close(4006);
    common::wait_rec(&mut events, 15, |rec| matches!(rec, Rec::Closed)).await;

    assert_eq!(client.state(), ConnState::Closed);
    // With a zero connect delay a retrying supervisor would have opened the
    // next session long before `Closed` could arrive.
    assert_eq!(fake.state.session_count(), 1);

    let _ = common::within(15, "stop", client.stop()).await;
}

/// 4003/4007/4008 describe conditions that need minutes; the client must wait
/// the long backoff instead of hammering the Miniserver.
#[tokio::test]
async fn a_structural_refusal_waits_the_long_backoff() {
    for code in [4003u16, 4007, 4008] {
        let fake = FakeMiniserver::start_default().await;
        let (handler, mut events) = RecordingHandler::new();
        let mut cfg = common::test_config(&fake);
        cfg.connect_delay_secs = 0;
        cfg.long_backoff_secs = 2;
        let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
            .await
            .expect("connect");

        fake.state.session(0).await.close(code);
        common::wait_rec(&mut events, 15, |rec| {
            matches!(rec, Rec::ConnectionClosed(_))
        })
        .await;
        wait_sessions(&fake, 2).await;

        let first = fake.state.session_opened_at(0).expect("session 0");
        let second = fake.state.session_opened_at(1).expect("session 1");
        let gap = second.duration_since(first);
        assert!(
            gap >= Duration::from_millis(1_800),
            "close code {code} reconnected after {gap:?}, expected the long backoff"
        );

        let _ = common::within(15, "stop", client.stop()).await;
    }
}

/// A normal close code uses the short delay — the counterpart to the test above,
/// so a policy that returned `Long` for everything would not pass both.
#[tokio::test]
async fn a_normal_close_reconnects_without_the_long_backoff() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    cfg.connect_delay_secs = 0;
    cfg.long_backoff_secs = 30;
    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");

    fake.state.session(0).await.close(1012);
    common::wait_rec(&mut events, 20, |rec| matches!(rec, Rec::Reconnected)).await;
    wait_sessions(&fake, 2).await;

    let gap = fake
        .state
        .session_opened_at(1)
        .expect("session 1")
        .duration_since(fake.state.session_opened_at(0).expect("session 0"));
    assert!(gap < Duration::from_secs(10), "reconnected after {gap:?}");

    let _ = common::within(15, "stop", client.stop()).await;
}

/// `stop()` releases the token on the Miniserver before it closes the socket;
/// dropping it the other way round loses the `killtoken`.
#[tokio::test]
async fn stop_kills_the_token_before_the_close_frame() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, _events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");

    common::within(15, "stop", client.stop())
        .await
        .expect("stop");

    fake.state
        .wait_until(10, "killtoken and the close frame", |log| {
            log.iter().any(|entry| {
                matches!(entry, Entry::Command(record) if record.label == "jdev/sys/killtoken")
            })
        })
        .await;

    let log = fake.state.log();
    let kill_at = log
        .iter()
        .position(
            |entry| matches!(entry, Entry::Command(record) if record.label == "jdev/sys/killtoken"),
        )
        .expect("a killtoken");
    let killed = log
        .iter()
        .filter_map(Entry::as_command)
        .find(|record| record.label == "jdev/sys/killtoken")
        .expect("the killtoken record");
    assert_eq!(killed.code, "200", "the fake rejected the killtoken hash");
    assert_eq!(fake.state.killed_tokens().len(), 1);

    if let Some(close_at) = log
        .iter()
        .position(|entry| matches!(entry, Entry::ClientClose { .. }))
    {
        assert!(
            kill_at < close_at,
            "killtoken must precede the close frame: {log:#?}"
        );
    }
    // No reconnect was attempted after the deliberate stop.
    assert_eq!(fake.state.session_count(), 1);
}

/// Dropping the client used to leak the supervisor: it keeps its own clone of
/// the command sender for the token refresher, so the façade's copy going away
/// never closed the channel and the task reconnected until the process ended.
#[tokio::test]
async fn dropping_the_client_shuts_the_io_task_down() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");

    drop(client);

    // `Closed` is only emitted once the supervisor returns, so seeing it is
    // proof the task ended rather than went round again.
    common::wait_rec(&mut events, 20, |rec| matches!(rec, Rec::Closed)).await;
    assert_eq!(fake.state.session_count(), 1);
    // The shutdown is the graceful one, not an abort: the token is released.
    assert_eq!(fake.state.killed_tokens().len(), 1);
}

/// An `authwithtoken` refused with `901` means the Miniserver is out of
/// connection slots, not that the token is bad. The client used to treat it as a
/// rejection and ask for a replacement over the very connection just refused.
#[tokio::test]
async fn the_connection_limit_does_not_cost_the_token() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    cfg.connect_delay_secs = 0;
    cfg.long_backoff_secs = 1;
    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");
    assert_eq!(fake.state.tokens_issued(), 1);

    fake.state.set_token_refusal(901);
    fake.state.session(0).await.close(1006);
    fake.state
        .wait_until(20, "an authwithtoken refused with 901", |log| {
            log.iter()
                .filter_map(Entry::as_command)
                .any(|record| record.label == "authwithtoken" && record.code == "901")
        })
        .await;
    fake.state.set_token_refusal(0);

    common::wait_rec(&mut events, 25, |rec| matches!(rec, Rec::Reconnected)).await;
    assert_eq!(
        fake.state.tokens_issued(),
        1,
        "the connection limit must not have cost the token"
    );

    let _ = common::within(15, "stop", client.stop()).await;
}

/// With `max_reconnect_attempts` the client gives up instead of retrying
/// forever, and reports `Closed`.
#[tokio::test]
async fn reconnect_attempts_are_capped() {
    let fake = FakeMiniserver::start(FakeConfig::default()).await;
    let (handler, mut events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    cfg.max_reconnect_attempts = 1;
    cfg.connect_delay_secs = 0;
    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");

    // Two closes: the first is retried, the second exhausts the budget.
    fake.state.session(0).await.close(1000);
    common::wait_rec(&mut events, 20, |rec| matches!(rec, Rec::Reconnected)).await;
    wait_sessions(&fake, 2).await;
    fake.state.session(1).await.close(1000);

    common::wait_rec(&mut events, 20, |rec| matches!(rec, Rec::Closed)).await;
    assert_eq!(client.state(), ConnState::Closed);
    assert_eq!(fake.state.session_count(), 2);

    let _ = common::within(15, "stop", client.stop()).await;
}

/// The same fallback, for the code a restarting Miniserver actually sends.
///
/// Observed after a `1012` close: the refusal came back `400`, which was not in
/// the "token is dead" set, so the session failed with the token still in
/// memory. Every reconnect then re-presented it and got the same `400` — the
/// client never reached the `getjwt` that would have healed it, and only a
/// process restart broke the loop.
#[tokio::test]
async fn a_restart_refusal_does_not_become_a_reconnect_loop() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    cfg.connect_delay_secs = 0;
    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");
    assert_eq!(fake.state.tokens_issued(), 1);

    // What the Miniserver does on the way back up: refuse the stored token with
    // 400 rather than 401, then start accepting again.
    fake.state.set_authwithtoken_refusal(400);
    fake.state.session(0).await.close(1012);
    fake.state
        .wait_until(25, "an authwithtoken refused with 400", |log| {
            log.iter()
                .filter_map(Entry::as_command)
                .any(|record| record.label == "authwithtoken" && record.code == "400")
        })
        .await;
    fake.state.set_authwithtoken_refusal(0);

    // Healing without the process restart: a second `getjwt` over a live session.
    common::wait_rec(&mut events, 30, |rec| matches!(rec, Rec::Reconnected)).await;
    fake.state
        .wait_until(20, "a replacement token", |log| {
            log.iter()
                .filter_map(Entry::as_command)
                .filter(|record| record.label == "jdev/sys/getjwt")
                .count()
                >= 2
        })
        .await;
    assert_eq!(client.state(), ConnState::Connected);

    let _ = common::within(15, "stop", client.stop()).await;
}

/// The reconnect must not send a `checktoken` before the `authwithtoken`.
///
/// This is the bug the reported incident actually was. The handshake used to
/// pre-flight the stored token with `checktoken`, which the protocol document
/// does not list in the authentication flow at all — and real firmware answers
/// it with `400 Bad request` on a connection that has not authenticated yet.
/// So every reconnect that had a token asked a question the Miniserver refuses
/// to answer, took the refusal for a verdict on the token, and failed the
/// session with the token still in memory. The first connect of a process was
/// fine (no token, straight to `getjwt`); every reconnect after it was wedged.
///
/// The fake refuses `checktoken` exactly the way the real one does, so the only
/// way to pass is not to ask.
#[tokio::test]
async fn a_reconnect_does_not_pre_flight_the_token_with_checktoken() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let mut cfg = common::test_config(&fake);
    cfg.connect_delay_secs = 0;
    let client = common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect");
    assert_eq!(fake.state.tokens_issued(), 1);

    fake.state.set_checktoken_refusal(400);
    fake.state.session(0).await.close(1012);
    common::wait_rec(&mut events, 30, |rec| matches!(rec, Rec::Reconnected)).await;
    wait_sessions(&fake, 2).await;

    assert_eq!(
        fake.state.count("jdev/sys/checktoken"),
        0,
        "the handshake asked a question the Miniserver refuses pre-auth: {:#?}",
        fake.state.commands()
    );
    // The token survived, so no replacement was needed.
    assert_eq!(fake.state.tokens_issued(), 1);
    assert_eq!(fake.state.count("jdev/sys/getjwt"), 1);
    assert_eq!(client.state(), ConnState::Connected);

    let _ = common::within(15, "stop", client.stop()).await;
}

/// A Miniserver that is still booting accepts the socket but refuses to install
/// a session key. That failure has nothing to do with the token, so the only
/// thing the client owes the operator is an error that names the step — the
/// incident it was mistaken for cost an evening of looking at the token path.
#[tokio::test]
async fn a_refused_keyexchange_names_the_step_it_failed_at() {
    let fake = FakeMiniserver::start(FakeConfig {
        keyexchange_refusal: Some(400),
        ..FakeConfig::default()
    })
    .await;
    let (handler, _events) = RecordingHandler::new();

    let error = common::within(
        20,
        "the refused connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect_err("connect must fail");

    let rendered = error.to_string();
    assert!(rendered.contains("keyexchange"), "{rendered}");
    assert!(rendered.contains("400"), "{rendered}");
    // It never got as far as the token: no `getjwt`, nothing to invalidate.
    assert_eq!(fake.state.count("jdev/sys/getjwt"), 0);
}

/// A Miniserver that has forgotten the token answers `401` on `authwithtoken`;
/// the client then has to fall back to acquiring a fresh one rather than
/// looping on a token nobody accepts.
#[tokio::test]
async fn a_rejected_token_is_replaced_on_the_next_session() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");
    assert_eq!(fake.state.tokens_issued(), 1);

    fake.state.set_reject_token(true);
    fake.state.session(0).await.close(1000);
    common::wait_rec(&mut events, 20, |rec| {
        matches!(rec, Rec::ConnectionClosed(_))
    })
    .await;

    // The reconnect tries the old token, is refused, and asks for a new one.
    fake.state
        .wait_until(25, "a rejected reauthentication", |log| {
            log.iter()
                .filter_map(Entry::as_command)
                .any(|record| record.code == "401")
        })
        .await;
    fake.state.set_reject_token(false);

    common::wait_rec(&mut events, 30, |rec| matches!(rec, Rec::Reconnected)).await;
    fake.state
        .wait_until(20, "a replacement token", |log| {
            log.iter()
                .filter_map(Entry::as_command)
                .filter(|record| record.label == "jdev/sys/getjwt")
                .count()
                >= 2
        })
        .await;
    assert_eq!(client.state(), ConnState::Connected);

    let _ = common::within(15, "stop", client.stop()).await;
}
