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
/// already has — `checktoken`/`authwithtoken`, never a second `getjwt`.
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
        second.iter().any(|label| label == "authwithtoken")
            || second.iter().any(|label| label == "jdev/sys/checktoken"),
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

/// A `checktoken` refused with `901` means the Miniserver is out of connection
/// slots, not that the token is bad. The client used to treat it as a rejection
/// and ask for a replacement over the very connection just refused.
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
        .wait_until(20, "a checktoken refused with 901", |log| {
            log.iter()
                .filter_map(Entry::as_command)
                .any(|record| record.label == "jdev/sys/checktoken" && record.code == "901")
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
