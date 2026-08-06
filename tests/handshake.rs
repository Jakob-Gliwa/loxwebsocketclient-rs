//! Handshake, preflight and token lifecycle against the fake Miniserver.

mod common;

use common::{
    ApiValueStyle, FakeConfig, FakeMiniserver, PublicKeyStyle, Rec, RecordingHandler, TEST_USER,
};
use loxwebsocket::{ConnState, Error, LoxClient};

#[tokio::test]
async fn full_handshake_reaches_connected_and_acquires_one_token() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, mut events) = RecordingHandler::new();

    let client = common::within(
        20,
        "the initial connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");

    assert_eq!(client.state(), ConnState::Connected);
    assert_eq!(common::next_rec(&mut events, 5).await, Rec::Connected);

    // The reachability probe runs before the socket is opened, and the public
    // key is fetched over plain HTTP.
    let gets = fake.state.http_gets();
    assert!(gets.contains(&"jdev/cfg/apiKey".to_string()), "{gets:?}");
    assert!(gets.contains(&"jdev/cfg/api".to_string()), "{gets:?}");
    assert!(
        gets.contains(&"jdev/sys/getPublicKey".to_string()),
        "{gets:?}"
    );

    // Exactly one token, acquired through getkey2 → getjwt, and updates enabled.
    assert_eq!(fake.state.count("jdev/sys/getkey2"), 1);
    assert_eq!(fake.state.count("jdev/sys/getjwt"), 1);
    assert_eq!(fake.state.count("jdev/sps/enablebinstatusupdate"), 1);
    assert_eq!(fake.state.tokens_issued(), 1);
    assert!(
        fake.state
            .session_commands(0)
            .iter()
            .all(|record| record.code == "200"),
        "{:?}",
        fake.state.session_commands(0)
    );

    common::within(15, "stop", client.stop())
        .await
        .expect("stop");
}

#[tokio::test]
async fn public_key_arrives_as_a_one_line_mislabeled_certificate() {
    // What Miniservers actually send: an SPKI blob labeled `CERTIFICATE`, with
    // no line wrapping. Both `rsa` and `pem` reject that verbatim.
    let fake = FakeMiniserver::start(FakeConfig {
        public_key_style: PublicKeyStyle::CertificateOneLine,
        ..FakeConfig::default()
    })
    .await;
    let (handler, _events) = RecordingHandler::new();

    let client = common::within(
        20,
        "connect with a mislabeled public key",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");
    assert_eq!(client.state(), ConnState::Connected);
    common::within(15, "stop", client.stop())
        .await
        .expect("stop");
}

#[tokio::test]
async fn reachability_value_may_be_a_single_quoted_string() {
    let fake = FakeMiniserver::start(FakeConfig {
        api_value_style: ApiValueStyle::SingleQuotedString,
        https_status: Some(1),
        ..FakeConfig::default()
    })
    .await;
    let (handler, _events) = RecordingHandler::new();

    let client = common::within(
        20,
        "connect with string-encoded LL.value",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");
    assert_eq!(client.state(), ConnState::Connected);
    common::within(15, "stop", client.stop())
        .await
        .expect("stop");
}

#[tokio::test]
async fn sha1_users_are_supported_as_well() {
    let fake = FakeMiniserver::start(FakeConfig {
        hash_alg: common::HashAlgName::Sha1,
        ..FakeConfig::default()
    })
    .await;
    let (handler, _events) = RecordingHandler::new();

    let client = common::within(
        20,
        "connect with a SHA1 user",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");
    assert_eq!(client.state(), ConnState::Connected);
    common::within(15, "stop", client.stop())
        .await
        .expect("stop");
}

#[tokio::test]
async fn exhausted_event_slots_fail_the_connect_instead_of_looping() {
    let fake = FakeMiniserver::start(FakeConfig {
        has_event_slots: Some(false),
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

    assert!(matches!(error, Error::NoEventSlots), "{error:?}");
    // The probe alone decided it; no socket was ever opened.
    assert_eq!(fake.state.session_count(), 0);
}

#[tokio::test]
async fn a_remote_connection_is_refused_when_local_only_is_set() {
    let fake = FakeMiniserver::start(FakeConfig {
        local: Some(false),
        ..FakeConfig::default()
    })
    .await;
    let (handler, _events) = RecordingHandler::new();

    let mut cfg = common::test_config(&fake);
    cfg.local_only = true;
    let error = common::within(20, "the refused connect", LoxClient::connect(cfg, handler))
        .await
        .expect_err("connect must fail");

    assert!(matches!(error, Error::NotLocal), "{error:?}");
    assert_eq!(fake.state.session_count(), 0);
}

#[tokio::test]
async fn a_bare_enable_updates_reply_is_accepted() {
    // Not every firmware wraps the update counter in an LL envelope.
    let fake = FakeMiniserver::start(FakeConfig {
        bare_enable_updates_reply: true,
        ..FakeConfig::default()
    })
    .await;
    let (handler, _events) = RecordingHandler::new();

    let client = common::within(
        20,
        "connect with a bare enablebinstatusupdate reply",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");
    assert_eq!(client.state(), ConnState::Connected);
    common::within(15, "stop", client.stop())
        .await
        .expect("stop");
}

/// `enablebinstatusupdate` is what makes the Miniserver start pushing, so on
/// some firmwares the first value table overtakes the acknowledgement. The
/// handshake used to return whatever arrived first and drop it on the floor,
/// which silently cost the initial state of every control in that table.
#[tokio::test]
async fn an_event_table_before_the_enable_ack_still_reaches_the_handler() {
    let fake = FakeMiniserver::start(FakeConfig {
        tables_before_enable_ack: true,
        ..FakeConfig::default()
    })
    .await;
    let (handler, mut events) = RecordingHandler::new();

    let client = common::within(
        20,
        "connect with the tables ahead of the ack",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");
    assert_eq!(client.state(), ConnState::Connected);

    for (uuid, value) in common::early_table_records() {
        let rec = common::wait_rec(&mut events, 10, |rec| matches!(rec, Rec::Value { .. })).await;
        assert_eq!(rec, Rec::Value { uuid, value });
    }

    common::within(15, "stop", client.stop())
        .await
        .expect("stop");
}

/// The refresher renews a token that is close to expiry.
///
/// Slow by construction: `refresh::next_refresh_delay` clamps the delay to the
/// `CONNECT_DELAY_SECS` *constant* (15 s) rather than to
/// `ConnectConfig::connect_delay_secs`, so the earliest refresh a test can
/// observe is 15 s away.
#[tokio::test]
async fn a_token_close_to_expiry_is_refreshed() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64
        - loxwebsocket::LOXONE_EPOCH;
    let fake = FakeMiniserver::start(FakeConfig {
        // Expires in half a minute, i.e. long past the 24 h refresh lead.
        token_valid_until: now + 30,
        ..FakeConfig::default()
    })
    .await;
    let (handler, _events) = RecordingHandler::new();
    let client = common::within(
        25,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");

    fake.state
        .wait_until(40, "a refreshjwt", |log| {
            log.iter()
                .filter_map(common::Entry::as_command)
                .any(|record| record.label == "jdev/sys/refreshjwt")
        })
        .await;

    let refresh = fake
        .state
        .commands()
        .into_iter()
        .find(|record| record.label == "jdev/sys/refreshjwt")
        .expect("the refresh command");
    assert_eq!(
        refresh.code, "200",
        "the fake rejected the refresh token hash"
    );

    let _ = common::within(15, "stop", client.stop()).await;
}

#[tokio::test]
async fn check_token_round_trips_through_the_command_path() {
    let fake = FakeMiniserver::start_default().await;
    let (handler, _events) = RecordingHandler::new();
    let client = common::within(
        20,
        "connect",
        LoxClient::connect(common::test_config(&fake), handler),
    )
    .await
    .expect("connect");

    assert!(
        common::within(10, "check_token", client.check_token())
            .await
            .expect("check_token")
    );
    assert_eq!(fake.state.count("jdev/sys/checktoken"), 1);

    // A Miniserver that has forgotten the token answers 401.
    fake.state.set_reject_token(true);
    assert!(
        !common::within(10, "check_token", client.check_token())
            .await
            .expect("check_token")
    );

    fake.state.set_reject_token(false);
    common::within(15, "stop", client.stop())
        .await
        .expect("stop");
    assert_eq!(TEST_USER, "admin");
}
