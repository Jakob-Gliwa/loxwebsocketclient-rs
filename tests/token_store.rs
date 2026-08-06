//! Token persistence across process restarts, against the fake Miniserver.
//!
//! A restart is simulated by stopping the client and connecting a second one
//! with the same store. The store is the only thing the two share, so anything
//! the second client re-uses can only have reached it that way.

mod common;

use common::{FakeMiniserver, RecordingHandler};
use loxwebsocket::{ConnectConfig, FileTokenStore, LoxClient, TokenStore};
use std::path::PathBuf;
use std::sync::Arc;

/// A directory that cleans up after itself, so the tests need no dev-dependency.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "loxwebsocket-tokenstore-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }

    fn store(&self) -> Arc<FileTokenStore> {
        Arc::new(FileTokenStore::new(self.0.join("token.cfg")))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(fake: &FakeMiniserver, store: &Arc<FileTokenStore>) -> ConnectConfig {
    ConnectConfig {
        token_store: Some(Arc::clone(store) as Arc<dyn TokenStore>),
        ..common::test_config(fake)
    }
}

async fn connect(cfg: ConnectConfig) -> LoxClient<RecordingHandler> {
    let (handler, _events) = RecordingHandler::new();
    common::within(20, "connect", LoxClient::connect(cfg, handler))
        .await
        .expect("connect")
}

#[tokio::test]
async fn a_restart_reuses_the_saved_token_instead_of_acquiring_one() {
    let dir = TempDir::new("reuse");
    let store = dir.store();
    let fake = FakeMiniserver::start_default().await;

    let cfg = ConnectConfig {
        // Without this the graceful stop below would kill the very token the
        // second client is supposed to pick up.
        kill_token_on_stop: false,
        ..config(&fake, &store)
    };

    let first = connect(cfg.clone()).await;
    assert_eq!(fake.state.tokens_issued(), 1);
    common::within(15, "stop", first.stop())
        .await
        .expect("stop");
    assert!(store.path().exists(), "the token outlived the first client");

    let second = connect(cfg).await;

    assert_eq!(
        fake.state.tokens_issued(),
        1,
        "the restart acquired a new token instead of reusing the saved one"
    );
    assert_eq!(
        fake.state.count("jdev/sys/getjwt"),
        1,
        "getjwt is exactly the round trip a store is meant to save"
    );
    // Encrypted commands reach the Miniserver without the `jdev/sys/` prefix,
    // so this is the verb the fake records for them.
    assert_eq!(
        fake.state.count("authwithtoken"),
        1,
        "the second session authenticated with the token it loaded"
    );

    common::within(15, "stop", second.stop())
        .await
        .expect("stop");
}

#[tokio::test]
async fn a_graceful_stop_kills_the_saved_token_by_default() {
    let dir = TempDir::new("kill");
    let store = dir.store();
    let fake = FakeMiniserver::start_default().await;

    let client = connect(config(&fake, &store)).await;
    assert!(
        store.path().exists(),
        "the token is saved as soon as it is acquired"
    );

    common::within(15, "stop", client.stop())
        .await
        .expect("stop");

    assert_eq!(fake.state.killed_tokens().len(), 1);
    assert!(
        !store.path().exists(),
        "a token killed on the Miniserver must not be offered to the next run"
    );
}

#[tokio::test]
async fn a_token_the_miniserver_no_longer_knows_falls_back_to_a_fresh_one() {
    let dir = TempDir::new("stale");
    let store = dir.store();
    let fake = FakeMiniserver::start_default().await;

    let cfg = ConnectConfig {
        kill_token_on_stop: false,
        ..config(&fake, &store)
    };
    let first = connect(cfg.clone()).await;
    common::within(15, "stop", first.stop())
        .await
        .expect("stop");

    // What a Miniserver reboot or a token cleanup looks like from here: the
    // saved token is still well-formed and unexpired, but no longer accepted.
    fake.state.set_reject_token(true);

    let second = connect(cfg).await;

    assert_eq!(
        fake.state.tokens_issued(),
        2,
        "a rejected token has to be replaced, not retried forever"
    );
    assert!(
        store.path().exists(),
        "the replacement was saved over the stale one"
    );

    common::within(15, "stop", second.stop())
        .await
        .expect("stop");
}
