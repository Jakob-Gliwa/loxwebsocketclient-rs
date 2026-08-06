//! Token refresh task.
//!
//! Refreshing used to be a `select!` arm inside the reader loop, with the
//! deadline rebuilt from scratch on every iteration — so an active connection
//! reset it with each incoming frame and it never became due. Here `sleep` is
//! awaited on its own, and the commands take the ordinary path through the
//! writer instead of reading raw frames out from under the reader.

use crate::auth::{CMD_GET_KEY, apply_valid_until, build_token_hash, cmd_refresh_token};
use crate::client::io::IoCommand;
use crate::client::keepalive::{
    TOKEN_REFRESH_DEFAULT_SECONDS, TOKEN_REFRESH_MIN_DELAY_SECS,
    TOKEN_REFRESH_SECONDS_BEFORE_EXPIRY,
};
use crate::client::state::SharedState;
use crate::error::{Error, Result};
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, sleep};
use tracing::{debug, warn};

/// Refresh the session token until the task is aborted with the session.
pub(crate) async fn run_refresher(
    username: String,
    shared: Arc<SharedState>,
    cmd_tx: mpsc::Sender<IoCommand>,
) {
    loop {
        sleep(next_refresh_delay(&shared)).await;
        match refresh_once(&username, &shared, &cmd_tx).await {
            Ok(true) => debug!("token refreshed"),
            Ok(false) => {}
            Err(e) => warn!("token refresh failed: {e}"),
        }
    }
}

/// Time until the token should be refreshed.
pub(crate) fn next_refresh_delay(shared: &SharedState) -> Duration {
    let secs = match shared.token_valid_until() {
        None => TOKEN_REFRESH_DEFAULT_SECONDS,
        Some(_) => {
            let token = shared.token();
            (token.seconds_to_expire() - TOKEN_REFRESH_SECONDS_BEFORE_EXPIRY)
                .max(TOKEN_REFRESH_MIN_DELAY_SECS)
        }
    };
    Duration::from_secs(secs.max(0) as u64)
}

/// Returns `Ok(false)` when there is no token to refresh.
async fn refresh_once(
    username: &str,
    shared: &SharedState,
    cmd_tx: &mpsc::Sender<IoCommand>,
) -> Result<bool> {
    let token = shared.token();
    if token.is_empty() {
        return Ok(false);
    }
    let key_resp = send(cmd_tx, CMD_GET_KEY.to_string()).await?;
    let hash = build_token_hash(&key_resp, &token)?;
    let resp = send(cmd_tx, cmd_refresh_token(&hash, username)).await?;

    // Re-read instead of reusing the snapshot: a reconnect may have replaced
    // the token while the refresh was in flight.
    let mut current = shared.token();
    if current.is_empty() || current.token != token.token {
        debug!("token changed during refresh, discarding the answer");
        return Ok(false);
    }
    apply_valid_until(&mut current, &resp)?;
    shared.set_token(current);
    Ok(true)
}

async fn send(cmd_tx: &mpsc::Sender<IoCommand>, cmd: String) -> Result<Bytes> {
    let (resp, rx) = oneshot::channel();
    cmd_tx
        .send(IoCommand::Encrypted { cmd, resp })
        .await
        .map_err(|_| Error::ChannelClosed)?;
    rx.await.map_err(|_| Error::ChannelClosed)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::LxToken;
    use crate::crypto::HashAlg;

    #[test]
    fn no_token_uses_the_default_interval() {
        let shared = SharedState::new();
        assert_eq!(
            next_refresh_delay(&shared),
            Duration::from_secs(TOKEN_REFRESH_DEFAULT_SECONDS as u64)
        );
    }

    #[test]
    fn refresh_is_scheduled_ahead_of_expiry() {
        let shared = SharedState::new();
        // Valid for far longer than the lead time (seconds since 2009-01-01).
        let valid_until = 40 * 365 * 24 * 3600;
        shared.set_token(LxToken::new("tok", valid_until, HashAlg::Sha256));
        let delay = next_refresh_delay(&shared).as_secs() as i64;
        let remaining = shared.token().seconds_to_expire();
        assert_eq!(delay, remaining - TOKEN_REFRESH_SECONDS_BEFORE_EXPIRY);
    }

    #[test]
    fn imminent_expiry_is_floored_not_negative() {
        let shared = SharedState::new();
        // Already expired: the delay must stay positive and short.
        shared.set_token(LxToken::new("tok", 1, HashAlg::Sha1));
        assert_eq!(
            next_refresh_delay(&shared),
            Duration::from_secs(TOKEN_REFRESH_MIN_DELAY_SECS as u64)
        );
    }
}
