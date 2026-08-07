//! High-level `LoxClient` façade.

mod connect;
mod handler;
mod handshake;
pub mod http;
mod io;
mod keepalive;
mod pending;
mod reader;
mod reconnect;
mod refresh;
mod state;
pub mod tls;
mod visu;
mod writer;

pub use connect::Endpoints;
pub use handler::{ChannelHandler, ClientEvent, LoxHandler, OwnedEvent};
pub use http::{ApiInfo, HttpClient};
pub use keepalive::{
    COMMAND_TIMEOUT_SECS, CONNECT_DELAY_SECS, KEEP_ALIVE_PERIOD_SECS, LONG_BACKOFF_SECS,
    MAX_MISSED_KEEPALIVES, PRODUCTIVE_SESSION_SECS, READ_IDLE_TIMEOUT_SECS,
    SHUTDOWN_JOIN_TIMEOUT_SECS, TOKEN_REFRESH_DEFAULT_SECONDS, TOKEN_REFRESH_MIN_DELAY_SECS,
    TOKEN_REFRESH_SECONDS_BEFORE_EXPIRY,
};
pub use pending::{CONTROL_KEY_SCAN_LIMIT, CONTROL_VALUE_LIMIT, extract_ll_control};
pub use reconnect::describe_close_code;
pub use tls::{TlsContext, TlsMode};

use crate::auth::flow::CMD_GET_KEY;
use crate::auth::store::token_binding;
use crate::auth::token::Redacted;
use crate::auth::{
    DEFAULT_CLIENT_INFO, DEFAULT_CLIENT_UUID, TokenPermission, TokenStore, build_token_hash,
    cmd_check_token, payload_ll_status,
};
use crate::error::{Error, Result};
use crate::metrics::{ConnState, LoxMetrics};
use bytes::Bytes;
use io::{IoCommand, run_supervisor};
use state::SharedState;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

/// Default depth of the façade → writer command channel.
pub const COMMAND_CHANNEL_DEPTH: usize = 32;

/// Default ceiling on commands in flight at once.
pub const MAX_PENDING_COMMANDS: usize = 32;

/// Connection / client configuration.
///
/// The `Debug` implementation redacts the password.
#[derive(Clone)]
pub struct ConnectConfig {
    /// HTTP(S) base URL of the Miniserver, e.g. `http://192.168.1.5` or bare host.
    pub loxone_url: String,
    pub username: String,
    pub password: String,
    /// Certificate verification policy for HTTPS / WSS. Defaults to
    /// [`TlsMode::WebPki`]; local Miniservers reached by IP usually need
    /// [`TlsMode::PinOnFirstUse`].
    pub tls: TlsMode,
    /// Send `enablebinstatusupdate` after auth.
    pub receive_updates: bool,
    /// Abort instead of reconnecting when the Miniserver reports the connection
    /// as remote. Only meaningful for installations that must never traverse
    /// Loxone's cloud relay.
    pub local_only: bool,
    /// `0` = unlimited reconnect attempts.
    pub max_reconnect_attempts: u32,
    pub client_uuid: String,
    pub client_info: String,
    /// Lifespan class of the acquired token; [`TokenPermission::App`] by default.
    pub token_permission: TokenPermission,
    pub keepalive_secs: u64,
    pub connect_delay_secs: u64,
    /// Delay after a close code that will not clear within seconds (no free
    /// event slots, firmware update, login block).
    pub long_backoff_secs: u64,
    pub command_timeout_secs: u64,
    /// Reader idle window. Must exceed `keepalive_secs`; the window is widened
    /// automatically for the payload length a message header announces.
    pub read_idle_timeout_secs: u64,
    /// Unanswered keepalives tolerated before the session is discarded.
    pub max_missed_keepalives: u32,
    /// Ceiling on pipelined commands; further `send_command` calls fail fast.
    pub max_pending_commands: usize,
    /// Depth of the queue between the façade and the writer task.
    ///
    /// The writer encrypts every command individually, so a burst that arrives
    /// faster than that fills the queue: one inbound message fanning out into
    /// dozens of controls is enough. Raise this if
    /// [`LoxClient::try_send_control`] reports [`Error::Backpressure`] on an
    /// otherwise healthy connection.
    pub command_channel_depth: usize,
    /// Where to keep the token between process runs. `None` — the default —
    /// means a fresh token is acquired on every start.
    ///
    /// See [`TokenStore`] for what a store is and is not good for, and
    /// [`FileTokenStore`](crate::FileTokenStore) for the one this crate ships.
    pub token_store: Option<Arc<dyn TokenStore>>,
    /// Send `killtoken` during [`LoxClient::stop`], invalidating the token on
    /// the Miniserver. Defaults to `true`, which keeps its token storage clean
    /// as the protocol document recommends.
    ///
    /// Turn it off to let a [`token_store`](Self::token_store) survive a
    /// graceful restart; the token then stays valid until it expires, whether
    /// or not this client comes back.
    pub kill_token_on_stop: bool,
}

impl std::fmt::Debug for ConnectConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectConfig")
            .field("loxone_url", &self.loxone_url)
            .field("username", &self.username)
            .field("password", &Redacted(self.password.len()))
            .field("tls", &self.tls)
            .field("receive_updates", &self.receive_updates)
            .field("local_only", &self.local_only)
            .field("max_reconnect_attempts", &self.max_reconnect_attempts)
            .field("client_uuid", &self.client_uuid)
            .field("client_info", &self.client_info)
            .field("token_permission", &self.token_permission)
            .field("keepalive_secs", &self.keepalive_secs)
            .field("connect_delay_secs", &self.connect_delay_secs)
            .field("long_backoff_secs", &self.long_backoff_secs)
            .field("command_timeout_secs", &self.command_timeout_secs)
            .field("read_idle_timeout_secs", &self.read_idle_timeout_secs)
            .field("max_missed_keepalives", &self.max_missed_keepalives)
            .field("max_pending_commands", &self.max_pending_commands)
            .field("command_channel_depth", &self.command_channel_depth)
            .field("token_store", &self.token_store)
            .field("kill_token_on_stop", &self.kill_token_on_stop)
            .finish()
    }
}

impl ConnectConfig {
    /// Configuration with library defaults, including [`TlsMode::WebPki`].
    pub fn new(
        loxone_url: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            loxone_url: loxone_url.into(),
            username: username.into(),
            password: password.into(),
            tls: TlsMode::default(),
            receive_updates: true,
            local_only: false,
            max_reconnect_attempts: 0,
            client_uuid: DEFAULT_CLIENT_UUID.to_string(),
            client_info: DEFAULT_CLIENT_INFO.to_string(),
            token_permission: TokenPermission::default(),
            keepalive_secs: KEEP_ALIVE_PERIOD_SECS,
            connect_delay_secs: CONNECT_DELAY_SECS,
            long_backoff_secs: LONG_BACKOFF_SECS,
            command_timeout_secs: COMMAND_TIMEOUT_SECS,
            read_idle_timeout_secs: READ_IDLE_TIMEOUT_SECS,
            max_missed_keepalives: MAX_MISSED_KEEPALIVES,
            max_pending_commands: MAX_PENDING_COMMANDS,
            command_channel_depth: COMMAND_CHANNEL_DEPTH,
            token_store: None,
            kill_token_on_stop: true,
        }
    }

    /// Keep the token in `store`, so a restart can re-use it.
    ///
    /// Convenience for setting [`token_store`](Self::token_store); pair it with
    /// `kill_token_on_stop = false` if graceful restarts should re-use the
    /// token too.
    pub fn with_token_store(mut self, store: Arc<dyn TokenStore>) -> Self {
        self.token_store = Some(store);
        self
    }
}

/// Async Loxone WebSocket client.
///
/// The handler runs on the dedicated IO task (sync zero-copy callbacks).
pub struct LoxClient<H: LoxHandler> {
    cmd_tx: mpsc::Sender<IoCommand>,
    shared: Arc<SharedState>,
    stopped: Arc<AtomicBool>,
    username: String,
    /// `None` once [`LoxClient::stop`] has taken it, which is how [`Drop`]
    /// tells an already-stopped client from a dropped one.
    join: Option<JoinHandle<()>>,
    _handler: PhantomData<H>,
}

impl<H: LoxHandler> std::fmt::Debug for LoxClient<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoxClient")
            .field("state", &self.state())
            .field("stopped", &self.stopped.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl<H: LoxHandler> LoxClient<H> {
    /// Connect, authenticate, and start the IO supervisor.
    ///
    /// Waits until the initial key-exchange + token auth succeeds. Lifecycle
    /// events are also delivered via [`LoxHandler::on_event`].
    pub async fn connect(cfg: ConnectConfig, handler: H) -> Result<Self> {
        let shared = match &cfg.token_store {
            Some(store) => {
                let binding = token_binding(&cfg.loxone_url, &cfg.username, &cfg.client_uuid);
                let shared = SharedState::with_token_store(Arc::clone(store), binding);
                // Before the handshake, so it can authenticate with whatever an
                // earlier run left behind instead of acquiring a new token.
                shared.restore_token();
                shared
            }
            None => SharedState::new(),
        };
        let stopped = Arc::new(AtomicBool::new(false));
        // `mpsc::channel` panics on zero, and a zero-depth queue would be a
        // configuration mistake rather than a request to drop everything.
        let (cmd_tx, cmd_rx) = mpsc::channel(cfg.command_channel_depth.max(1));
        let (ready_tx, ready_rx) = oneshot::channel();
        let username = cfg.username.clone();

        let shared_task = Arc::clone(&shared);
        let stopped_task = Arc::clone(&stopped);
        let supervisor_tx = cmd_tx.clone();
        let join = tokio::spawn(async move {
            run_supervisor(
                cfg,
                handler,
                supervisor_tx,
                cmd_rx,
                shared_task,
                stopped_task,
                Some(ready_tx),
            )
            .await;
        });

        match ready_rx.await {
            Ok(Ok(())) => Ok(Self {
                cmd_tx,
                shared,
                stopped,
                username,
                join: Some(join),
                _handler: PhantomData,
            }),
            Ok(Err(e)) => {
                stopped.store(true, Ordering::Relaxed);
                let _ = join.await;
                Err(e)
            }
            Err(_) => {
                stopped.store(true, Ordering::Relaxed);
                let _ = join.await;
                Err(Error::ws("IO task exited before ready"))
            }
        }
    }

    /// Send an encrypted request/response command; returns the type-0 payload.
    ///
    /// Commands may be pipelined up to
    /// [`ConnectConfig::max_pending_commands`]; answers are correlated in the
    /// order the commands went out.
    pub async fn send_command(&self, cmd: &str) -> Result<Bytes> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(IoCommand::Encrypted {
                cmd: cmd.to_string(),
                resp: tx,
            })
            .await
            .map_err(|_| Error::ChannelClosed)?;
        rx.await.map_err(|_| Error::ChannelClosed)?
    }

    /// Fire-and-forget control: `jdev/sps/io/{uuid}/{value}`.
    ///
    /// The acknowledgement the Miniserver sends is consumed by an internal
    /// waiter, so it can never complete a concurrent [`Self::send_command`].
    ///
    /// Fails with [`Error::NotConnected`] rather than queueing when there is no
    /// live session; see [`Self::live`]. Waits for room in the command queue
    /// when there is one — use [`Self::try_send_control`] to be refused instead.
    pub async fn send_control(&self, uuid: &str, value: &str) -> Result<()> {
        self.require_live()?;
        self.cmd_tx
            .send(IoCommand::Control {
                uuid: uuid.to_string(),
                value: value.to_string(),
            })
            .await
            .map_err(|_| Error::ChannelClosed)
    }

    /// Fire-and-forget control that never waits for room in the queue.
    ///
    /// [`Error::Backpressure`] means the writer is not keeping up. A caller
    /// under a QoS-0 contract needs that answer now, not once the Miniserver is
    /// back: it can drop the value, coalesce it with the next one, or shed the
    /// whole burst — all of which are better than a send that resolves minutes
    /// later with a value nobody wants any more.
    pub fn try_send_control(&self, uuid: &str, value: &str) -> Result<()> {
        self.require_live()?;
        self.cmd_tx
            .try_send(IoCommand::Control {
                uuid: uuid.to_string(),
                value: value.to_string(),
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => {
                    self.shared
                        .metrics
                        .controls_rejected_backpressure
                        .fetch_add(1, Ordering::Relaxed);
                    Error::Backpressure
                }
                mpsc::error::TrySendError::Closed(_) => Error::ChannelClosed,
            })
    }

    /// Queue a visualization-password secured control (max 1 pending).
    ///
    /// Refuses with [`Error::NotConnected`] off-session, like [`Self::send_control`].
    pub async fn send_visu_control(&self, uuid: &str, value: &str, visu_pw: &str) -> Result<()> {
        self.require_live()?;
        self.cmd_tx
            .send(IoCommand::VisuControl {
                uuid: uuid.to_string(),
                value: value.to_string(),
                visu_pw: visu_pw.to_string(),
            })
            .await
            .map_err(|_| Error::ChannelClosed)
    }

    /// Whether a control sent right now would reach a writer.
    ///
    /// Racy by nature — the session can end between this call and the next
    /// send — but enough to skip work that only makes sense while connected.
    pub fn live(&self) -> bool {
        self.state() == ConnState::Connected
    }

    /// Refuse a control there is no session for, counting the refusal.
    ///
    /// Deliberately not applied to [`Self::send_command`]. That one is
    /// request/response: its caller is waiting for an answer either way, and
    /// the state can still be `Connecting` when a legitimate one goes out.
    fn require_live(&self) -> Result<()> {
        if self.live() {
            return Ok(());
        }
        self.shared
            .metrics
            .controls_rejected_offline
            .fetch_add(1, Ordering::Relaxed);
        Err(Error::NotConnected)
    }

    /// Ask the Miniserver whether the current token is still valid.
    ///
    /// Returns `false` when there is no token or the Miniserver rejects it;
    /// the token itself is never exposed.
    pub async fn check_token(&self) -> Result<bool> {
        let token = self.shared.token();
        if token.is_empty() {
            return Ok(false);
        }
        let key_resp = self.send_command(CMD_GET_KEY).await?;
        let hash = build_token_hash(&key_resp, &token)?;
        let resp = self
            .send_command(&cmd_check_token(&hash, &self.username))
            .await?;
        Ok(payload_ll_status(&resp).as_deref() == Some("200"))
    }

    /// Immutable metrics snapshot.
    pub fn metrics(&self) -> LoxMetrics {
        self.shared
            .metrics
            .snapshot(self.shared.state(), self.shared.token_valid_until())
    }

    /// Current connection state.
    pub fn state(&self) -> ConnState {
        self.shared.state()
    }

    /// Stop the supervisor and wait for the IO task to finish.
    ///
    /// The session's token is killed on the Miniserver first (best effort,
    /// short timeout), then the close frame goes out. The join is bounded by
    /// [`SHUTDOWN_JOIN_TIMEOUT_SECS`] so a wedged Miniserver cannot hang the
    /// caller.
    ///
    /// Dropping the client instead requests the same shutdown but cannot wait
    /// for it, so `stop()` is the only way to be sure the `killtoken` went out.
    pub async fn stop(mut self) -> Result<()> {
        self.stopped.store(true, Ordering::Relaxed);
        let _ = self.cmd_tx.send(IoCommand::Stop).await;
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        match timeout(Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS), join).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(Error::ws(format!("IO task join: {e}"))),
            Err(_) => Err(Error::Timeout("IO task did not stop in time".into())),
        }
    }
}

/// Wind the supervisor down when the client goes away without [`LoxClient::stop`].
///
/// The supervisor holds its own clone of the command sender — it hands one to
/// the token refresher every session — so dropping the façade's copy never
/// closes the channel. Without the explicit stop below, `cmd_rx.recv()` would
/// simply never return `None` and the task would keep reconnecting, sending
/// keepalives and refreshing tokens for the rest of the process lifetime.
impl<H: LoxHandler> Drop for LoxClient<H> {
    fn drop(&mut self) {
        let Some(join) = self.join.take() else {
            // `stop()` already wound it down and waited for it.
            return;
        };
        self.stopped.store(true, Ordering::Relaxed);
        if self.cmd_tx.try_send(IoCommand::Stop).is_ok() {
            // Dropping the handle detaches the task; it finishes the graceful
            // close on its own.
            return;
        }
        // A full channel would leave only the flag, which the supervisor
        // notices at its next reconnect and not during a live session — so
        // hand the blocking send to a detached task instead.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let cmd_tx = self.cmd_tx.clone();
                handle.spawn(async move {
                    let _ = cmd_tx.send(IoCommand::Stop).await;
                });
            }
            // No runtime to spawn on and no room to queue: aborting is the only
            // remaining way not to leak the task.
            Err(_) => join.abort(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_the_password() {
        let cfg = ConnectConfig::new("http://10.0.0.1", "admin", "hunter2");
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("hunter2"));
        assert!(rendered.contains("<redacted, 7 bytes>"));
        assert!(rendered.contains("admin"));
    }

    #[test]
    fn defaults_are_internally_consistent() {
        let cfg = ConnectConfig::new("host", "u", "p");
        assert!(matches!(cfg.tls, TlsMode::WebPki));
        assert_eq!(cfg.token_permission, TokenPermission::App);
        // A quiet but healthy connection must survive at least one keepalive
        // round trip before the reader gives up on it.
        assert!(cfg.read_idle_timeout_secs > cfg.keepalive_secs);
        assert!(cfg.long_backoff_secs > cfg.connect_delay_secs);
        assert!(cfg.max_pending_commands > 0);
        // Zero would panic `mpsc::channel`; the `.max(1)` in `connect` is a
        // backstop, not a licence for the default to be wrong.
        assert!(cfg.command_channel_depth > 0);
        assert_eq!(cfg.command_channel_depth, COMMAND_CHANNEL_DEPTH);
    }
}
