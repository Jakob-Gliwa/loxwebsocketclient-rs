//! IO supervisor: connect, hand shake, run the reader inline, reconnect.
//!
//! One session owns three concurrent pieces: the reader loop (inline here, so
//! it can hold the handler without a lock), the writer task (sole owner of the
//! write half and the salt state) and the token refresher (a plain client of
//! the writer). Everything they share lives behind `Arc`s created per session.

use crate::client::ConnectConfig;
use crate::client::connect::{Endpoints, split_ws, ws_connect};
use crate::client::handler::{ClientEvent, HandlerGuard, LoxHandler};
use crate::client::handshake::Handshake;
use crate::client::http::HttpClient;
use crate::client::keepalive::{PRODUCTIVE_SESSION_SECS, SHUTDOWN_JOIN_TIMEOUT_SECS};
use crate::client::pending::PendingQueue;
use crate::client::reader::{ReadOutcome, Reader};
use crate::client::reconnect::{
    Backoff, backoff_for_close, describe_close_code, should_continue, terminal_close,
    token_survives_close,
};
use crate::client::refresh::run_refresher;
use crate::client::state::{Liveness, SharedState};
use crate::client::tls::TlsContext;
use crate::client::visu::VisuQueue;
use crate::client::writer::{Writer, WriterConfig, WriterMsg};
use crate::crypto::{SaltState, SessionKeys, wrap_session_key};
use crate::error::{Error, Result};
use crate::metrics::ConnState;
use bytes::Bytes;
use fastwebsockets::FragmentCollectorRead;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant, sleep, timeout};
use tracing::{debug, error, info, warn};

/// Channel depth for reader-to-writer messages (close echo, secured commands).
const WRITER_CHANNEL_DEPTH: usize = 16;

/// Commands from the façade into the IO supervisor.
#[derive(Debug)]
pub enum IoCommand {
    Encrypted {
        cmd: String,
        resp: oneshot::Sender<Result<Bytes>>,
    },
    Control {
        uuid: String,
        value: String,
    },
    VisuControl {
        uuid: String,
        value: String,
        visu_pw: String,
    },
    Stop,
}

/// Everything that outlives a single session.
struct SessionCtx {
    cfg: ConnectConfig,
    endpoints: Endpoints,
    tls: TlsContext,
    http: HttpClient,
    shared: Arc<SharedState>,
    stopped: Arc<AtomicBool>,
    /// Handed to the refresher so it goes through the ordinary command path.
    cmd_tx: mpsc::Sender<IoCommand>,
}

impl std::fmt::Debug for SessionCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCtx")
            .field("endpoints", &self.endpoints)
            .finish_non_exhaustive()
    }
}

enum SessionOutcome {
    Stopped,
    Disconnected { close_code: Option<u16> },
    Failed(Error),
}

/// Session result plus the command receiver handed back by the writer.
struct SessionResult {
    outcome: SessionOutcome,
    cmd_rx: Option<mpsc::Receiver<IoCommand>>,
    /// How long the session ran once connected, or `None` if the handshake
    /// never completed. Not derivable from `outcome`: a connection dropped
    /// without a close frame reports `Failed` just like one that never
    /// authenticated, and the two need opposite reconnect answers.
    connected_for: Option<Duration>,
}

/// Run the full connect / listen / reconnect supervisor until stop.
///
/// `ready` is signaled once after the first successful auth, or with an error
/// if the initial connect fails.
pub async fn run_supervisor<H: LoxHandler>(
    cfg: ConnectConfig,
    handler: H,
    cmd_tx: mpsc::Sender<IoCommand>,
    cmd_rx: mpsc::Receiver<IoCommand>,
    shared: Arc<SharedState>,
    stopped: Arc<AtomicBool>,
    mut ready: Option<oneshot::Sender<Result<()>>>,
) {
    // The reader runs inline on this task, so an unwinding callback would take
    // the supervisor with it and leave the client wedged in `Connected`.
    let mut handler = HandlerGuard::new(handler);

    let setup = Endpoints::from_loxone_url(&cfg.loxone_url)
        .and_then(|endpoints| TlsContext::new(cfg.tls.clone()).map(|tls| (tls, endpoints)));
    let (tls, endpoints) = match setup {
        Ok(v) => v,
        Err(e) => {
            error!("connection setup failed: {e}");
            finish(&shared, &mut handler, &mut ready, Some(e));
            return;
        }
    };
    let ctx = SessionCtx {
        http: HttpClient::new(&endpoints, tls.clone()),
        cfg,
        endpoints,
        tls,
        shared,
        stopped,
        cmd_tx,
    };

    let mut cmd_rx = Some(cmd_rx);
    let mut attempt: u32 = 0;
    let mut ever_connected = false;

    loop {
        if ctx.stopped.load(Ordering::Relaxed) {
            finish(&ctx.shared, &mut handler, &mut ready, Some(Error::Stopped));
            return;
        }
        // Backstop for an unwind in a lifecycle callback, which — unlike the
        // reader path — has no error to propagate.
        if handler.panicked() {
            finish(
                &ctx.shared,
                &mut handler,
                &mut ready,
                Some(Error::HandlerPanic),
            );
            return;
        }

        ctx.shared.set_state(if ever_connected {
            ConnState::Reconnecting
        } else {
            ConnState::Connecting
        });

        let Some(rx) = cmd_rx.take() else {
            error!("command channel lost with the writer task");
            finish(&ctx.shared, &mut handler, &mut ready, None);
            return;
        };

        let result = session_once(&ctx, &mut handler, rx, ever_connected, &mut ready).await;
        cmd_rx = result.cmd_rx;

        if let Some(session_len) = result.connected_for {
            ever_connected = true;
            if session_len >= Duration::from_secs(PRODUCTIVE_SESSION_SECS) {
                // `max_reconnect_attempts` bounds consecutive failures. A
                // session that did real work clears the budget; a flapping one
                // deliberately does not.
                attempt = 0;
            }
        }

        let backoff = match result.outcome {
            SessionOutcome::Stopped => {
                finish(&ctx.shared, &mut handler, &mut ready, Some(Error::Stopped));
                return;
            }
            SessionOutcome::Disconnected { close_code } => {
                warn!(
                    "disconnected: {} ({:?})",
                    describe_close_code(close_code),
                    close_code
                );
                ctx.shared.metrics.mark_disconnected(close_code);
                handler.lifecycle(ClientEvent::ConnectionClosed { close_code });
                if !token_survives_close(close_code) {
                    debug!("close code invalidates the token, discarding it");
                    ctx.shared.clear_token();
                }
                if let Some(e) = terminal_close(close_code) {
                    error!("aborting, reconnecting cannot change this: {e}");
                    finish(&ctx.shared, &mut handler, &mut ready, Some(e));
                    return;
                }
                backoff_for_close(close_code)
            }
            SessionOutcome::Failed(e) => {
                error!("session failed: {e}");
                ctx.shared
                    .metrics
                    .reconnect_failures
                    .fetch_add(1, Ordering::Relaxed);

                if e.is_terminal() {
                    error!("aborting, reconnecting cannot change this: {e}");
                    finish(&ctx.shared, &mut handler, &mut ready, Some(e));
                    return;
                }
                if !ever_connected {
                    finish(&ctx.shared, &mut handler, &mut ready, Some(e));
                    return;
                }
                if e.needs_long_backoff() {
                    Backoff::Long
                } else {
                    Backoff::Normal
                }
            }
        };

        if !wait_reconnect(&ctx, &mut attempt, &mut handler, backoff).await {
            return;
        }
    }
}

/// Terminal bookkeeping: state, pending `ready` and the `Closed` event.
fn finish<H: LoxHandler>(
    shared: &SharedState,
    handler: &mut HandlerGuard<H>,
    ready: &mut Option<oneshot::Sender<Result<()>>>,
    error: Option<Error>,
) {
    shared.set_state(ConnState::Closed);
    if let Some(tx) = ready.take() {
        let _ = tx.send(Err(error.unwrap_or(Error::Stopped)));
    }
    handler.lifecycle(ClientEvent::Closed);
}

async fn wait_reconnect<H: LoxHandler>(
    ctx: &SessionCtx,
    attempt: &mut u32,
    handler: &mut HandlerGuard<H>,
    backoff: Backoff,
) -> bool {
    if !should_continue(*attempt, ctx.cfg.max_reconnect_attempts) {
        error!(
            "reconnect exhausted after {} attempts",
            ctx.cfg.max_reconnect_attempts
        );
        ctx.shared.set_state(ConnState::Closed);
        handler.lifecycle(ClientEvent::Closed);
        return false;
    }

    *attempt += 1;
    ctx.shared
        .metrics
        .reconnect_attempts
        .fetch_add(1, Ordering::Relaxed);

    let delay = match backoff {
        Backoff::Normal => ctx.cfg.connect_delay_secs,
        Backoff::Long => ctx.cfg.long_backoff_secs,
    };
    info!("waiting {delay}s before reconnect attempt {attempt}");
    ctx.shared.set_state(ConnState::Reconnecting);

    if !sleep_unless_stopped(Duration::from_secs(delay), &ctx.stopped).await {
        ctx.shared.set_state(ConnState::Closed);
        handler.lifecycle(ClientEvent::Closed);
        return false;
    }
    true
}

/// Sleep for `total`, returning `false` as soon as a stop is requested.
///
/// The long backoff runs for minutes, and `stop()` must not have to wait it
/// out; polling in slices keeps that simple without another channel.
async fn sleep_unless_stopped(total: Duration, stopped: &AtomicBool) -> bool {
    const SLICE: Duration = Duration::from_millis(250);
    let deadline = Instant::now() + total;
    loop {
        if stopped.load(Ordering::Relaxed) {
            return false;
        }
        let now = Instant::now();
        if now >= deadline {
            return true;
        }
        sleep(SLICE.min(deadline - now)).await;
    }
}

/// Ask the Miniserver about itself before spending a TLS handshake and an
/// authentication on a connection it will refuse anyway.
async fn preflight(ctx: &SessionCtx) -> Result<()> {
    if !ctx.cfg.receive_updates && !ctx.cfg.local_only {
        return Ok(());
    }
    let info = match ctx.http.api_info().await {
        Ok(info) => info,
        Err(e) => {
            // Unreachable over HTTP does not imply unreachable over the
            // WebSocket port; let the connect attempt decide.
            debug!("reachability probe failed: {e}");
            return Ok(());
        }
    };
    if ctx.cfg.local_only && info.local == Some(false) {
        return Err(Error::NotLocal);
    }
    if ctx.cfg.receive_updates && info.has_event_slots == Some(false) {
        return Err(Error::NoEventSlots);
    }
    if info.https_status == Some(1) && !ctx.endpoints.use_tls {
        warn!("Miniserver offers TLS but the configured URL is plain http");
    }
    Ok(())
}

async fn session_once<H: LoxHandler>(
    ctx: &SessionCtx,
    handler: &mut HandlerGuard<H>,
    cmd_rx: mpsc::Receiver<IoCommand>,
    is_reconnect: bool,
    ready: &mut Option<oneshot::Sender<Result<()>>>,
) -> SessionResult {
    macro_rules! bail {
        ($e:expr) => {
            return SessionResult {
                outcome: SessionOutcome::Failed($e),
                cmd_rx: Some(cmd_rx),
                connected_for: None,
            }
        };
    }

    let cfg = &ctx.cfg;

    if let Err(e) = preflight(ctx).await {
        bail!(e);
    }

    if ctx.tls.needs_pin_bootstrap() {
        if let Err(e) = ctx.http.bootstrap_pin(&cfg.username, &cfg.password).await {
            if matches!(e, Error::TlsPinMismatch { .. }) {
                bail!(e);
            }
            warn!("could not derive certificate pin from getcertificate: {e}");
        }
    }

    let keys = SessionKeys::generate();
    // Fresh per session: carrying a salt over would make the first command emit
    // `nextSalt/{stale}/…` and earn a spurious 401.
    let mut salt = SaltState::new();

    let public_key = match ctx.http.get_public_key(&cfg.username, &cfg.password).await {
        Ok(k) => k,
        Err(e) => bail!(e),
    };
    let session_b64 = match wrap_session_key(&public_key, &keys.session_payload()) {
        Ok(s) => s,
        Err(e) => bail!(e),
    };

    let ws = match ws_connect(&ctx.endpoints, &ctx.tls).await {
        Ok(ws) => ws,
        Err(e) => bail!(e),
    };

    let (ws_read, mut ws_write, abort_reader) = split_ws(ws);
    let mut ws_read = FragmentCollectorRead::new(ws_read);

    {
        let mut handshake = Handshake {
            read: &mut ws_read,
            write: &mut ws_write,
            keys: &keys,
            salt: &mut salt,
            cfg,
            handler: &mut *handler,
        };
        if let Err(e) = handshake.key_exchange(&session_b64).await {
            bail!(e);
        }
        if let Err(e) = handshake.authenticate(&ctx.shared).await {
            bail!(e);
        }
        if cfg.receive_updates {
            if let Err(e) = handshake.enable_updates().await {
                bail!(e);
            }
        }
    }

    let connected_at = Instant::now();
    ctx.shared.set_state(ConnState::Connected);
    ctx.shared.metrics.mark_connected();
    if is_reconnect {
        ctx.shared
            .metrics
            .reconnects
            .fetch_add(1, Ordering::Relaxed);
        handler.lifecycle(ClientEvent::Reconnected);
    } else {
        ctx.shared.metrics.connects.fetch_add(1, Ordering::Relaxed);
        handler.lifecycle(ClientEvent::Connected);
    }
    if let Some(tx) = ready.take() {
        let _ = tx.send(Ok(()));
    }

    let pending = Arc::new(Mutex::new(PendingQueue::new()));
    let visu = Arc::new(Mutex::new(VisuQueue::new()));
    let liveness = Liveness::new();
    let (out_tx, out_rx) = mpsc::channel(WRITER_CHANNEL_DEPTH);

    let writer = Writer {
        ws: ws_write,
        keys: keys.clone(),
        salt,
        pending: Arc::clone(&pending),
        visu: Arc::clone(&visu),
        shared: Arc::clone(&ctx.shared),
        liveness: Arc::clone(&liveness),
        stopped: Arc::clone(&ctx.stopped),
        abort_reader: Some(abort_reader),
        cfg: WriterConfig {
            username: cfg.username.clone(),
            keepalive_period: Duration::from_secs(cfg.keepalive_secs),
            command_timeout: Duration::from_secs(cfg.command_timeout_secs),
            max_missed_keepalives: cfg.max_missed_keepalives,
            max_pending: cfg.max_pending_commands,
            kill_token_on_stop: cfg.kill_token_on_stop,
        },
    };
    let writer_task = tokio::spawn(writer.run(cmd_rx, out_rx));

    let refresher = tokio::spawn(run_refresher(
        cfg.username.clone(),
        Arc::clone(&ctx.shared),
        ctx.cmd_tx.clone(),
    ));

    let mut reader = Reader {
        shared: Arc::clone(&ctx.shared),
        keys,
        pending,
        visu,
        liveness,
        out_tx: out_tx.clone(),
        idle_timeout: Duration::from_secs(cfg.read_idle_timeout_secs),
    };
    let read_outcome = reader.run(&mut ws_read, handler).await;

    refresher.abort();
    let _ = out_tx.send(WriterMsg::Shutdown).await;
    drop(out_tx);

    let cmd_rx = match timeout(Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS), writer_task).await {
        Ok(Ok(rx)) => Some(rx),
        Ok(Err(e)) => {
            error!("writer task panicked: {e}");
            None
        }
        Err(_) => {
            error!("writer task did not finish in time; command channel lost");
            None
        }
    };

    let outcome = if ctx.stopped.load(Ordering::Relaxed) {
        SessionOutcome::Stopped
    } else {
        match read_outcome {
            ReadOutcome::Closed { close_code } => SessionOutcome::Disconnected { close_code },
            ReadOutcome::IdleTimeout => SessionOutcome::Failed(Error::Timeout(
                "no frame within the reader idle window".into(),
            )),
            ReadOutcome::Failed(e) => SessionOutcome::Failed(e),
        }
    };
    SessionResult {
        outcome,
        cmd_rx,
        connected_for: Some(connected_at.elapsed()),
    }
}
