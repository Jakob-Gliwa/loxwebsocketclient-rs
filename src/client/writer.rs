//! Writer task: the only owner of the WebSocket write half and the salt state.
//!
//! `fastwebsockets::WebSocketWrite::write_frame` performs a plain `write_all`,
//! so dropping it midway leaves half a frame on the wire. The `select!` arms
//! below therefore only decide *what* to send; the write itself is awaited
//! afterwards, outside the `select!`, where nothing can cancel it.

use crate::auth::{CMD_GET_KEY, build_token_hash, cmd_get_visu_salt, cmd_kill_token};
use crate::client::connect::{AbortHandle, WsWriteHalf};
use crate::client::io::IoCommand;
use crate::client::keepalive::SHUTDOWN_COMMAND_TIMEOUT_SECS;
use crate::client::pending::{PendingQueue, cmd_label};
use crate::client::state::{Liveness, SharedState};
use crate::client::visu::{VisuPending, VisuQueue};
use crate::crypto::{SaltState, SessionKeys};
use crate::error::{Error, Result};
use crate::sync::lock;
use bytes::Bytes;
use fastwebsockets::{Frame, OpCode, Payload, WebSocketWrite};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant, MissedTickBehavior, timeout};
use tracing::{debug, error, warn};

/// Budget for a single frame write before the session is abandoned.
///
/// A stalled peer that stops reading would otherwise park the writer forever
/// and with it the command channel the supervisor needs back.
const WRITE_TIMEOUT_SECS: u64 = 20;

/// Messages the reader (and the supervisor) send to the writer.
#[derive(Debug)]
pub(crate) enum WriterMsg {
    /// Control frame the read half is obligated to answer with (auto-close,
    /// auto-pong). The payload is owned because the frame borrowed the reader's
    /// buffer; control frames are at most 125 bytes.
    Obligated { opcode: OpCode, payload: Vec<u8> },
    /// Plaintext command to encrypt, register and send.
    Command {
        cmd: String,
        resp: Option<oneshot::Sender<Result<Bytes>>>,
    },
    /// Stop writing and let the reader see the end of the stream.
    Shutdown,
}

/// Everything the writer needs for one session.
pub(crate) struct WriterConfig {
    pub username: String,
    pub keepalive_period: Duration,
    pub command_timeout: Duration,
    pub max_missed_keepalives: u32,
    pub max_pending: usize,
}

impl std::fmt::Debug for WriterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriterConfig")
            .field("keepalive_period", &self.keepalive_period)
            .field("command_timeout", &self.command_timeout)
            .field("max_missed_keepalives", &self.max_missed_keepalives)
            .field("max_pending", &self.max_pending)
            .finish_non_exhaustive()
    }
}

/// What one loop iteration decided to put on the wire.
enum Outgoing {
    /// Already-encrypted or plaintext text frame.
    Text(String),
    Control {
        opcode: OpCode,
        payload: Vec<u8>,
    },
    /// Leave the loop; the session is over.
    Stop,
    /// Leave the loop after the graceful `killtoken` + close sequence.
    Close,
    /// Nothing to write this iteration.
    Idle,
}

pub(crate) struct Writer {
    pub ws: WebSocketWrite<WsWriteHalf>,
    pub keys: SessionKeys,
    pub salt: SaltState,
    pub pending: Arc<Mutex<PendingQueue>>,
    pub visu: Arc<Mutex<VisuQueue>>,
    pub shared: Arc<SharedState>,
    pub liveness: Arc<Liveness>,
    pub stopped: Arc<AtomicBool>,
    pub abort_reader: Option<AbortHandle>,
    pub cfg: WriterConfig,
}

impl std::fmt::Debug for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writer")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl Writer {
    /// Drive the write half until the session ends.
    ///
    /// `cmd_rx` is handed back so the supervisor can reuse the façade's command
    /// channel for the next session.
    pub async fn run(
        mut self,
        mut cmd_rx: mpsc::Receiver<IoCommand>,
        mut out_rx: mpsc::Receiver<WriterMsg>,
    ) -> mpsc::Receiver<IoCommand> {
        let mut keepalive = tokio::time::interval(self.cfg.keepalive_period);
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        keepalive.tick().await;

        loop {
            // Absolute instant, so re-arming it on every iteration cannot push
            // the deadline out — the trap the old refresh timer fell into.
            let expiry = self
                .next_expiry()
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));

            // Every arm is cancel-safe and only *decides* what to send.
            let outgoing = tokio::select! {
                biased;

                msg = out_rx.recv() => match msg {
                    Some(msg) => self.on_writer_msg(msg),
                    None => Outgoing::Stop,
                },

                cmd = cmd_rx.recv() => match cmd {
                    Some(IoCommand::Stop) | None => Outgoing::Close,
                    Some(cmd) => self.on_io_command(cmd),
                },

                _ = keepalive.tick() => self.on_keepalive_tick(),

                _ = tokio::time::sleep_until(expiry) => Outgoing::Idle,
            };

            match outgoing {
                Outgoing::Idle => {}
                Outgoing::Text(text) => {
                    if let Err(e) = self.write_text(&text).await {
                        self.shared
                            .metrics
                            .command_errors
                            .fetch_add(1, Ordering::Relaxed);
                        warn!("write failed, discarding session: {e}");
                        break;
                    }
                }
                Outgoing::Control { opcode, payload } => {
                    if let Err(e) = self.write_control(opcode, payload).await {
                        debug!("control frame not sent: {e}");
                        break;
                    }
                }
                Outgoing::Stop => break,
                Outgoing::Close => {
                    self.stopped.store(true, Ordering::Relaxed);
                    self.graceful_close().await;
                    break;
                }
            }

            self.expire_pending();
        }

        self.finish();
        cmd_rx
    }

    fn on_writer_msg(&mut self, msg: WriterMsg) -> Outgoing {
        match msg {
            WriterMsg::Obligated { opcode, payload } => Outgoing::Control { opcode, payload },
            WriterMsg::Command { cmd, resp } => self.prepare_command(cmd, resp),
            WriterMsg::Shutdown => Outgoing::Stop,
        }
    }

    fn on_io_command(&mut self, cmd: IoCommand) -> Outgoing {
        match cmd {
            IoCommand::Stop => Outgoing::Close,
            IoCommand::Encrypted { cmd, resp } => {
                self.shared
                    .metrics
                    .commands_sent
                    .fetch_add(1, Ordering::Relaxed);
                if lock(&self.pending).len() >= self.cfg.max_pending {
                    self.shared
                        .metrics
                        .command_errors
                        .fetch_add(1, Ordering::Relaxed);
                    let _ = resp.send(Err(Error::protocol(format!(
                        "too many commands in flight (max {})",
                        self.cfg.max_pending
                    ))));
                    return Outgoing::Idle;
                }
                self.prepare_command(cmd, Some(resp))
            }
            IoCommand::Control { uuid, value } => {
                self.shared
                    .metrics
                    .commands_sent
                    .fetch_add(1, Ordering::Relaxed);
                self.prepare_command(format!("jdev/sps/io/{uuid}/{value}"), None)
            }
            IoCommand::VisuControl {
                uuid,
                value,
                visu_pw,
            } => {
                self.shared
                    .metrics
                    .commands_sent
                    .fetch_add(1, Ordering::Relaxed);
                lock(&self.visu).push(VisuPending {
                    uuid,
                    value,
                    visu_pw,
                });
                // The reader recognises the answer by this exact command and
                // then drains the visu queue.
                self.prepare_command(cmd_get_visu_salt(&self.cfg.username), None)
            }
        }
    }

    fn on_keepalive_tick(&mut self) -> Outgoing {
        let missed = self.liveness.missed();
        if missed >= self.cfg.max_missed_keepalives as u64 {
            warn!("{missed} keepalives unanswered, discarding session");
            self.shared
                .metrics
                .keepalive_misses
                .fetch_add(missed, Ordering::Relaxed);
            return Outgoing::Stop;
        }
        self.liveness.record_sent();
        Outgoing::Text("keepalive".to_string())
    }

    /// Encrypt `cmd`, register its waiter and return the frame text.
    ///
    /// The waiter is pushed here — under the same lock, before the write — so
    /// the queue order can never disagree with the wire order.
    ///
    /// The encrypted text is stored alongside the plaintext. That is one copy
    /// of a few hundred bytes per outgoing command, and it buys the reader an
    /// AES round trip per incoming answer; see [`PendingQueue::resolve`].
    fn prepare_command(
        &mut self,
        cmd: String,
        resp: Option<oneshot::Sender<Result<Bytes>>>,
    ) -> Outgoing {
        match self.salt.encrypt(&self.keys, &cmd) {
            Ok(encrypted) => {
                let deadline = Instant::now() + self.cfg.command_timeout;
                lock(&self.pending).push(cmd, encrypted.clone(), resp, deadline);
                Outgoing::Text(encrypted)
            }
            Err(e) => {
                self.shared
                    .metrics
                    .command_errors
                    .fetch_add(1, Ordering::Relaxed);
                error!(command = cmd_label(&cmd), "encryption failed: {e}");
                if let Some(resp) = resp {
                    let _ = resp.send(Err(e));
                }
                Outgoing::Idle
            }
        }
    }

    /// Deadline of the oldest waiter, if any.
    fn next_expiry(&self) -> Option<Instant> {
        lock(&self.pending).next_deadline()
    }

    fn expire_pending(&self) {
        let expired = lock(&self.pending).expire(Instant::now());
        if expired > 0 {
            self.shared
                .metrics
                .command_timeouts
                .fetch_add(expired as u64, Ordering::Relaxed);
            warn!("{expired} command(s) timed out without a response");
        }
    }

    async fn write_text(&mut self, text: &str) -> Result<()> {
        let frame = Frame::new(true, OpCode::Text, None, Payload::Borrowed(text.as_bytes()));
        self.write_frame(frame).await
    }

    async fn write_control(&mut self, opcode: OpCode, payload: Vec<u8>) -> Result<()> {
        self.write_frame(Frame::new(true, opcode, None, Payload::Owned(payload)))
            .await
    }

    /// Write one frame, bounded by [`WRITE_TIMEOUT_SECS`].
    ///
    /// INVARIANT: this timeout is terminal, exactly like the reader's. A
    /// half-written frame desynchronises the peer, so once it fires the write
    /// half is never touched again and the caller abandons the session.
    async fn write_frame(&mut self, frame: Frame<'_>) -> Result<()> {
        timeout(
            Duration::from_secs(WRITE_TIMEOUT_SECS),
            self.ws.write_frame(frame),
        )
        .await
        .map_err(|_| Error::Timeout("socket write stalled".into()))?
        .map_err(|e| Error::ws(e.to_string()))
    }

    /// Best-effort `killtoken`, then the close frame.
    ///
    /// Killing the token keeps the Miniserver's token storage clean; the
    /// protocol document recommends it explicitly. Any failure here is logged
    /// and ignored — shutdown must not hang on an unresponsive Miniserver.
    async fn graceful_close(&mut self) {
        if let Err(e) = self.kill_token().await {
            debug!("killtoken skipped: {e}");
        }
        self.shared.clear_token();

        if let Err(e) = self.write_frame(Frame::close(1000, b"bye")).await {
            debug!("close frame not sent: {e}");
        }
        let _ = self.ws.flush().await;
    }

    async fn kill_token(&mut self) -> Result<()> {
        let token = self.shared.token();
        if token.is_empty() {
            return Ok(());
        }
        let short = Duration::from_secs(SHUTDOWN_COMMAND_TIMEOUT_SECS);
        let key_resp = self.request(CMD_GET_KEY.to_string(), short).await?;
        let hash = build_token_hash(&key_resp, &token)?;
        self.request(cmd_kill_token(&hash, &self.cfg.username), short)
            .await?;
        debug!("token killed on the Miniserver");
        Ok(())
    }

    /// Send a command and wait for its answer. Only used on the shutdown path,
    /// where the reader is still running and completes the waiter.
    async fn request(&mut self, cmd: String, wait: Duration) -> Result<Bytes> {
        let (tx, rx) = oneshot::channel();
        let label = cmd_label(&cmd).to_string();
        match self.prepare_command(cmd, Some(tx)) {
            Outgoing::Text(text) => self.write_text(&text).await?,
            _ => return Err(Error::protocol(format!("could not encrypt {label}"))),
        }
        timeout(wait, rx)
            .await
            .map_err(|_| Error::Timeout(label))?
            .map_err(|_| Error::ChannelClosed)?
    }

    fn finish(&mut self) {
        let dropped = lock(&self.pending).fail_all("session ended");
        if dropped > 0 {
            debug!("{dropped} command(s) dropped with the session");
        }
        lock(&self.visu).drain();
        // Unblock the reader: it cannot observe a shutdown request while parked
        // in `read_frame`, so the stream itself is made to fail.
        if let Some(abort) = self.abort_reader.take() {
            let _ = abort.send(());
        }
    }
}
