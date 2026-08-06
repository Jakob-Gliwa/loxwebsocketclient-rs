//! Reader loop: runs inline in the supervisor task and owns the handler.
//!
//! `read_frame` is not cancel-safe — it consumes the frame header out of the
//! persistent buffer *before* awaiting the payload, so a dropped future leaves
//! the parser permanently out of step with the stream. The loop therefore never
//! appears in a `select!`. Its only cancellation is the idle timeout, and that
//! one is terminal.

use crate::auth::{CMD_GET_VISUAL_PASSWD, parse_key_salt};
use crate::client::connect::AbortableRead;
use crate::client::handler::{HandlerGuard, LoxHandler};
use crate::client::keepalive::read_timeout;
use crate::client::pending::{PendingQueue, cmd_label, extract_ll_control};
use crate::client::state::{Liveness, SharedState};
use crate::client::visu::VisuQueue;
use crate::client::writer::WriterMsg;
use crate::crypto::{SessionKeys, hash_visu_password};
use crate::error::{Error, Result};
use crate::proto::{
    MessageType, parse_header, walk_daytimers, walk_texts, walk_values, walk_weather,
};
use crate::sync::lock;
use bytes::Bytes;
use fastwebsockets::{FragmentCollectorRead, Frame, OpCode};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use tracing::{debug, warn};

/// Why the reader stopped.
#[derive(Debug)]
pub(crate) enum ReadOutcome {
    /// A close frame arrived (or the Miniserver announced out-of-service).
    Closed { close_code: Option<u16> },
    /// Nothing was received within the idle window.
    IdleTimeout,
    /// The stream or the protocol broke.
    Failed(Error),
}

/// Loxone alternates an 8-byte header frame with the payload frame it describes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FrameExpect {
    /// `announced` carries the length an estimated header predicted, so the
    /// wait for the *exact* header is widened too — the Miniserver sends the
    /// estimate precisely when it still has to produce the data.
    Header {
        announced: u32,
    },
    Payload {
        msg_type: u8,
        len: u32,
    },
}

impl FrameExpect {
    const START: Self = Self::Header { announced: 0 };

    /// Payload length this state expects to have to wait for.
    fn announced_len(self) -> u32 {
        match self {
            Self::Header { announced } => announced,
            Self::Payload { len, .. } => len,
        }
    }
}

/// State the reader needs besides the stream and the handler.
pub(crate) struct Reader {
    pub shared: Arc<SharedState>,
    pub keys: SessionKeys,
    pub pending: Arc<Mutex<PendingQueue>>,
    pub visu: Arc<Mutex<VisuQueue>>,
    pub liveness: Arc<Liveness>,
    pub out_tx: mpsc::Sender<WriterMsg>,
    pub idle_timeout: Duration,
}

impl std::fmt::Debug for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reader")
            .field("idle_timeout", &self.idle_timeout)
            .finish_non_exhaustive()
    }
}

impl Reader {
    /// Read until the session ends.
    pub async fn run<H: LoxHandler>(
        &mut self,
        ws: &mut FragmentCollectorRead<AbortableRead>,
        handler: &mut HandlerGuard<H>,
    ) -> ReadOutcome {
        let mut expect = FrameExpect::START;

        // Built once: the reader must not allocate per frame. Loxone never
        // sends WebSocket pings (the Python reference disables autoping on
        // purpose), so in practice this only forwards the close echo. The
        // payload is copied because the frame borrows the reader's buffer;
        // control frames are at most 125 bytes.
        let obligated_tx = self.out_tx.clone();
        let mut send_fn = move |frame: Frame<'_>| {
            let tx = obligated_tx.clone();
            let msg = WriterMsg::Obligated {
                opcode: frame.opcode,
                payload: frame.payload.to_vec(),
            };
            async move { tx.send(msg).await.map_err(|_| Error::ChannelClosed) }
        };

        loop {
            // The announced payload length widens the window for the frame that
            // carries it, so a multi-megabyte table is not judged by the same
            // deadline as a keepalive answer.
            let deadline = read_timeout(self.idle_timeout, expect.announced_len());

            // INVARIANT: this timeout is the only cancellation the reader ever
            // performs, and it is terminal. `read_frame` consumes the frame
            // header before awaiting the payload, so a cancelled read desyncs
            // the parser for good. Once this fires the stream is dropped, never
            // read again. Do not turn this into a `select!` arm.
            let frame = match timeout(deadline, ws.read_frame(&mut send_fn)).await {
                Ok(Ok(frame)) => frame,
                Ok(Err(e)) => return ReadOutcome::Failed(Error::ws(e.to_string())),
                Err(_) => return ReadOutcome::IdleTimeout,
            };

            match frame.opcode {
                OpCode::Close => {
                    return ReadOutcome::Closed {
                        close_code: parse_close_code(&frame.payload),
                    };
                }
                OpCode::Text | OpCode::Binary => {
                    match self
                        .on_data_frame(&mut expect, &frame.payload, handler)
                        .await
                    {
                        Ok(Some(outcome)) => return outcome,
                        Ok(None) => {}
                        Err(e) => return ReadOutcome::Failed(e),
                    }
                }
                OpCode::Ping | OpCode::Pong | OpCode::Continuation => {}
            }
        }
    }

    async fn on_data_frame<H: LoxHandler>(
        &mut self,
        expect: &mut FrameExpect,
        payload: &[u8],
        handler: &mut HandlerGuard<H>,
    ) -> Result<Option<ReadOutcome>> {
        match *expect {
            FrameExpect::Header { .. } => match parse_header(payload) {
                Ok(Some(hdr)) if hdr.is_estimated() => {
                    // An exact header for the same message follows; the
                    // estimate is only useful as a lower bound on the wait.
                    debug!(len = hdr.payload_len(), "skipping estimated header");
                    *expect = FrameExpect::Header {
                        announced: hdr.payload_len(),
                    };
                }
                Ok(Some(hdr)) => {
                    if hdr.identifier == MessageType::OutOfService as u8 {
                        return Ok(Some(ReadOutcome::Closed {
                            close_code: Some(1012),
                        }));
                    }
                    let len = hdr.payload_len();
                    if len == 0 {
                        self.dispatch(hdr.identifier, &[], handler).await?;
                        *expect = FrameExpect::START;
                    } else {
                        *expect = FrameExpect::Payload {
                            msg_type: hdr.identifier,
                            len,
                        };
                    }
                }
                Ok(None) => warn!("expected header, got {} bytes", payload.len()),
                Err(e) => warn!("header parse error: {e}"),
            },
            FrameExpect::Payload { msg_type, len } => {
                if payload.len() as u32 != len {
                    debug!("payload len mismatch: got {} expected {len}", payload.len());
                }
                self.dispatch(msg_type, payload, handler).await?;
                *expect = FrameExpect::START;
            }
        }
        Ok(None)
    }

    async fn dispatch<H: LoxHandler>(
        &mut self,
        msg_type: u8,
        payload: &[u8],
        handler: &mut HandlerGuard<H>,
    ) -> Result<()> {
        self.shared.metrics.record_message(msg_type);

        // One guard for the whole message: `dispatch_event` turns a single
        // frame into thousands of per-record callbacks, so the unwind edge
        // belongs out here rather than around each one.
        let dispatched = handler.guard_or_fail("event dispatch", |h| {
            h.on_raw_payload(msg_type, payload);
            dispatch_event(msg_type, payload, h)
        })?;
        if dispatched {
            return Ok(());
        }

        match MessageType::from_u8(msg_type) {
            Some(MessageType::Text) => self.on_text_message(payload, handler).await?,
            Some(MessageType::Keepalive) => {
                if let Some(sent) = self.liveness.record_ack() {
                    self.shared
                        .metrics
                        .set_keepalive_rtt_ms(sent.elapsed().as_secs_f64() * 1000.0);
                }
                handler.guard_or_fail("on_keepalive", |h| h.on_keepalive())?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Correlate a type-0 answer with the command that asked for it.
    async fn on_text_message<H: LoxHandler>(
        &mut self,
        payload: &[u8],
        handler: &mut HandlerGuard<H>,
    ) -> Result<()> {
        // Cheap bounded scan instead of a DOM: `data/LoxAPP3.json` alone is
        // several megabytes and would otherwise be parsed on every arrival.
        // The value stays borrowed and encrypted here — the queue knows what it
        // sent and can usually settle the correlation by comparison alone.
        let control = extract_ll_control(payload);

        let resolved = {
            let mut queue = lock(&self.pending);
            let resolved = queue.resolve(control, &self.keys);
            if resolved.is_none() {
                queue.note_unsolicited();
            }
            resolved
        };
        let Some(resolved) = resolved else {
            // No waiter: an unsolicited push, e.g. a status message as JSON.
            self.shared
                .metrics
                .unsolicited_responses
                .fetch_add(1, Ordering::Relaxed);
            handler.guard_or_fail("on_json", |h| h.on_json(payload))?;
            return Ok(());
        };

        if !resolved.matched {
            self.shared
                .metrics
                .correlation_mismatches
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                expected = cmd_label(&resolved.plaintext_cmd),
                actual = resolved.actual.as_deref().map(cmd_label).unwrap_or("?"),
                "response did not match the waiting command"
            );
        }

        // Only a correlated getvisusalt answer may be parsed for key material —
        // getkey2 returns the same shape and must not feed the visu hash.
        if resolved.plaintext_cmd.starts_with(CMD_GET_VISUAL_PASSWD) && !lock(&self.visu).is_empty()
        {
            self.flush_visu(payload).await;
        }

        if let Some(resp) = resolved.resp {
            let _ = resp.send(Ok(Bytes::copy_from_slice(payload)));
        }
        Ok(())
    }

    /// Turn a `getvisusalt` answer into the queued secured commands.
    async fn flush_visu(&mut self, payload: &[u8]) {
        let key_salt = match parse_key_salt(payload) {
            Ok(ks) => ks,
            Err(e) => {
                warn!("getvisusalt response unusable: {e}");
                lock(&self.visu).drain();
                return;
            }
        };
        let items = lock(&self.visu).drain();
        for item in items {
            match hash_visu_password(&key_salt, &item.visu_pw) {
                Ok(hash) => {
                    let cmd = format!("jdev/sps/ios/{}/{}/{}", hash, item.uuid, item.value);
                    if self
                        .out_tx
                        .send(WriterMsg::Command { cmd, resp: None })
                        .await
                        .is_err()
                    {
                        debug!("writer gone, dropping secured command");
                        return;
                    }
                }
                Err(e) => warn!("visu password hashing failed: {e}"),
            }
        }
    }
}

/// Hand an event-table payload to the handler.
///
/// Returns `false` for message types that are not events — those need session
/// state the handshake does not have yet, which is exactly why this part is
/// split out: [`Handshake::read_payload`] reuses it so a Miniserver that pushes
/// its first tables before acknowledging `enablebinstatusupdate` does not lose
/// them.
///
/// [`Handshake::read_payload`]: crate::client::handshake::Handshake
pub(crate) fn dispatch_event<H: LoxHandler>(msg_type: u8, payload: &[u8], handler: &mut H) -> bool {
    match MessageType::from_u8(msg_type) {
        Some(MessageType::BinaryFile) => handler.on_binary(payload),
        Some(MessageType::ValueStates) => {
            walk_values(payload, |uuid, value| handler.on_value(uuid, value));
        }
        Some(MessageType::TextStates) => {
            walk_texts(payload, |uuid, icon, text| {
                handler.on_text(uuid, icon, text)
            });
        }
        Some(MessageType::DaytimerStates) => {
            walk_daytimers(payload, |ev| handler.on_daytimer(ev));
        }
        Some(MessageType::WeatherStates) => {
            walk_weather(payload, |ev| handler.on_weather(ev));
        }
        _ => return false,
    }
    true
}

fn parse_close_code(payload: &[u8]) -> Option<u16> {
    if payload.len() >= 2 {
        Some(u16::from_be_bytes([payload[0], payload[1]]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announced_length_carries_through_the_frame_states() {
        assert_eq!(FrameExpect::START.announced_len(), 0);
        assert_eq!(
            FrameExpect::Header { announced: 4096 }.announced_len(),
            4096
        );
        assert_eq!(
            FrameExpect::Payload {
                msg_type: 2,
                len: 96
            }
            .announced_len(),
            96
        );
    }

    #[test]
    fn close_code_needs_two_bytes() {
        assert_eq!(parse_close_code(&[]), None);
        assert_eq!(parse_close_code(&[0x0f]), None);
        assert_eq!(parse_close_code(&1000u16.to_be_bytes()), Some(1000));
        assert_eq!(
            parse_close_code(&[0x0f, 0xa8, b'b', b'y', b'e']),
            Some(4008)
        );
    }
}
