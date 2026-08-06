//! Loxone handshake, run sequentially on the already-split halves.
//!
//! Splitting happens before this point, so the frame parser's buffer stays with
//! the reader for the whole connection. Until the handshake is done there is no
//! writer task yet, which is why request/response here is a plain
//! send-then-read rather than a correlated queue.

use crate::auth::{
    CMD_ENABLE_UPDATES, CMD_GET_KEY, CMD_KEY_EXCHANGE, LxToken, apply_valid_until,
    build_acquire_token_cmd, build_token_hash, cmd_auth_with_token, cmd_check_token, cmd_getkey2,
    cmd_kill_token, ll_status_error, ll_status_invalidates_token, parse_json, parse_token_response,
    payload_ll_status, require_ll_ok,
};
use crate::client::ConnectConfig;
use crate::client::connect::{AbortableRead, WsWriteHalf};
use crate::client::handler::{HandlerGuard, LoxHandler};
use crate::client::pending::cmd_label;
use crate::client::reader::dispatch_event;
use crate::client::state::SharedState;
use crate::crypto::{SaltState, SessionKeys};
use crate::error::{Error, Result};
use crate::proto::{MessageType, WsBinHdr, parse_header};
use bytes::Bytes;
use fastwebsockets::{FragmentCollectorRead, Frame, OpCode, Payload, WebSocketWrite};
use tokio::time::{Duration, timeout};
use tracing::{debug, warn};

/// A token with less remaining lifetime than this is replaced instead of reused.
const TOKEN_MIN_REMAINING_SECS: i64 = 300;

/// Event tables tolerated between a handshake command and its answer.
///
/// Together with the per-frame timeout this bounds the interleaving loop: the
/// timeout guarantees progress, this guarantees the progress goes somewhere.
/// The realistic worst case is the four table types arriving once each, so the
/// budget only has to rule out a Miniserver that never answers at all.
const MAX_INTERLEAVED_FRAMES: usize = 64;

/// Sequential request/response over the split halves.
pub(crate) struct Handshake<'a, H> {
    pub read: &'a mut FragmentCollectorRead<AbortableRead>,
    pub write: &'a mut WebSocketWrite<WsWriteHalf>,
    pub keys: &'a SessionKeys,
    pub salt: &'a mut SaltState,
    pub cfg: &'a ConnectConfig,
    /// Only used for event tables that overtake a handshake answer; see
    /// [`Handshake::read_payload`].
    pub handler: &'a mut HandlerGuard<H>,
}

impl<H> std::fmt::Debug for Handshake<'_, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handshake").finish_non_exhaustive()
    }
}

impl<H: LoxHandler> Handshake<'_, H> {
    fn command_timeout(&self) -> Duration {
        Duration::from_secs(self.cfg.command_timeout_secs)
    }

    /// `jdev/sys/keyexchange/{base64}` — raw Base64, never URI-encoded.
    pub async fn key_exchange(&mut self, session_b64: &str) -> Result<()> {
        self.send_text(&format!("{CMD_KEY_EXCHANGE}{session_b64}"))
            .await?;
        let resp = self.read_payload(self.command_timeout()).await?;
        let root = parse_json(&resp)?;
        require_ll_ok(&root)?;
        debug!("session key accepted");
        Ok(())
    }

    /// Authenticate the connection, reusing the in-memory token when possible.
    pub async fn authenticate(&mut self, shared: &SharedState) -> Result<()> {
        let existing = shared.token();
        if !existing.is_empty() {
            if existing.seconds_to_expire() < TOKEN_MIN_REMAINING_SECS {
                debug!("token too close to expiry, replacing it");
                let token = self.acquire_token(Some(&existing)).await?;
                shared.set_token(token);
                return Ok(());
            }
            match self.reuse_token(&existing).await? {
                Some(token) => {
                    shared.set_token(token);
                    debug!("authenticated with the existing token");
                    return Ok(());
                }
                None => {
                    warn!("Miniserver rejected the stored token, acquiring a new one");
                    shared.clear_token();
                }
            }
        }
        let token = self.acquire_token(None).await?;
        shared.set_token(token);
        Ok(())
    }

    /// Subscribe to live status updates.
    pub async fn enable_updates(&mut self) -> Result<()> {
        let resp = self.request(CMD_ENABLE_UPDATES).await?;
        // The answer is the current update counter, not an LL envelope on every
        // firmware, so only an explicit error status is treated as failure.
        if let Some(code) = payload_ll_status(&resp) {
            if code != "200" {
                return Err(ll_status_error(&code).in_step("enablebinstatusupdate"));
            }
        }
        Ok(())
    }

    /// Validate and then use the stored token.
    ///
    /// `Ok(None)` means the Miniserver refused the token and a fresh one has to
    /// be acquired; `Err` means the exchange itself failed and the session
    /// should be discarded.
    async fn reuse_token(&mut self, token: &LxToken) -> Result<Option<LxToken>> {
        let key_resp = self.request(CMD_GET_KEY).await?;
        let hash = build_token_hash(&key_resp, token)?;

        // checktoken is the cheap way to learn whether authwithtoken can work
        // at all; a rejection here saves a doomed authentication round trip.
        let check = self
            .request(&cmd_check_token(&hash, &self.cfg.username))
            .await?;
        match classify(&check) {
            LlOutcome::Ok => {}
            LlOutcome::TokenRejected => return Ok(None),
            LlOutcome::Failed(e) => return Err(e),
        }

        let auth = self
            .request(&cmd_auth_with_token(&hash, &self.cfg.username))
            .await?;
        match classify(&auth) {
            LlOutcome::Ok => {
                let mut token = token.clone();
                apply_valid_until(&mut token, &auth)?;
                Ok(Some(token))
            }
            LlOutcome::TokenRejected => Ok(None),
            LlOutcome::Failed(e) => Err(e),
        }
    }

    /// Acquire a fresh token, killing `displaced` first when there is one.
    async fn acquire_token(&mut self, displaced: Option<&LxToken>) -> Result<LxToken> {
        if let Some(old) = displaced {
            if let Err(e) = self.kill_token(old).await {
                debug!("could not kill the displaced token: {e}");
            }
        }

        let getkey2 = self
            .request(&cmd_getkey2(&self.cfg.username))
            .await
            .map_err(|e| e.in_step("getkey2"))?;
        let (cmd, alg) = build_acquire_token_cmd(
            &getkey2,
            &self.cfg.username,
            &self.cfg.password,
            self.cfg.token_permission,
            &self.cfg.client_uuid,
            &self.cfg.client_info,
        )
        .map_err(|e| e.in_step("getkey2"))?;
        debug!(
            alg = alg.as_str(),
            permission = %self.cfg.token_permission,
            command = cmd_label(&cmd),
            "requesting token"
        );
        let resp = self
            .request(&cmd)
            .await
            .map_err(|e| e.in_step(cmd_label(&cmd)))?;
        let token = parse_token_response(&resp, alg)?;
        if token.token.is_empty() {
            return Err(Error::auth("acquire_token: empty token"));
        }
        Ok(token)
    }

    async fn kill_token(&mut self, token: &LxToken) -> Result<()> {
        let key_resp = self.request(CMD_GET_KEY).await?;
        let hash = build_token_hash(&key_resp, token)?;
        self.request(&cmd_kill_token(&hash, &self.cfg.username))
            .await?;
        Ok(())
    }

    /// Encrypted request/response with the configured command timeout.
    async fn request(&mut self, cmd: &str) -> Result<Bytes> {
        let encrypted = self.salt.encrypt(self.keys, cmd)?;
        self.send_text(&encrypted).await?;
        let resp = self.read_payload(self.command_timeout()).await?;
        if tracing::enabled!(tracing::Level::TRACE) {
            // Never log LL.value: getkey2/getvisusalt carry the user key + salt.
            tracing::trace!(
                command = cmd_label(cmd),
                code = payload_ll_status(&resp).as_deref().unwrap_or("?"),
                bytes = resp.len(),
                "handshake response"
            );
        }
        Ok(resp)
    }

    async fn send_text(&mut self, text: &str) -> Result<()> {
        let frame = Frame::new(true, OpCode::Text, None, Payload::Borrowed(text.as_bytes()));
        self.write
            .write_frame(frame)
            .await
            .map_err(|e| Error::ws(e.to_string()))
    }

    /// Read the next text answer: the 8-byte header frame plus its payload.
    ///
    /// Everything that is not a type-0 answer is passed over. Event tables are
    /// forwarded to the handler rather than dropped: `enablebinstatusupdate`
    /// makes the Miniserver start pushing, and on some firmwares the first
    /// tables arrive before the acknowledgement does. Those tables are the
    /// current state of every control, so losing them would leave the caller
    /// with stale values until each one next changes on its own.
    ///
    /// The handler therefore sees a handful of events before
    /// [`ClientEvent::Connected`]; that is documented on [`LoxHandler`].
    ///
    /// [`ClientEvent::Connected`]: crate::ClientEvent::Connected
    async fn read_payload(&mut self, wait: Duration) -> Result<Bytes> {
        for _ in 0..MAX_INTERLEAVED_FRAMES {
            let hdr = self.read_header(wait).await?;
            if hdr.is_estimated() {
                // An exact header for the same message follows.
                continue;
            }
            if hdr.identifier == MessageType::OutOfService as u8 {
                return Err(Error::Closed("out of service".into()));
            }
            let payload = if hdr.payload_len() == 0 {
                Bytes::new()
            } else {
                self.read_frame_bytes(wait).await?
            };
            if hdr.identifier == MessageType::Text as u8 {
                self.handler.guard_or_fail("on_raw_payload", |h| {
                    h.on_raw_payload(hdr.identifier, &payload)
                })?;
                return Ok(payload);
            }
            let dispatched = self.handler.guard_or_fail("event dispatch", |h| {
                h.on_raw_payload(hdr.identifier, &payload);
                dispatch_event(hdr.identifier, &payload, h)
            })?;
            if !dispatched {
                debug!(
                    identifier = hdr.identifier,
                    "ignoring non-event message while waiting for a handshake answer"
                );
            }
        }
        Err(Error::protocol(
            "no handshake answer within the interleaved frame budget",
        ))
    }

    async fn read_header(&mut self, wait: Duration) -> Result<WsBinHdr> {
        let bytes = self.read_frame_bytes(wait).await?;
        parse_header(&bytes)?.ok_or_else(|| {
            Error::protocol(format!("expected 8-byte header, got {} bytes", bytes.len()))
        })
    }

    async fn read_frame_bytes(&mut self, wait: Duration) -> Result<Bytes> {
        // Loxone never sends WebSocket pings — the Python reference disables
        // autoping on purpose — and a close during the handshake ends the
        // session anyway, so the obligated-send channel stays empty here.
        let mut no_reply = |_frame: Frame<'_>| async { Ok::<(), Error>(()) };
        let frame = timeout(wait, self.read.read_frame(&mut no_reply))
            .await
            .map_err(|_| Error::Timeout("handshake response".into()))?
            .map_err(|e| Error::ws(e.to_string()))?;
        if frame.opcode == OpCode::Close {
            return Err(Error::Closed("closed during handshake".into()));
        }
        Ok(Bytes::copy_from_slice(&frame.payload))
    }
}

enum LlOutcome {
    Ok,
    TokenRejected,
    Failed(Error),
}

fn classify(payload: &[u8]) -> LlOutcome {
    match payload_ll_status(payload) {
        Some(code) if code == "200" => LlOutcome::Ok,
        Some(code) if ll_status_invalidates_token(&code) => LlOutcome::TokenRejected,
        Some(code) => LlOutcome::Failed(ll_status_error(&code)),
        None => LlOutcome::Failed(Error::protocol("response is not an LL envelope")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_classification_drives_the_token_policy() {
        assert!(matches!(
            classify(br#"{"LL":{"code":"200","value":{}}}"#),
            LlOutcome::Ok
        ));
        for code in ["401", "403"] {
            let body = format!(r#"{{"LL":{{"code":"{code}"}}}}"#);
            assert!(
                matches!(classify(body.as_bytes()), LlOutcome::TokenRejected),
                "{code} should invalidate the token"
            );
        }
        for code in ["500", "503"] {
            let body = format!(r#"{{"LL":{{"code":"{code}"}}}}"#);
            assert!(
                matches!(classify(body.as_bytes()), LlOutcome::Failed(_)),
                "{code} should not invalidate the token"
            );
        }
        assert!(matches!(classify(b"garbage"), LlOutcome::Failed(_)));
    }

    /// A `checktoken` refused with 901 must keep the token: the Miniserver is
    /// out of connection slots, which says nothing about the credential, and
    /// re-authenticating would need the very connection it just refused.
    #[test]
    fn the_connection_limit_does_not_cost_the_token() {
        let refused = classify(br#"{"LL":{"code":"901"}}"#);
        assert!(matches!(
            refused,
            LlOutcome::Failed(Error::TooManyConnections)
        ));
    }
}
