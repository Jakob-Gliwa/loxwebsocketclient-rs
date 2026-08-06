//! Error types for the Loxone WebSocket client.

use thiserror::Error;

/// Result alias for crate operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by `loxwebsocket`.
#[derive(Debug, Error)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("HTTP status {status}: {message}")]
    HttpStatus { status: u16, message: String },

    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("TLS error: {0}")]
    Tls(String),

    /// The certificate presented (or announced via `jdev/sys/getcertificate`)
    /// does not match the pinned `SubjectPublicKeyInfo` fingerprint.
    #[error("certificate pin mismatch: expected SPKI {expected}, got {actual}")]
    TlsPinMismatch {
        /// Hex-encoded SHA-256 of the pinned SPKI.
        expected: String,
        /// Hex-encoded SHA-256 of the SPKI actually presented.
        actual: String,
    },

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("encryption error: {0}")]
    Crypto(String),

    #[error("JSON error: {0}")]
    Json(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("connection closed: {0}")]
    Closed(String),

    #[error("reconnect failed after {attempts} attempts")]
    ReconnectExhausted { attempts: u32 },

    /// All 31 event slots of the Miniserver are taken; live status updates are
    /// unavailable until another client disconnects. Warrants a long backoff
    /// rather than an immediate retry.
    #[error("Miniserver has no free event slots")]
    NoEventSlots,

    /// The Miniserver is already serving as many concurrent connections as it
    /// can (`LL` status 901). Transient and unrelated to the token, so the
    /// client backs off instead of re-authenticating.
    #[error("Miniserver has reached its connection limit")]
    TooManyConnections,

    /// The user this client authenticates as has been disabled on the
    /// Miniserver (`LL` status 423, close code 4006). Only an administrator
    /// can undo that, so reconnecting cannot help.
    #[error("the Miniserver has disabled this user")]
    UserDisabled,

    /// The Miniserver reports this connection as remote while the client was
    /// configured for local-only operation. Retrying cannot change that.
    #[error("connection is not local")]
    NotLocal,

    #[error("client stopped")]
    Stopped,

    #[error("invalid UUID: {0}")]
    InvalidUuid(String),

    #[error("command channel closed")]
    ChannelClosed,
}

impl Error {
    pub(crate) fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    pub(crate) fn auth(msg: impl Into<String>) -> Self {
        Self::Auth(msg.into())
    }

    pub(crate) fn crypto(msg: impl Into<String>) -> Self {
        Self::Crypto(msg.into())
    }

    pub(crate) fn ws(msg: impl Into<String>) -> Self {
        Self::WebSocket(msg.into())
    }

    pub(crate) fn http(msg: impl Into<String>) -> Self {
        Self::Http(msg.into())
    }

    pub(crate) fn json(msg: impl Into<String>) -> Self {
        Self::Json(msg.into())
    }

    /// Whether no amount of reconnecting can change this condition.
    ///
    /// The supervisor gives up and reports [`ClientEvent::Closed`] instead of
    /// entering a retry loop that is guaranteed to fail.
    ///
    /// [`ClientEvent::Closed`]: crate::ClientEvent::Closed
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::NotLocal | Self::UserDisabled)
    }

    /// Whether this condition needs minutes rather than seconds to clear.
    ///
    /// Both variants say the Miniserver is at a capacity limit; retrying at the
    /// normal connect delay only adds to the load that caused them.
    pub fn needs_long_backoff(&self) -> bool {
        matches!(self, Self::NoEventSlots | Self::TooManyConnections)
    }

    /// Prefix the message with the handshake step that produced it.
    ///
    /// Variants the supervisor dispatches on pass through unchanged — folding
    /// them into [`Error::Auth`] would cost the classification that decides
    /// between a retry, a long backoff and giving up.
    pub(crate) fn in_step(self, step: &str) -> Self {
        if self.is_terminal() || self.needs_long_backoff() {
            return self;
        }
        Self::Auth(format!("{step}: {self}"))
    }
}
