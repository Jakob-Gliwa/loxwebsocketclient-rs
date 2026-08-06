//! TCP/TLS + fastwebsockets handshake (`remotecontrol` subprotocol).

use crate::client::tls::TlsContext;
use crate::error::{Error, Result};
use fastwebsockets::WebSocket;
use fastwebsockets::handshake;
use http_body_util::Empty;
use hyper::Request;
use hyper::body::Bytes;
use hyper::header::{CONNECTION, UPGRADE};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use std::cell::Cell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use url::Url;

/// WebSocket stream type after hyper upgrade.
pub type WsStream = TokioIo<Upgraded>;

/// Write half produced by [`tokio::io::split`] on a [`WsStream`].
pub type WsWriteHalf = tokio::io::WriteHalf<WsStream>;

/// Read half that can be forced to end from another task.
///
/// The reader never selects over its `read_frame` future — doing so corrupts
/// the frame parser's buffer — so it cannot observe a shutdown request while
/// waiting for data. This wrapper turns such a request into an I/O error at the
/// stream level instead, which the frame parser reports as a normal read
/// failure and the reader loop treats as the end of the session. Because the
/// read future is still polled to completion, the cancel-safety invariant is
/// untouched.
#[derive(Debug)]
pub struct AbortableRead {
    inner: tokio::io::ReadHalf<WsStream>,
    abort: oneshot::Receiver<()>,
    aborted: bool,
}

/// Sending on this handle makes the paired [`AbortableRead`] fail its next poll.
pub type AbortHandle = oneshot::Sender<()>;

impl AbortableRead {
    fn new(inner: tokio::io::ReadHalf<WsStream>, abort: oneshot::Receiver<()>) -> Self {
        Self {
            inner,
            abort,
            aborted: false,
        }
    }
}

impl AsyncRead for AbortableRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.aborted && Pin::new(&mut this.abort).poll(cx).is_ready() {
            this.aborted = true;
        }
        if this.aborted {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "read half aborted by the writer",
            )));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

/// Split a WebSocket into an abortable read half and a write half.
///
/// Must happen before the Loxone handshake: a `FragmentCollector` only hands
/// back the raw stream, so splitting later would discard whatever the frame
/// parser has already buffered — after `enablebinstatusupdate` that is a full
/// event table.
pub fn split_ws(
    ws: WebSocket<WsStream>,
) -> (
    fastwebsockets::WebSocketRead<AbortableRead>,
    fastwebsockets::WebSocketWrite<WsWriteHalf>,
    AbortHandle,
) {
    let (abort_tx, abort_rx) = oneshot::channel();
    // `split` takes an `Fn`, so the receiver is handed over through a cell.
    let slot = Cell::new(Some(abort_rx));
    let (read, write) = ws.split(move |stream| {
        let (r, w) = tokio::io::split(stream);
        let abort = slot.take().expect("split_fn is called exactly once");
        (AbortableRead::new(r, abort), w)
    });
    (read, write, abort_tx)
}

struct SpawnExecutor;

impl<Fut> hyper::rt::Executor<Fut> for SpawnExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        tokio::task::spawn(fut);
    }
}

/// Parsed connection endpoints derived from an HTTP(S) base URL.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// Scheme + authority without trailing slash, e.g. `https://ms.example:4523`.
    pub http_base: String,
    /// `ws(s)://{host}:{port}/ws/rfc6455`.
    pub ws_url: String,
    pub host: String,
    pub port: u16,
    pub use_tls: bool,
}

impl Endpoints {
    /// Derive endpoints from a Miniserver URL; a bare host defaults to `http`.
    pub fn from_loxone_url(loxone_url: &str) -> Result<Self> {
        let mut url_str = loxone_url.trim().to_string();
        if !url_str.starts_with("http://") && !url_str.starts_with("https://") {
            url_str = format!("http://{url_str}");
        }
        let url = Url::parse(&url_str).map_err(|e| Error::protocol(e.to_string()))?;
        let host = url
            .host_str()
            .ok_or_else(|| Error::protocol("URL missing host"))?
            .to_string();
        let use_tls = url.scheme() == "https";
        let port = url.port().unwrap_or(if use_tls { 443 } else { 80 });
        let http_base = {
            let mut u = url.clone();
            u.set_path("");
            u.set_query(None);
            u.set_fragment(None);
            let s = u.to_string();
            s.trim_end_matches('/').to_string()
        };
        let ws_scheme = if use_tls { "wss" } else { "ws" };
        let ws_url = format!("{ws_scheme}://{host}:{port}/ws/rfc6455");
        Ok(Self {
            http_base,
            ws_url,
            host,
            port,
            use_tls,
        })
    }
}

/// Open a WebSocket to the Miniserver with `Sec-WebSocket-Protocol: remotecontrol`.
///
/// Returns the unsplit [`WebSocket`] so the caller can decide how to split it.
/// Splitting must happen before any Loxone frame is read: a
/// `FragmentCollector` can only surrender the raw stream, which would discard
/// everything already sitting in its read buffer.
pub async fn ws_connect(endpoints: &Endpoints, tls: &TlsContext) -> Result<WebSocket<WsStream>> {
    let addr = format!("{}:{}", endpoints.host, endpoints.port);
    let tcp = TcpStream::connect(&addr)
        .await
        .map_err(|e| Error::ws(format!("TCP connect {addr}: {e}")))?;
    tcp.set_nodelay(true).ok();

    // Path-only request-target. Absolute-form (`GET http://host/...`) makes many
    // Miniserver HTTP stacks answer 400 Bad Request.
    let host_header = if (!endpoints.use_tls && endpoints.port == 80)
        || (endpoints.use_tls && endpoints.port == 443)
    {
        endpoints.host.clone()
    } else {
        format!("{}:{}", endpoints.host, endpoints.port)
    };

    let req = Request::builder()
        .method("GET")
        .uri("/ws/rfc6455")
        .header("Host", host_header)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "Upgrade")
        .header("Sec-WebSocket-Key", handshake::generate_key())
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Protocol", "remotecontrol")
        .body(Empty::<Bytes>::new())
        .map_err(|e| Error::ws(e.to_string()))?;

    let (ws, _resp) = if endpoints.use_tls {
        let server_name = ServerName::try_from(endpoints.host.clone())
            .map_err(|e| Error::ws(format!("invalid server name: {e}")))?;
        let stream = tls
            .connector()
            .connect(server_name, tcp)
            .await
            .map_err(|e| Error::Tls(format!("TLS handshake: {e}")))?;
        handshake::client(&SpawnExecutor, req, stream)
            .await
            .map_err(|e| Error::ws(format!("WS handshake: {e}")))?
    } else {
        handshake::client(&SpawnExecutor, req, tcp)
            .await
            .map_err(|e| Error::ws(format!("WS handshake: {e}")))?
    };

    Ok(configure_ws(ws))
}

fn configure_ws(mut ws: WebSocket<WsStream>) -> WebSocket<WsStream> {
    // These flags migrate into the read/write halves on `WebSocket::split`.
    ws.set_auto_close(true);
    ws.set_auto_pong(true);
    ws.set_writev(true);
    ws
}
