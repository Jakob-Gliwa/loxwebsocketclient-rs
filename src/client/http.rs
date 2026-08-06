//! Cold-path HTTP requests over the shared hyper / tokio-rustls stack.
//!
//! Only a handful of `GET`s ever go through here — the public key, the
//! certificate chain and the reachability probe — but they must not pull in a
//! second HTTP client or a second rustls crypto provider, so they reuse the
//! [`TlsContext`] that also backs the WebSocket connection.

use crate::auth::ll_status_code;
use crate::client::connect::Endpoints;
use crate::client::tls::{TlsContext, spki_sha256_from_pem_chain};
use crate::crypto::normalize_public_key_pem;
use crate::error::{Error, Result};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper::header::{AUTHORIZATION, HOST};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use sonic_rs::{JsonValueTrait, Value};
use tokio::net::TcpStream;
use tokio::time::Duration;
use tracing::debug;

pub const CMD_GET_PUBLIC_KEY: &str = "jdev/sys/getPublicKey";
pub const CMD_GET_CERTIFICATE: &str = "jdev/sys/getcertificate";
pub const CMD_API_KEY: &str = "jdev/cfg/apiKey";
pub const CMD_API: &str = "jdev/cfg/api";

pub const TIMEOUT_SECS: u64 = 30;
/// Reachability probes must fail fast; they gate the reconnect loop.
pub const REACHABILITY_TIMEOUT_SECS: u64 = 3;

/// Miniserver facts from `jdev/cfg/apiKey` and `jdev/cfg/api`.
///
/// Every field is optional: which attributes are present depends on the
/// firmware generation (`local` exists since 12.1, `httpsStatus` only on
/// second-generation Miniservers).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApiInfo {
    /// Serial number / MAC address, e.g. `504F94A0B1C2`.
    pub snr: Option<String>,
    /// Firmware version, e.g. `15.2.11.4`.
    pub version: Option<String>,
    /// `1` = TLS available, `2` = certificate present but expired.
    pub https_status: Option<u8>,
    /// Whether the Miniserver considers this connection local.
    pub local: Option<bool>,
    /// Whether one of the 31 live-update slots is still free.
    pub has_event_slots: Option<bool>,
}

impl ApiInfo {
    /// Take every field this instance is still missing from `other`.
    pub fn fill_from(&mut self, other: ApiInfo) {
        self.snr = self.snr.take().or(other.snr);
        self.version = self.version.take().or(other.version);
        self.https_status = self.https_status.or(other.https_status);
        self.local = self.local.or(other.local);
        self.has_event_slots = self.has_event_slots.or(other.has_event_slots);
    }

    fn from_value(v: &Value) -> Self {
        Self {
            snr: string_field(v, "snr"),
            version: string_field(v, "version"),
            https_status: u8_field(v, "httpsStatus"),
            local: bool_field(v, "local"),
            has_event_slots: bool_field(v, "hasEventSlots"),
        }
    }
}

/// Issues the cold-path `GET`s against one Miniserver.
///
/// Holds no connection pool: every request opens a fresh connection, but the
/// TLS configuration behind [`TlsContext`] is built once and shared.
#[derive(Debug, Clone)]
pub struct HttpClient {
    host: String,
    port: u16,
    use_tls: bool,
    authority: String,
    tls: TlsContext,
}

impl HttpClient {
    /// Bind the cold-path client to `endpoints` using `tls` for HTTPS.
    pub fn new(endpoints: &Endpoints, tls: TlsContext) -> Self {
        let default_port = if endpoints.use_tls { 443 } else { 80 };
        let authority = if endpoints.port == default_port {
            endpoints.host.clone()
        } else {
            format!("{}:{}", endpoints.host, endpoints.port)
        };
        Self {
            host: endpoints.host.clone(),
            port: endpoints.port,
            use_tls: endpoints.use_tls,
            authority,
            tls,
        }
    }

    /// Fetch and normalize the Miniserver RSA public key via HTTP Basic Auth.
    pub async fn get_public_key(&self, username: &str, password: &str) -> Result<String> {
        let body = self
            .get_ll(CMD_GET_PUBLIC_KEY, Some((username, password)), TIMEOUT_SECS)
            .await?;
        let root = parse_json(&body)?;
        let ll = root
            .get("LL")
            .ok_or_else(|| Error::protocol("getPublicKey missing LL"))?;
        let public_key = ll
            .get("value")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::protocol("getPublicKey missing LL.value"))?;
        if public_key.is_empty() {
            return Err(Error::protocol("public key is empty"));
        }
        Ok(normalize_public_key_pem(public_key))
    }

    /// Fetch the PEM certificate chain from `jdev/sys/getcertificate`.
    pub async fn get_certificate(&self, username: &str, password: &str) -> Result<String> {
        let body = self
            .get_ll(
                CMD_GET_CERTIFICATE,
                Some((username, password)),
                TIMEOUT_SECS,
            )
            .await?;
        let root = parse_json(&body)?;
        let chain = root
            .get("LL")
            .and_then(|ll| ll.get("value"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::protocol("getcertificate missing LL.value"))?;
        if !chain.contains("BEGIN CERTIFICATE") {
            return Err(Error::protocol("getcertificate returned no PEM block"));
        }
        Ok(chain.to_string())
    }

    /// Learn or confirm the SPKI pin from `jdev/sys/getcertificate`.
    ///
    /// Returns [`Error::TlsPinMismatch`] when the announced leaf key differs
    /// from an already enforced pin. Note that in [`crate::client::TlsMode::PinOnFirstUse`]
    /// this request itself may run over the very connection whose certificate
    /// is being pinned — see the [TLS module docs](crate::client::tls) for the
    /// resulting trust-on-first-use caveat.
    pub async fn bootstrap_pin(&self, username: &str, password: &str) -> Result<[u8; 32]> {
        let pem = self.get_certificate(username, password).await?;
        let spki = spki_sha256_from_pem_chain(&pem)?;
        self.tls.adopt_spki(spki)?;
        Ok(spki)
    }

    /// Reachability probe: merged `jdev/cfg/apiKey` and `jdev/cfg/api`.
    ///
    /// `apiKey` is the authoritative source for `snr`, `version`,
    /// `httpsStatus` and `local`; `hasEventSlots` is only documented for
    /// `api`. Both endpoints are optional individually — the probe only fails
    /// when neither answers, which is the actual "unreachable" signal.
    pub async fn api_info(&self) -> Result<ApiInfo> {
        let key = self.fetch_api_info(CMD_API_KEY).await;
        let api = self.fetch_api_info(CMD_API).await;

        match (key, api) {
            (Ok(mut info), Ok(extra)) => {
                info.fill_from(extra);
                Ok(info)
            }
            (Ok(info), Err(e)) => {
                debug!("{CMD_API} unavailable: {e}");
                Ok(info)
            }
            (Err(e), Ok(info)) => {
                debug!("{CMD_API_KEY} unavailable: {e}");
                Ok(info)
            }
            (Err(e), Err(_)) => Err(e),
        }
    }

    async fn fetch_api_info(&self, path: &str) -> Result<ApiInfo> {
        let body = self.get_ll(path, None, REACHABILITY_TIMEOUT_SECS).await?;
        parse_api_info(&body)
    }

    async fn get_ll(
        &self,
        path: &str,
        credentials: Option<(&str, &str)>,
        timeout_secs: u64,
    ) -> Result<Bytes> {
        let (status, body) = self
            .get(path, credentials, Duration::from_secs(timeout_secs))
            .await?;
        if status != 200 {
            return Err(Error::HttpStatus {
                status,
                message: format!("GET /{path}"),
            });
        }
        Ok(body)
    }

    async fn get(
        &self,
        path: &str,
        credentials: Option<(&str, &str)>,
        timeout: Duration,
    ) -> Result<(u16, Bytes)> {
        tokio::time::timeout(timeout, self.get_inner(path, credentials))
            .await
            .map_err(|_| Error::Timeout(format!("HTTP GET /{path}")))?
    }

    async fn get_inner(
        &self,
        path: &str,
        credentials: Option<(&str, &str)>,
    ) -> Result<(u16, Bytes)> {
        let addr = format!("{}:{}", self.host, self.port);
        let tcp = TcpStream::connect(&addr)
            .await
            .map_err(|e| Error::http(format!("TCP connect {addr}: {e}")))?;
        tcp.set_nodelay(true).ok();

        let io: Box<dyn Transport> = if self.use_tls {
            let server_name = ServerName::try_from(self.host.clone())
                .map_err(|e| Error::Tls(format!("invalid server name: {e}")))?;
            let tls = self
                .tls
                .connector()
                .connect(server_name, tcp)
                .await
                .map_err(|e| Error::Tls(format!("TLS handshake: {e}")))?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .map_err(|e| Error::http(e.to_string()))?;
        let driver = tokio::spawn(conn);

        // Path-only request-target: absolute-form makes Miniserver HTTP stacks
        // answer 400.
        let mut builder = Request::builder()
            .method("GET")
            .uri(format!("/{path}"))
            .header(HOST, &self.authority);
        if let Some((username, password)) = credentials {
            builder = builder.header(AUTHORIZATION, basic_auth(username, password));
        }
        let req = builder
            .body(Empty::<Bytes>::new())
            .map_err(|e| Error::http(e.to_string()))?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| Error::http(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| Error::http(e.to_string()))?
            .to_bytes();
        drop(sender);
        driver.abort();
        Ok((status, body))
    }
}

trait Transport: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> Transport for T {}

fn basic_auth(username: &str, password: &str) -> String {
    format!("Basic {}", B64.encode(format!("{username}:{password}")))
}

fn parse_json(payload: &[u8]) -> Result<Value> {
    sonic_rs::from_slice(payload).map_err(|e| Error::json(e.to_string()))
}

/// Parse an `apiKey` / `api` response into [`ApiInfo`].
///
/// `LL.value` is an object on some firmwares and a JSON-ish *string* on
/// others, the latter frequently using single quotes. Both are accepted; a
/// non-`200` status code is not, so callers can distinguish an unreachable
/// Miniserver from a malformed answer.
pub fn parse_api_info(payload: &[u8]) -> Result<ApiInfo> {
    let root = parse_json(payload)?;
    let ll = root
        .get("LL")
        .ok_or_else(|| Error::protocol("api response missing LL"))?;
    match ll_status_code(ll) {
        Some(code) if code != "200" => {
            return Err(Error::protocol(format!("api response LL status {code}")));
        }
        _ => {}
    }
    let value = ll
        .get("value")
        .ok_or_else(|| Error::protocol("api response missing LL.value"))?;

    match value.as_str() {
        Some(raw) => Ok(ApiInfo::from_value(&parse_relaxed_object(raw)?)),
        None if value.is_object() => Ok(ApiInfo::from_value(value)),
        None => Err(Error::protocol("api response LL.value is not an object")),
    }
}

/// Parse an object that may use single instead of double quotes.
fn parse_relaxed_object(raw: &str) -> Result<Value> {
    if let Ok(v) = sonic_rs::from_str::<Value>(raw) {
        if v.is_object() {
            return Ok(v);
        }
    }
    let normalized = raw.replace('\'', "\"");
    let v: Value =
        sonic_rs::from_str(&normalized).map_err(|e| Error::json(format!("LL.value: {e}")))?;
    if !v.is_object() {
        return Err(Error::protocol("LL.value string is not an object"));
    }
    Ok(v)
}

fn string_field(v: &Value, key: &str) -> Option<String> {
    let field = v.get(key)?;
    field
        .as_str()
        .map(str::to_string)
        .or_else(|| field.as_u64().map(|n| n.to_string()))
        .filter(|s| !s.is_empty())
}

fn u8_field(v: &Value, key: &str) -> Option<u8> {
    let field = v.get(key)?;
    field
        .as_u64()
        .or_else(|| field.as_str().and_then(|s| s.trim().parse().ok()))
        .and_then(|n| u8::try_from(n).ok())
}

fn bool_field(v: &Value, key: &str) -> Option<bool> {
    let field = v.get(key)?;
    if let Some(b) = field.as_bool() {
        return Some(b);
    }
    if let Some(n) = field.as_u64() {
        return Some(n != 0);
    }
    match field.as_str()?.trim() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_as_object() {
        let body = br#"{"LL":{"control":"dev/cfg/apiKey","value":{"snr":"504F94A0B1C2",
            "version":"15.2.11.4","httpsStatus":1,"local":true},"Code":"200"}}"#;
        let info = parse_api_info(body).unwrap();
        assert_eq!(info.snr.as_deref(), Some("504F94A0B1C2"));
        assert_eq!(info.version.as_deref(), Some("15.2.11.4"));
        assert_eq!(info.https_status, Some(1));
        assert_eq!(info.local, Some(true));
        assert_eq!(info.has_event_slots, None);
    }

    #[test]
    fn value_as_single_quoted_string() {
        let body = br#"{"LL":{"control":"dev/cfg/apiKey","value":"{'snr':'504F94A0B1C2','version':'15.2.11.4','key':'313233','httpsStatus':2,'local':false}","Code":"200"}}"#;
        let info = parse_api_info(body).unwrap();
        assert_eq!(info.snr.as_deref(), Some("504F94A0B1C2"));
        assert_eq!(info.version.as_deref(), Some("15.2.11.4"));
        assert_eq!(info.https_status, Some(2));
        assert_eq!(info.local, Some(false));
    }

    #[test]
    fn value_as_double_quoted_string() {
        let body =
            br#"{"LL":{"value":"{\"snr\":\"504F94A0B1C2\",\"hasEventSlots\":true}","code":"200"}}"#;
        let info = parse_api_info(body).unwrap();
        assert_eq!(info.snr.as_deref(), Some("504F94A0B1C2"));
        assert_eq!(info.has_event_slots, Some(true));
        assert_eq!(info.version, None);
    }

    #[test]
    fn missing_fields_stay_none() {
        let body = br#"{"LL":{"value":"{'snr':'504F94A0B1C2'}","Code":"200"}}"#;
        let info = parse_api_info(body).unwrap();
        assert_eq!(
            info,
            ApiInfo {
                snr: Some("504F94A0B1C2".into()),
                ..ApiInfo::default()
            }
        );
    }

    #[test]
    fn string_and_numeric_encodings_of_flags() {
        let body = br#"{"LL":{"value":"{'httpsStatus':'1','local':'true','hasEventSlots':0}","Code":"200"}}"#;
        let info = parse_api_info(body).unwrap();
        assert_eq!(info.https_status, Some(1));
        assert_eq!(info.local, Some(true));
        assert_eq!(info.has_event_slots, Some(false));
    }

    #[test]
    fn malformed_responses_are_errors() {
        assert!(parse_api_info(br#"{"LL":{"Code":"200"}}"#).is_err());
        assert!(parse_api_info(br#"{"LL":{"value":"nonsense","Code":"200"}}"#).is_err());
        assert!(parse_api_info(br#"{"LL":{"value":{},"Code":"401"}}"#).is_err());
        assert!(parse_api_info(b"not json").is_err());
    }

    #[test]
    fn api_fills_only_the_gaps() {
        let mut key = parse_api_info(
            br#"{"LL":{"value":"{'snr':'AA','version':'15.0','local':true}","Code":"200"}}"#,
        )
        .unwrap();
        let api = parse_api_info(
            br#"{"LL":{"value":"{'snr':'BB','hasEventSlots':false}","Code":"200"}}"#,
        )
        .unwrap();
        key.fill_from(api);
        assert_eq!(key.snr.as_deref(), Some("AA"));
        assert_eq!(key.has_event_slots, Some(false));
        assert_eq!(key.local, Some(true));
    }

    #[test]
    fn basic_auth_header() {
        assert_eq!(basic_auth("admin", "secret"), "Basic YWRtaW46c2VjcmV0");
    }
}
