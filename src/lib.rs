//! High-performance Loxone Miniserver WebSocket client.
//!
//! # Features
//!
//! - `tokio` + `fastwebsockets` transport with `remotecontrol` subprotocol
//! - Sync zero-copy [`LoxHandler`] callbacks on the reader task
//! - Per-record streaming for value / text / daytimer / weather events
//! - Full auth (getkey2 → getjwt → authwithtoken), keepalive, token refresh, reconnect
//! - AES-256-CBC ZeroBytePadding command encryption
//!
//! # Example
//!
//! ```no_run
//! use loxwebsocket::{ConnectConfig, LoxClient, LoxHandler, LoxoneUuid};
//!
//! struct PrintHandler;
//!
//! impl LoxHandler for PrintHandler {
//!     fn on_value(&mut self, uuid: &LoxoneUuid, value: f64) {
//!         println!("{uuid} = {value}");
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> loxwebsocket::Result<()> {
//!     let cfg = ConnectConfig::new("http://192.168.1.5", "user", "pass");
//!     let client = LoxClient::connect(cfg, PrintHandler).await?;
//!     client.send_control("uuid", "on").await?;
//!     client.stop().await?;
//!     Ok(())
//! }
//! ```

pub mod auth;
pub mod client;
pub mod collect;
pub mod crypto;
pub mod error;
pub mod metrics;
pub mod proto;
pub(crate) mod sync;
pub mod uuid;

pub use auth::{FileTokenStore, LOXONE_EPOCH, LxToken, TokenPermission, TokenStore};
pub use client::{
    ApiInfo, CONTROL_KEY_SCAN_LIMIT, CONTROL_VALUE_LIMIT, ChannelHandler, ClientEvent,
    ConnectConfig, HttpClient, LoxClient, LoxHandler, OwnedEvent, TlsContext, TlsMode,
    extract_ll_control,
};
pub use collect::{
    LoxBuildHasher, LoxHasher, UuidMap, UuidStrMap, collect_texts, collect_texts_by_name,
    collect_values, collect_values_by_name,
};
pub use error::{Error, Result};
pub use metrics::{ConnState, LoxMetrics};
pub use proto::{DaytimerEntry, DaytimerEvent, MessageType, WeatherEntry, WeatherEvent};
pub use uuid::{LoxoneUuid, LoxoneUuidStr};
