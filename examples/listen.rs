//! Listen for Loxone value updates.
//!
//! Usage:
//! ```text
//! LOX_URL=http://192.168.1.5 LOX_USER=admin LOX_PASS=secret \
//!   cargo run --example listen --release
//! ```

use loxwebsocket::{ClientEvent, ConnectConfig, LoxClient, LoxHandler, LoxoneUuid, TlsMode};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_subscriber::EnvFilter;

/// Wall-clock seconds with microsecond precision, for lining up this
/// process's output against another client observing the same Miniserver.
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs_f64()
}

struct PrintHandler {
    values: u64,
}

impl LoxHandler for PrintHandler {
    fn on_value(&mut self, uuid: &LoxoneUuid, value: f64) {
        self.values += 1;
        println!("{:.6} value  {uuid} = {value}", now());
    }

    fn on_text(&mut self, uuid: &LoxoneUuid, _icon: &LoxoneUuid, text: &[u8]) {
        let s = String::from_utf8_lossy(text);
        println!("{:.6} text   {uuid} = {s}", now());
    }

    fn on_keepalive(&mut self) {
        tracing::debug!("keepalive ok");
    }

    fn on_event(&mut self, event: ClientEvent) {
        println!("{:.6} event  {event:?}", now());
    }
}

#[tokio::main]
async fn main() -> loxwebsocket::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    let url = env::var("LOX_URL").unwrap_or_else(|_| "http://127.0.0.1".into());
    let user = env::var("LOX_USER").expect("LOX_USER required");
    let pass = env::var("LOX_PASS").expect("LOX_PASS required");

    let mut cfg = ConnectConfig::new(url, user, pass);
    cfg.tls = match env::var("LOX_TLS").as_deref() {
        Ok("webpki") | Err(_) => TlsMode::WebPki,
        Ok("tofu") => TlsMode::PinOnFirstUse,
        Ok("insecure") => TlsMode::Insecure,
        Ok(other) => panic!("LOX_TLS must be webpki, tofu or insecure, got {other:?}"),
    };

    let client = LoxClient::connect(cfg, PrintHandler { values: 0 }).await?;
    println!("{:.6} client spawned; state={}", now(), client.state());

    // Run until Ctrl+C, or LISTEN_SECONDS if set (for scripted comparisons).
    if let Ok(secs) = env::var("LISTEN_SECONDS") {
        let secs: u64 = secs.parse().expect("LISTEN_SECONDS must be an integer");
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
    } else {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for ctrl_c");
    }
    println!("{:.6} stopping… metrics={:?}", now(), client.metrics());
    client.stop().await?;
    Ok(())
}
