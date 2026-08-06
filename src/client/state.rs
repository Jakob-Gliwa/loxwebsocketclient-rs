//! State shared between the façade, the supervisor, the writer and the reader.

use crate::auth::{LxToken, TokenStore};
use crate::metrics::{ConnState, ConnStateCell, MetricsState};
use crate::sync::lock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::debug;

/// Where the token is kept between runs, and under which identity.
#[derive(Debug)]
struct TokenPersistence {
    store: Arc<dyn TokenStore>,
    binding: String,
}

/// Connection state readable by `LoxClient::metrics` and `LoxClient::state`.
#[derive(Debug)]
pub(crate) struct SharedState {
    pub(crate) metrics: Arc<MetricsState>,
    state: ConnStateCell,
    token: Mutex<LxToken>,
    /// Every token mutation in the crate goes through this type, which is what
    /// makes hanging persistence off it enough to cover all of them.
    persist: Option<TokenPersistence>,
}

impl SharedState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            metrics: MetricsState::new(),
            state: ConnStateCell::default(),
            token: Mutex::new(LxToken::default()),
            persist: None,
        })
    }

    /// As [`Self::new`], with the token mirrored into `store` under `binding`.
    pub fn with_token_store(store: Arc<dyn TokenStore>, binding: String) -> Arc<Self> {
        Arc::new(Self {
            metrics: MetricsState::new(),
            state: ConnStateCell::default(),
            token: Mutex::new(LxToken::default()),
            persist: Some(TokenPersistence { store, binding }),
        })
    }

    pub fn set_state(&self, s: ConnState) {
        self.state.set(s);
    }

    pub fn state(&self) -> ConnState {
        self.state.get()
    }

    /// Snapshot of the in-memory token.
    pub fn token(&self) -> LxToken {
        lock(&self.token).clone()
    }

    /// Replace the token, mirroring it into the store if there is one.
    ///
    /// The store is written under the lock so that the saved value always
    /// matches the last one set — the writer task can clear the token while the
    /// refresh path is replacing it, and a write outside the lock could land in
    /// either order. [`TokenStore`] documents the resulting duty to be quick.
    pub fn set_token(&self, token: LxToken) {
        let mut current = lock(&self.token);
        *current = token;
        if let Some(persist) = &self.persist {
            persist.store.save(&persist.binding, &current);
        }
    }

    /// Forget the token. Only legitimate on an authentication rejection, on a
    /// close code that says the user changed, or on `stop()`.
    pub fn clear_token(&self) {
        let mut current = lock(&self.token);
        current.clear();
        if let Some(persist) = &self.persist {
            persist.store.clear(&persist.binding);
        }
    }

    /// Adopt a token left behind by an earlier run, if the store has a usable one.
    ///
    /// An expired one is dropped here rather than handed to the handshake: it
    /// would only be spent on a `refreshjwt` the Miniserver is going to refuse.
    /// Anything still valid is worth trying even if the Miniserver has since
    /// forgotten it — the handshake already falls back to acquiring a new one.
    pub fn restore_token(&self) {
        let Some(persist) = &self.persist else { return };
        let Some(token) = persist.store.load(&persist.binding) else {
            return;
        };
        if token.is_empty() || token.seconds_to_expire() <= 0 {
            debug!("the saved token has expired, discarding it");
            persist.store.clear(&persist.binding);
            return;
        }
        debug!(
            expires_in_secs = token.seconds_to_expire(),
            "reusing the saved token"
        );
        // Deliberately not through `set_token`: this is where it came from.
        *lock(&self.token) = token;
    }

    /// `validUntil` of the current token, or `None` when there is none.
    pub fn token_valid_until(&self) -> Option<i64> {
        let token = lock(&self.token);
        (!token.is_empty()).then_some(token.valid_until)
    }
}

/// Keepalive bookkeeping shared by the writer (which sends) and the reader
/// (which sees the type-6 answers).
#[derive(Debug, Default)]
pub(crate) struct Liveness {
    sent: AtomicU64,
    acked: AtomicU64,
    sent_at: Mutex<Option<Instant>>,
}

impl Liveness {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Called by the writer just before a `keepalive` goes out.
    pub fn record_sent(&self) {
        *lock(&self.sent_at) = Some(Instant::now());
        self.sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Called by the reader on a type-6 message; returns when the keepalive it
    /// answers went out, for the round-trip measurement.
    ///
    /// Counts one answer rather than catching up to `sent`. Catching up would
    /// let a genuinely lost answer be forgiven by the next one that arrives, so
    /// a link dropping every other keepalive would look perfectly healthy.
    pub fn record_ack(&self) -> Option<Instant> {
        // Capped at `sent` so an unsolicited type-6 cannot bank credit against
        // a keepalive that has yet to go missing.
        let sent = self.sent.load(Ordering::Relaxed);
        let _ = self
            .acked
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |acked| {
                (acked < sent).then_some(acked + 1)
            });
        lock(&self.sent_at).take()
    }

    /// Keepalives sent that were never answered.
    pub fn missed(&self) -> u64 {
        self.sent
            .load(Ordering::Relaxed)
            .saturating_sub(self.acked.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HashAlg;

    #[test]
    fn token_lifecycle() {
        let shared = SharedState::new();
        assert!(shared.token().is_empty());
        assert_eq!(shared.token_valid_until(), None);
        shared.set_token(LxToken::new("tok", 42, HashAlg::Sha256));
        assert_eq!(shared.token_valid_until(), Some(42));
        shared.clear_token();
        assert!(shared.token().is_empty());
        assert_eq!(shared.token_valid_until(), None);
    }

    #[test]
    fn state_is_observable_without_locking() {
        let shared = SharedState::new();
        assert_eq!(shared.state(), ConnState::Closed);
        shared.set_state(ConnState::Connected);
        assert_eq!(shared.state(), ConnState::Connected);
    }

    #[test]
    fn every_keepalive_needs_its_own_answer() {
        let liveness = Liveness::new();
        assert_eq!(liveness.missed(), 0);
        liveness.record_sent();
        assert_eq!(liveness.missed(), 1);
        liveness.record_sent();
        liveness.record_sent();
        assert_eq!(liveness.missed(), 3);

        // One answer clears one keepalive, not the whole backlog: the two
        // earlier ones really were lost and stay counted.
        assert!(liveness.record_ack().is_some());
        assert_eq!(liveness.missed(), 2);
        assert!(liveness.record_ack().is_none());
        assert_eq!(liveness.missed(), 1);
    }

    /// An answer with no keepalive outstanding must not push the counter below
    /// zero, or a stray type-6 would buy the connection a free miss later on.
    #[test]
    fn an_unsolicited_answer_cannot_bank_credit() {
        let liveness = Liveness::new();
        liveness.record_ack();
        liveness.record_ack();
        assert_eq!(liveness.missed(), 0);
        // The next real keepalive is still outstanding, not pre-paid.
        liveness.record_sent();
        assert_eq!(liveness.missed(), 1);
    }
}
