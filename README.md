# loxwebsocket

[![CI](https://github.com/Jakob-Gliwa/loxwebsocketclient-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Jakob-Gliwa/loxwebsocketclient-rs/actions/workflows/ci.yml)

High-performance Rust WebSocket client for the [Loxone Miniserver](https://www.loxone.com/) (protocol V17.0).

Targets Miniserver firmware v15 and newer; the legacy `gettoken` / `refreshtoken` paths are gone. Edition 2024, MSRV 1.86 (verified in CI against the committed `Cargo.lock`).

## Design

| Concern | Choice |
|---|---|
| Transport | `tokio` + [`fastwebsockets`](https://github.com/denoland/fastwebsockets), read/write halves split before the Loxone handshake |
| Hot path | Sync [`LoxHandler`](src/client/handler.rs) callbacks on the reader task (zero-copy borrows) |
| Events | Streamed **per record** — no `HashMap` batching |
| Encryption | AES-256-CBC **ZeroBytePadding**, RSA PKCS#1 v1.5 session wrap |
| Commands | Pipelined up to `max_pending_commands`, correlated FIFO against `LL.control` |
| TLS | `rustls` + `ring` only; one crypto provider, one HTTP stack |

## Quick start

```rust
use loxwebsocket::{ConnectConfig, LoxClient, LoxHandler, LoxoneUuid, TlsMode};

struct PrintHandler;

impl LoxHandler for PrintHandler {
    fn on_value(&mut self, uuid: &LoxoneUuid, value: f64) {
        println!("{uuid} = {value}");
    }
}

#[tokio::main]
async fn main() -> loxwebsocket::Result<()> {
    let mut cfg = ConnectConfig::new("https://192.168.1.5", "user", "pass");
    // A Miniserver reached by IP presents a CloudDNS certificate that WebPKI
    // cannot validate; pin it on first use instead.
    cfg.tls = TlsMode::PinOnFirstUse;

    let client = LoxClient::connect(cfg, PrintHandler).await?;
    println!("state = {}", client.state()); // ConnState::Connected
    client.send_control("some-uuid", "on").await?;
    // …
    client.stop().await?;
    Ok(())
}
```

### Example binary

```bash
LOX_URL=https://192.168.1.5 LOX_USER=admin LOX_PASS=secret LOX_TLS=tofu \
  cargo run --example listen --release
```

`LOX_TLS` accepts `webpki` (default), `tofu` and `insecure`.

## TLS

Certificate verification is **on** by default. `TlsMode` selects the policy:

| Variant | Verifies | Use for |
|---|---|---|
| `WebPki` (default) | Full chain + hostname against the Mozilla root store | Miniservers reached under their real DNS name |
| `PinOnFirstUse` | Leaf SPKI, learned on first contact, enforced afterwards | Local Miniservers reached by IP |
| `Pinned { spki_sha256 }` | Leaf SPKI against an out-of-band fingerprint | Anything that must not have a trust-on-first-use window |
| `Insecure` | Nothing | Explicit opt-out; logs a warning |

Caveats worth knowing before choosing a pin mode:

- `PinOnFirstUse` is trust on first use. The pin comes either from the first TLS handshake or from `jdev/sys/getcertificate`, both unauthenticated at that moment, so an attacker present during the very first connect gets their own key pinned. Only `Pinned` closes that window.
- Chain validation against the *Loxone Root Certificate* is deliberately **not** implemented. The pin modes check the leaf public key; the chain is parsed and logged, never trusted.
- The pin modes also skip hostname verification, because the certificate name (`{ip}.{snr}.dyndns.loxonecloud.com`) practically never matches the address dialled.

## Tokens

Tokens are held in memory and never exposed through a getter. By default they are also **transient** — each process start acquires a new one; see [Persisting the token](#persisting-the-token) to change that.

| Event | Effect on the token |
|---|---|
| Transport disconnect, reconnect | Reused via `checktoken` + `authwithtoken` |
| Close code 4004 / 4005 / 4006 (user changed or disabled) | Discarded |
| `LL` 401 / 403 on `checktoken` / `authwithtoken` | Discarded, new one acquired |
| `LL` 901 (connection limit reached) | **Kept**; the Miniserver is full, which says nothing about the token. Long backoff |
| Less than 5 minutes of lifetime left | Replaced; the displaced token is killed server-side |
| `stop()` | `killtoken` (best effort, short timeout) before the close frame, unless `kill_token_on_stop` is off |
| `drop()` without `stop()` | Same graceful shutdown, but nothing waits for it to finish |

`ConnectConfig::token_permission` picks the lifespan class: `TokenPermission::Web` (ID 2, hours) or `TokenPermission::App` (ID 4, weeks, the default). `LoxClient::check_token()` asks the Miniserver whether the current token is still valid without revealing it.

### Persisting the token

Setting `ConnectConfig::token_store` mirrors the token into a `TokenStore`, and a later start authenticates with what it finds there instead of spending a `getkey2` + `getjwt` round trip on a new one. The crate ships `FileTokenStore`, which keeps one token in one file — written atomically, and on Unix created with mode `0600` in a `0700` directory. A keyring-backed store is a stronger choice; implement the trait for it.

```rust
use loxwebsocket::{ConnectConfig, FileTokenStore};
use std::sync::Arc;

let cfg = ConnectConfig {
    // A graceful stop kills the token by default, which would leave the store
    // holding something already dead.
    kill_token_on_stop: false,
    ..ConnectConfig::new("http://192.168.1.5", "user", "pass")
}
.with_token_store(Arc::new(FileTokenStore::new("/var/lib/myapp/lox_token.cfg")));
```

Two things worth knowing:

- A saved token is bound to the Miniserver URL, the user name and the client UUID it was issued for, and is ignored when any of those change. Spelling the same Miniserver two ways costs a fresh token rather than risking the wrong one.
- The saved file holds bearer material equivalent to the password. Nothing recovers from it leaking except the token expiring, so keep it on storage only the account running the client can read.

## Connection behaviour

| `ConnectConfig` field | Default | Meaning |
|---|---|---|
| `local_only` | `false` | Abort instead of reconnecting when the Miniserver reports the connection as remote (`Error::NotLocal`) |
| `read_idle_timeout_secs` | 150 | Reader idle window, widened automatically for the payload length a message header announces |
| `max_missed_keepalives` | 3 | Unanswered keepalives tolerated before the session is discarded |
| `max_pending_commands` | 32 | Ceiling on pipelined commands; further `send_command` calls fail fast |
| `long_backoff_secs` | 300 | Delay after close code 4003, 4007 or 4008, and after `Error::NoEventSlots` or `Error::TooManyConnections` |
| `keepalive_secs` | 60 | Plaintext `keepalive` period |
| `connect_delay_secs` | 15 | Delay between ordinary reconnect attempts |
| `command_timeout_secs` | 30 | Encrypted request/response deadline |
| `max_reconnect_attempts` | 0 | `0` is unlimited. Bounds *consecutive* failures: the budget is cleared by a session that lasted at least 60 s, so a long-lived client is never shut down for reconnecting often, while a Miniserver that accepts the handshake and drops it again still runs into the cap |

Unless both `receive_updates` and `local_only` are off, each connect attempt is preflighted against `jdev/cfg/apiKey` and `jdev/cfg/api` (both are needed: `hasEventSlots` only appears on the latter, and some firmwares return `LL.value` as a single-quoted string). `hasEventSlots == false` becomes `Error::NoEventSlots` and earns the long backoff, `local == false` under `local_only` becomes `Error::NotLocal` and stops the client outright. An HTTP probe that simply fails is not treated as a verdict — the WebSocket attempt still runs.

Two conditions end the client rather than starting a retry loop, because only an administrator can lift them: `Error::NotLocal`, and `Error::UserDisabled` from either `LL` 423 or close code 4006. Both report `ClientEvent::Closed`; anything else reconnects. `Error::is_terminal()` and `Error::needs_long_backoff()` expose that classification.

Dropping a `LoxClient` without calling `stop()` requests the same shutdown — the supervisor releases the token and closes the socket — but `Drop` cannot await it. Prefer `stop()` where the `killtoken` matters.

`LoxClient::state()` returns a `ConnState` (`Closed`, `Connecting`, `Connected`, `Reconnecting`), read from an atomic byte so it never blocks the reader.

## Performance

> The `benches/` suite, `examples/capture` and `examples/parity` are local development tooling and are not part of this repository (see [Crate layout](#crate-layout)); the figures below are kept for context on the design decisions they informed, but the commands are not runnable against a fresh checkout.

`cargo bench` runs four criterion targets — `uuid`, `proto`, `crypto` and `hotpath`. The first three are synthetic; `hotpath` replays recorded Miniserver payloads and is skipped unless `benches/fixtures/` has been populated by `examples/capture`. Figures below are medians from a single run on `aarch64-apple-darwin`. **Read them as ratios, not absolutes**: the same suite varies by up to 2× between runs on this machine depending on thermal state, while the ratios within one run stay stable.

| Benchmark | Median |
|---|---|
| `uuid_format/format_macro_baseline` — the `format!` implementation that was replaced | 756 ns |
| `uuid_format/format_loxone` → `String` via hex LUT | 82.8 ns |
| `uuid_format/format_loxone_into` → reused `String` | 26.6 ns |
| `uuid_format/format_loxone_bytes` → `[u8; 35]` on the stack | 14.6 ns |
| `walk_values/slice_cast/1000` | 656 ns (1.52 Gelem/s) |
| `walk_values/chunks_exact/1000` — the copying walker it replaced | 958 ns (1.04 Gelem/s) |
| `walk_values/slice_cast/10000` vs `chunks_exact/10000` | 6.69 µs vs. 9.82 µs |
| `walk_texts/pad0/64` — 256 records | 380 ns |
| `walk_daytimers/100x10` | 971 ns |
| `walk_weather/100x10` | 1.15 µs |
| `parse_header/exact` | 4.9 ns |
| `salt_state_encrypt/short` — 50-byte command | 5.56 µs |
| `control_correlation/compare_wire` — the echo comparison the reader does | 7.4 ns |
| `control_correlation/decrypt_echo` — recovering the plaintext instead | 3.55 µs |
| `uuid_map_lookup` — 1000 lookups, raw key vs. formatted `String` key | 15.9 µs vs. 36.0 µs |

Three baselines are kept in the suite on purpose, so the gains stay reproducible rather than anecdotal:

- `format_macro_baseline` is the pre-rewrite UUID formatter — roughly 9× slower than the LUT version and 50× slower than the stack-buffer form.
- `walk_values/chunks_exact` is the walker that copied each record's 16 + 8 bytes into stack arrays. Reinterpreting the payload as `&[ValueRecord]` in one checked cast and handing the callback a `&LoxoneUuid` borrowed from the frame buffer is 21–32 % faster, growing with table size. This is the hottest path in the client and was the last of the four walkers to get the treatment; daytimer and weather entries have been cast in place from the start.
- `control_correlation/decrypt_echo` is what the reader used to run on *every* type-0 answer: percent-decode, Base64 decode, AES-CBC and two allocations, purely to check that the answer's verb matched the waiting command. The writer already knows the exact `jdev/sys/enc/…` blob it sent, so the queue keeps a copy and compares — some 480× cheaper, with the decryption left as the fallback for an echo that does not match verbatim.

The cheapest formatting is none at all. `LoxoneUuid` implements `Hash` and `Eq` over the 16 raw wire bytes (hashed as two `u64` reads), so consumer state maps should be keyed on the UUID directly and format only at the boundary where a human or `LoxAPP3.json` is involved:

```rust
use loxwebsocket::LoxoneUuid;
use std::collections::HashMap;

let mut states: HashMap<LoxoneUuid, f64> = HashMap::new();
states.insert(LoxoneUuid::from_bytes([0u8; 16]), 21.5);
```

That is roughly half the cost of going through the string form, and swapping in a non-cryptographic hasher removes the remaining SipHash overhead on top — which is what `loxwebsocket::collect` does by default.

### Owned snapshots

Consumers that cannot hold a borrow across `.await` should use the `collect` helpers rather than building a map by hand, because the obvious implementation pays for two things it does not have to: a `String` allocation per record, and SipHash over a key that is already uniformly distributed.

```rust
use loxwebsocket::{collect_values, collect_values_by_name};

# let payload: &[u8] = &[];
let by_uuid = collect_values(payload);       // UuidMap<f64>, raw 16-byte key
let by_name = collect_values_by_name(payload); // UuidStrMap<f64>, inline 35-byte key
```

`LoxoneUuidStr` keeps the Loxone string form inside the map bucket instead of behind a pointer. On the recorded capture that is 4.5× faster than `HashMap<String, f64>` for value tables.

### Parity against the Python/Cython client

> As above, `examples/parity.rs`, `benches/parity_py.py` and `benches/compare.py` are local-only tooling, not part of this repository.

`examples/parity.rs` and `benches/parity_py.py` replay the same recorded capture through both implementations and `benches/compare.py` prints the verdict, failing if any Rust path that produces the same consumer artifact is slower than its Python counterpart:

```bash
set -a && source .env && set +a
cargo run --example capture --release          # record fixtures from a Miniserver
cargo run --example parity --release
uv run --with orjson python benches/parity_py.py
python benches/compare.py
```

Cost per message, replayed over the recorded message mix on `aarch64-apple-darwin`. Comparisons within ±5 % count as a tie, because the two sides are timed in separate processes:

| Message type | Consumer artifact | Rust | Python/Cython | Factor |
|---|---|---|---|---|
| 2 — values | map keyed by UUID string (identical artifact) | 604 ns | 2.88 µs | 4.8× |
| 2 — values | map keyed by raw UUID | 226 ns | 2.88 µs | 12.8× |
| 2 — values | streaming callback (no Python counterpart) | 67 ns | — | — |
| 3 — texts | map keyed by UUID string (identical artifact) | 704 ns | 1.49 µs | 2.1× |
| 3 — texts | map keyed by raw UUID | 536 ns | 1.49 µs | 2.8× |
| 3 — texts | streaming callback (no Python counterpart) | 65 ns | — | — |
| 0 — text/JSON | correlated answer handed to the caller | 57 ns | 58 ns | tie |
| 0 — text/JSON | unsolicited answer parsed as JSON | 157 ns | 286 ns | 1.8× |

Two things to keep in mind when reading these. The type-0 handoff is a tie because both sides are dominated by the same copy — but the Rust figure also includes the `LL.control` correlation scan, which the Python client does not perform at all; it resolves the pending future positionally. And the Python figures exclude `asyncio` dispatch: the real Python client spends a further 2.3 µs per type-2 message on the `await` chain and `create_task`, which for a small message is the bulk of its cost.

## Protocol notes (critical traps)

- `fastwebsockets`' `read_frame` and `write_frame` are **not cancel-safe**. `read_frame` consumes the frame header out of its persistent buffer before awaiting the payload, and `write_frame` is a plain `write_all`. Neither may ever appear as a `select!` arm — a single competing timer permanently desynchronises the stream. The reader loop runs inline with one terminal `timeout` as its only cancellation; the writer's `select!` arms merely decide *what* to send and the write is awaited outside.
- The socket must be split **before** the Loxone handshake. `FragmentCollector::into_inner()` hands back only the raw stream, so splitting later discards whatever the frame parser already buffered — after `enablebinstatusupdate` that is a full event table.
- The Miniserver answers **every** command, including fire-and-forget controls. Each outgoing command therefore registers a FIFO waiter (the fire-and-forget ones simply drop the receiver), otherwise an ack completes an unrelated `send_command`.
- WebSocket keyexchange Base64 must **not** be URI-encoded (unlike the HTTP `?sk=` parameter).
- Command encryption uses **ZeroBytePadding**, not PKCS#7; decrypt with `rstrip(0)`.
- Salt bookkeeping is **reset on every reconnect** — a stale `nextSalt/…` earns a spurious 401.
- Estimated headers (info bit 0) are skipped; an exact header always follows. The estimate is still useful as a lower bound for widening the read timeout.
- Type-0 `LL.code` / `LL.Code` casing is both accepted, and `LL.control` is scanned with a bounded byte scan rather than a JSON DOM — `data/LoxAPP3.json` arrives on the same path and is several megabytes.
- `getkey2` and `getvisusalt` return the same envelope shape; only the correlated command distinguishes them, so a `getkey2` answer must never feed the visu hash.

## Crate layout

```
src/
  lib.rs
  error.rs / metrics.rs / uuid.rs / sync.rs
  proto/          # header, value, text, daytimer, weather
  crypto/         # AES session (SessionKeys + SaltState), RSA wrap, HMAC
  auth/           # token lifecycle, getkey2/getjwt/authwithtoken commands, TokenStore
  client/
    mod.rs        # LoxClient façade, ConnectConfig
    connect.rs    # TCP/TLS + WebSocket upgrade, split_ws
    tls.rs        # TlsMode, SPKI pinning, certificate parsing
    http.rs       # cold-path GETs, ApiInfo
    io.rs         # supervisor: session loop, preflight, reconnect policy
    handshake.rs  # keyexchange, auth, enablebinstatusupdate
    reader.rs     # inline reader loop, event dispatch
    writer.rs     # write half, salt state, keepalive, shutdown
    pending.rs    # PendingQueue, LL.control correlation
    refresh.rs    # token refresh task
    state.rs      # shared state, liveness counters, token persistence hook
    keepalive.rs / reconnect.rs / visu.rs / handler.rs
examples/listen.rs
```

Not part of this repository (local-only, gitignored): `benches/` (criterion suites, parity harness), `refs/` (Loxone spec PDF, Python/Cython reference client), `scripts/`, `output/`, `examples/capture.rs`, `examples/parity.rs`.

## Known gaps

- **CloudDNS / Remote Connect is not implemented.** Resolving a Miniserver through `connect.loxonecloud.com` (`GET /getip?snr=…`) and the remote-connect relay — the headline feature of protocol version 17.0 — is missing. Only direct addresses work: a local IP or hostname, or a port-forwarded public one.
- No chain validation against the Loxone Root Certificate, and no hostname verification in the pin modes (see [TLS](#tls)).
- `rsa` 0.9 carries [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) (Marvin Attack). It is accepted in `.cargo/audit.toml` because the advisory covers private-key operations and this crate only ever encrypts with the Miniserver's public key. Revisit when `rsa` 0.10 ships.

## License

MIT
