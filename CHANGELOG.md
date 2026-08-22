# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the crate follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the major version is `0`, the minor version is where breaking changes go.

Entries for 0.1.0 and 0.2.0 were reconstructed from the tagged history when this
file was introduced.

## [Unreleased]

## [0.3.0] - 2026-08-22

### Fixed

- **Every reconnect that had a token was wedged.** The handshake pre-flighted the
  stored token with `jdev/sys/checktoken` before authenticating with it. The
  protocol document does not list that command in the authentication flow —
  "Authenticating using tokens" is `getkey` followed by `authwithtoken`, and
  `checktoken` is documented separately as a way to verify a token *without*
  renewing it. Firmware refuses it with `400 Bad request` on a connection that
  has not authenticated yet, whatever the token is worth. So the handshake asked
  a question the Miniserver will not answer, took the refusal for a verdict on
  the token, and failed the session with the token still in memory — and the next
  reconnect did exactly the same thing, indefinitely. The first connect of a
  process was unaffected, because with no token it goes straight to `getjwt`,
  which is why restarting the process looked like a fix. The pre-flight is gone;
  reuse is now `getkey` + `authwithtoken`, as documented. `LoxClient::check_token`
  still uses `checktoken` for its documented purpose, on a live session.

- A refusal of `authwithtoken` now costs the token whatever status code carries
  it. Only `401` and `403` used to count, so any other refusal failed the session
  without discarding the token, and the next reconnect presented it again. See
  the `ll_status_invalidates_token` note below.

- A token refresh the Miniserver refuses no longer retries forever. Refreshes
  only run inside the last day of a token's life, and a failure was logged and
  rescheduled — for a token that close to expiry, every 15 seconds, indefinitely,
  on a credential that was about to expire anyway. After three consecutive
  failures the session is now dropped deliberately; the reconnect re-runs the
  handshake, which is the only place that can tell a dead token from a live one
  and fall back to a fresh authentication.

### Changed

- **Behavioural break.** `auth::flow::ll_status_invalidates_token` now answers
  `true` for every LL status except `200`, `423`, `500`, `503` and `901`; it
  previously answered `true` only for `401` and `403`. The signature is
  unchanged, so nothing fails to compile — code that depends on the old set has
  to be looked at rather than being caught by the compiler. The set is now
  defined by its complement: the token survives only a refusal that describes the
  Miniserver's own state or the user's account. Everything else, including status
  codes this crate has no name for, costs the token, because the two mistakes are
  not symmetric — treating a live token as dead costs one round trip, treating a
  dead one as live costs the connection until the process restarts.

- Handshake failures name the step that produced them. `keyexchange`, `getkey`
  and `authwithtoken` now carry a step prefix the way `getkey2` and `getjwt`
  already did, so `authentication failed: LL status 400` no longer leaves four
  candidate commands to pick between — which is what made the bug above take as
  long to find as it did. A refused token is logged with both the step and the
  status code that refused it.

## [0.2.0] - 2026-08-07

### Changed

- The command encryption path was fused into a single pass: one allocation per
  outgoing command instead of five plus an AES key schedule.

### Fixed

- Fire-and-forget controls are refused with `Error::NotConnected` instead of
  being queued on a session that does not exist, where they would have parked the
  caller for the whole reconnect delay and then sent a stale value.

## [0.1.0] - 2026-08-07

Initial release.

[Unreleased]: https://github.com/Jakob-Gliwa/loxwebsocketclient-rs/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Jakob-Gliwa/loxwebsocketclient-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Jakob-Gliwa/loxwebsocketclient-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Jakob-Gliwa/loxwebsocketclient-rs/releases/tag/v0.1.0
