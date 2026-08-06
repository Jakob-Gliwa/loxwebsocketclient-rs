//! Request/response correlation for the split reader/writer.
//!
//! The Miniserver answers *every* command it receives, so a fire-and-forget
//! control command still produces a type-0 acknowledgement. Without a waiter of
//! its own that acknowledgement would complete the oneshot of an unrelated
//! `send_command`. Every outgoing command therefore registers an entry here —
//! fire-and-forget commands simply register one whose receiver is dropped.
//!
//! The writer pushes under the lock and only then writes to the socket, so the
//! queue order matches the wire order and FIFO pop is correct even when
//! commands are pipelined.

use crate::crypto::{CMD_ENCRYPT, SessionKeys, strip_salt_prefix};
use crate::error::{Error, Result};
use bytes::Bytes;
use std::collections::VecDeque;
use tokio::sync::oneshot;
use tokio::time::Instant;

/// How far into a type-0 payload the cheap `LL.control` scan looks for the key.
///
/// The control field is emitted first in every LL envelope; bounding the scan
/// keeps multi-megabyte payloads such as `data/LoxAPP3.json` off the hot path.
pub const CONTROL_KEY_SCAN_LIMIT: usize = 512;

/// Longest `LL.control` value the scan will accept.
///
/// Generous on purpose: an encrypted command is echoed as its percent-encoded
/// `jdev/sys/enc/…` blob, which for a `getjwt` runs to several hundred bytes.
pub const CONTROL_VALUE_LIMIT: usize = 8 * 1024;

/// One command awaiting its type-0 answer.
#[derive(Debug)]
pub(crate) struct PendingEntry {
    /// Plaintext command as handed to the encryptor, used to verify `LL.control`.
    pub plaintext_cmd: String,
    /// The exact `jdev/sys/enc/…` text that went on the wire.
    ///
    /// The Miniserver echoes an encrypted command verbatim, so keeping a copy
    /// turns the usual correlation into a string comparison. See
    /// [`PendingQueue::resolve`].
    pub wire_cmd: String,
    /// `None` for fire-and-forget commands that still need a queue slot.
    pub resp: Option<oneshot::Sender<Result<Bytes>>>,
    pub deadline: Instant,
}

/// Outcome of matching a type-0 payload against the queue head.
#[derive(Debug)]
pub(crate) struct Resolved {
    pub plaintext_cmd: String,
    pub resp: Option<oneshot::Sender<Result<Bytes>>>,
    /// `false` when `LL.control` disagreed with `plaintext_cmd`.
    pub matched: bool,
    /// Decoded `LL.control`, populated only when the echo had to be decrypted —
    /// that is, on the mismatch path where the warning needs it.
    pub actual: Option<String>,
}

/// FIFO of outstanding commands.
#[derive(Debug, Default)]
pub(crate) struct PendingQueue {
    entries: VecDeque<PendingEntry>,
    mismatches: u64,
    unsolicited: u64,
    timeouts: u64,
}

impl PendingQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Deadline of the oldest waiter; entries are pushed in deadline order
    /// because every command shares the same timeout.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.entries.front().map(|entry| entry.deadline)
    }

    /// Counters mirrored into [`crate::LoxMetrics`]; kept here so the queue can
    /// be reasoned about — and tested — without the metrics plumbing.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of answers whose `LL.control` did not match the waiting command.
    #[cfg(test)]
    pub fn mismatches(&self) -> u64 {
        self.mismatches
    }

    /// Number of type-0 answers that arrived with an empty queue.
    #[cfg(test)]
    pub fn unsolicited(&self) -> u64 {
        self.unsolicited
    }

    /// Number of entries dropped because their deadline passed.
    #[cfg(test)]
    pub fn timeouts(&self) -> u64 {
        self.timeouts
    }

    pub fn push(
        &mut self,
        plaintext_cmd: impl Into<String>,
        wire_cmd: impl Into<String>,
        resp: Option<oneshot::Sender<Result<Bytes>>>,
        deadline: Instant,
    ) {
        self.entries.push_back(PendingEntry {
            plaintext_cmd: plaintext_cmd.into(),
            wire_cmd: wire_cmd.into(),
            resp,
            deadline,
        });
    }

    /// Pop the oldest waiter for an incoming answer.
    ///
    /// `control` is the raw `LL.control` value straight out of the payload, or
    /// `None` when the payload carried none. A mismatch is counted but the
    /// entry is still resolved: the Miniserver answers in order, so a differing
    /// control field means our own view is off, not that a later answer will
    /// fit better.
    ///
    /// The Miniserver echoes an encrypted command as the very `jdev/sys/enc/…`
    /// blob it received, so the normal case is a comparison against the text
    /// the writer sent. Only a mismatch pays for the percent-decode, Base64
    /// decode, AES round trip and two allocations that recovering the plaintext
    /// costs — which is why `keys` is needed at all.
    pub fn resolve(&mut self, control: Option<&str>, keys: &SessionKeys) -> Option<Resolved> {
        let entry = self.entries.pop_front()?;
        let (matched, actual) = match control {
            None => (true, None),
            Some(ctrl) if canonical(ctrl) == canonical(&entry.wire_cmd) => (true, None),
            Some(ctrl) => {
                let decoded = decode_control(ctrl, keys);
                let ok = decoded
                    .as_deref()
                    .is_some_and(|plain| control_matches(plain, &entry.plaintext_cmd));
                if !ok {
                    self.mismatches += 1;
                }
                (ok, decoded)
            }
        };
        Some(Resolved {
            plaintext_cmd: entry.plaintext_cmd,
            resp: entry.resp,
            matched,
            actual,
        })
    }

    /// Record a type-0 answer that had no waiter.
    pub fn note_unsolicited(&mut self) {
        self.unsolicited += 1;
    }

    /// Fail every entry whose deadline has passed; returns how many.
    pub fn expire(&mut self, now: Instant) -> usize {
        let mut expired = 0;
        while let Some(front) = self.entries.front() {
            if front.deadline > now {
                break;
            }
            let entry = self.entries.pop_front().expect("front checked above");
            if let Some(resp) = entry.resp {
                let _ = resp.send(Err(Error::Timeout(format!(
                    "no response to {}",
                    cmd_label(&entry.plaintext_cmd)
                ))));
            }
            expired += 1;
        }
        self.timeouts += expired as u64;
        expired
    }

    /// Fail and drop every entry, e.g. when the session ends.
    pub fn fail_all(&mut self, reason: &str) -> usize {
        let drained = self.entries.len();
        for entry in self.entries.drain(..) {
            if let Some(resp) = entry.resp {
                let _ = resp.send(Err(Error::Closed(reason.to_string())));
            }
        }
        drained
    }
}

/// Compare a wire `LL.control` value against the command we sent.
///
/// The Miniserver echoes the command it processed, but with quirks: encrypted
/// commands come back as the `jdev/sys/enc/…` blob (the caller decrypts those
/// first), some answers carry a leading slash or drop the `j`, and hash
/// arguments are sometimes elided. Verification therefore falls back to the
/// command verb, which is coarse enough that two `jdev/sps/io` commands to
/// different objects still compare equal — FIFO order already covers that
/// case; the check exists to catch an answer landing on the wrong *kind* of
/// waiter.
fn control_matches(control: &str, plaintext_cmd: &str) -> bool {
    verb(control) == verb(plaintext_cmd)
}

/// Strip the spellings the Miniserver varies between: surrounding whitespace,
/// trailing NULs from the zero-byte padding, a leading slash, and the `j` of
/// `jdev`. What remains compares byte for byte.
fn canonical(cmd: &str) -> &str {
    let s = cmd.trim().trim_end_matches('\0');
    let s = s.strip_prefix('/').unwrap_or(s);
    s.strip_prefix('j')
        .filter(|rest| rest.starts_with("dev/"))
        .unwrap_or(s)
}

/// Verb-identifying prefix of a command, with the `jdev`/`dev` spelling folded.
fn verb(cmd: &str) -> &str {
    let s = canonical(cmd);
    let segments = if s.starts_with("dev/") { 3 } else { 1 };
    take_segments(s, segments)
}

fn take_segments(s: &str, n: usize) -> &str {
    let mut end = 0;
    for (i, segment) in s.split('/').take(n).enumerate() {
        if i > 0 {
            end += 1;
        }
        end += segment.len();
    }
    &s[..end.min(s.len())]
}

/// Leading path segments of a command — safe to log.
///
/// Everything after the verb may be a password hash, token hash or visu hash,
/// so `authwithtoken/{hash}/{user}` is reduced to `authwithtoken`.
pub(crate) fn cmd_label(cmd: &str) -> &str {
    let segments = if cmd.starts_with("jdev/") || cmd.starts_with("dev/") {
        3
    } else {
        1
    };
    take_segments(cmd, segments)
}

/// Read eight bytes as a little-endian word, so byte `i` sits in bits `8*i`.
///
/// Only ever fed a `chunks_exact(8)` item.
#[inline]
fn word_at(chunk: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(chunk);
    u64::from_le_bytes(buf)
}

const ONES: u64 = 0x0101_0101_0101_0101;

#[inline]
const fn repeat_byte(byte: u8) -> u64 {
    (byte as u64) * ONES
}

/// Marks the high bit of every zero byte in `word`.
#[inline]
const fn zero_byte_mask(word: u64) -> u64 {
    word.wrapping_sub(ONES) & !word & 0x8080_8080_8080_8080
}

/// First index holding `a` or `b`, comparing eight bytes per step.
///
/// The `control` value of a keyexchange answer runs to several hundred bytes,
/// and a byte-at-a-time scan over it costs more than the rest of the type-0
/// path put together.
#[inline]
fn find_either(haystack: &[u8], a: u8, b: u8) -> Option<usize> {
    let (rep_a, rep_b) = (repeat_byte(a), repeat_byte(b));
    let mut chunks = haystack.chunks_exact(8);
    let mut offset = 0;
    for chunk in chunks.by_ref() {
        let word = word_at(chunk);
        let mask = zero_byte_mask(word ^ rep_a) | zero_byte_mask(word ^ rep_b);
        if mask != 0 {
            return Some(offset + (mask.trailing_zeros() / 8) as usize);
        }
        offset += 8;
    }
    chunks
        .remainder()
        .iter()
        .position(|x| *x == a || *x == b)
        .map(|i| offset + i)
}

#[inline]
fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    find_either(haystack, needle, needle)
}

/// Offset of `"control"` inside `window`, or `None`.
///
/// Candidate positions are reached by jumping from quote to quote instead of
/// comparing a nine-byte window at every offset, which matters most for the
/// payloads that do *not* contain the key and are scanned to the limit.
fn find_control_key(window: &[u8]) -> Option<usize> {
    const KEY: &[u8; 9] = b"\"control\"";
    let last = window.len().checked_sub(KEY.len())?;
    let anchor = word_at(&KEY[..8]);

    let mut from = 0;
    while from <= last {
        let at = from + find_byte(&window[from..], b'"')?;
        if at > last {
            return None;
        }
        if word_at(&window[at..at + 8]) == anchor && window[at + 8] == b'"' {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

/// Extract `LL.control` from a raw type-0 payload without building a DOM.
///
/// The key is only looked for in the first [`CONTROL_KEY_SCAN_LIMIT`] bytes, so
/// a payload that is not an LL envelope — the multi-megabyte structure file
/// above all — costs a bounded scan and nothing else. Returns `None` whenever
/// the field cannot be read cheaply; the caller then skips verification rather
/// than reporting a false mismatch.
pub fn extract_ll_control(payload: &[u8]) -> Option<&str> {
    const KEY_LEN: usize = b"\"control\"".len();
    let key_window = &payload[..payload.len().min(CONTROL_KEY_SCAN_LIMIT)];
    let key_end = find_control_key(key_window)? + KEY_LEN;

    let after_key = &payload[key_end..];
    let colon = find_byte(after_key, b':')?;
    let after_colon = &after_key[colon + 1..];
    let quote = after_colon.iter().position(|b| !b.is_ascii_whitespace())?;
    if after_colon[quote] != b'"' {
        return None;
    }

    let value = &after_colon[quote + 1..];
    let value = &value[..value.len().min(CONTROL_VALUE_LIMIT)];
    // Loxone never escapes anything inside `control`; a backslash means the
    // cheap scan is out of its depth.
    let end = find_either(value, b'"', b'\\')?;
    if value[end] != b'"' {
        return None;
    }
    std::str::from_utf8(&value[..end]).ok()
}

/// Turn a raw `LL.control` into the plaintext command it stands for.
///
/// Encrypted commands are echoed as their `jdev/sys/enc/…` blob; decrypting is
/// the only way to correlate them, and it also strips the salt prefix.
pub(crate) fn decode_control(control: &str, keys: &SessionKeys) -> Option<String> {
    if control.contains(CMD_ENCRYPT) {
        let plain = keys.decrypt_control_response(control).ok()?;
        Some(strip_salt_prefix(&plain).to_string())
    } else {
        Some(control.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SaltState;
    use tokio::time::Duration;

    fn waiter() -> (
        oneshot::Sender<Result<Bytes>>,
        oneshot::Receiver<Result<Bytes>>,
    ) {
        oneshot::channel()
    }

    fn far_future() -> Instant {
        Instant::now() + Duration::from_secs(3600)
    }

    /// Keys that decrypt nothing. Tests that pass an unencrypted echo never
    /// reach the decryption path, so a real session key would only obscure
    /// which path a case actually takes.
    fn no_keys() -> SessionKeys {
        SessionKeys::from_key_iv([0u8; 32], [0u8; 16])
    }

    /// Register a command whose wire form is the command itself, i.e. what an
    /// unencrypted session would send.
    fn push_plain(
        q: &mut PendingQueue,
        cmd: &str,
        resp: Option<oneshot::Sender<Result<Bytes>>>,
        deadline: Instant,
    ) {
        q.push(cmd, cmd, resp, deadline);
    }

    #[tokio::test]
    async fn fifo_order_across_pipelined_commands() {
        let mut q = PendingQueue::new();
        let (tx1, rx1) = waiter();
        let (tx2, rx2) = waiter();
        push_plain(&mut q, "jdev/sys/getkey", Some(tx1), far_future());
        push_plain(&mut q, "jdev/sps/io/a/on", Some(tx2), far_future());
        assert_eq!(q.len(), 2);

        let first = q.resolve(Some("jdev/sys/getkey"), &no_keys()).unwrap();
        assert!(first.matched);
        first
            .resp
            .unwrap()
            .send(Ok(Bytes::from_static(b"one")))
            .unwrap();
        let second = q.resolve(Some("jdev/sps/io/a/on"), &no_keys()).unwrap();
        assert!(second.matched);
        second
            .resp
            .unwrap()
            .send(Ok(Bytes::from_static(b"two")))
            .unwrap();

        assert_eq!(rx1.await.unwrap().unwrap(), Bytes::from_static(b"one"));
        assert_eq!(rx2.await.unwrap().unwrap(), Bytes::from_static(b"two"));
        assert!(q.is_empty());
        assert_eq!(q.mismatches(), 0);
    }

    #[test]
    fn control_command_gets_its_own_slot() {
        let mut q = PendingQueue::new();
        // A fire-and-forget control still occupies a slot so its ack cannot
        // complete the encrypted request queued behind it.
        push_plain(&mut q, "jdev/sps/io/a/on", None, far_future());
        let (tx, _rx) = waiter();
        push_plain(&mut q, "jdev/sys/getkey", Some(tx), far_future());

        let ack = q.resolve(Some("jdev/sps/io/a/on"), &no_keys()).unwrap();
        assert!(ack.resp.is_none());
        let answer = q.resolve(Some("jdev/sys/getkey"), &no_keys()).unwrap();
        assert!(answer.resp.is_some());
    }

    #[test]
    fn mismatched_control_is_counted_but_still_resolves() {
        let mut q = PendingQueue::new();
        push_plain(&mut q, "jdev/sys/getkey2/admin", None, far_future());
        let resolved = q.resolve(Some("jdev/sps/io/other/on"), &no_keys()).unwrap();
        assert!(!resolved.matched);
        assert_eq!(q.mismatches(), 1);
        assert!(q.is_empty());
    }

    #[test]
    fn missing_control_does_not_count_as_mismatch() {
        let mut q = PendingQueue::new();
        push_plain(&mut q, "data/LoxAPP3.json", None, far_future());
        let resolved = q.resolve(None, &no_keys()).unwrap();
        assert!(resolved.matched);
        assert_eq!(q.mismatches(), 0);
    }

    #[test]
    fn empty_queue_resolves_to_none() {
        let mut q = PendingQueue::new();
        assert!(q.resolve(Some("jdev/sys/getkey"), &no_keys()).is_none());
        q.note_unsolicited();
        assert_eq!(q.unsolicited(), 1);
    }

    #[tokio::test]
    async fn expired_entries_fail_with_timeout() {
        let mut q = PendingQueue::new();
        let (tx, rx) = waiter();
        let past = Instant::now() - Duration::from_secs(1);
        push_plain(&mut q, "jdev/sys/getkey", Some(tx), past);
        let (tx2, rx2) = waiter();
        push_plain(&mut q, "jdev/sys/getkey2/admin", Some(tx2), far_future());

        assert_eq!(q.expire(Instant::now()), 1);
        assert_eq!(q.timeouts(), 1);
        assert_eq!(q.len(), 1);
        assert!(matches!(rx.await.unwrap(), Err(Error::Timeout(_))));
        assert_eq!(q.expire(Instant::now()), 0);
        drop(rx2);
    }

    #[test]
    fn next_deadline_tracks_the_oldest_waiter() {
        let mut q = PendingQueue::new();
        assert_eq!(q.next_deadline(), None);
        let first = Instant::now() + Duration::from_secs(5);
        push_plain(&mut q, "jdev/sys/getkey", None, first);
        push_plain(
            &mut q,
            "jdev/sps/io/a/on",
            None,
            Instant::now() + Duration::from_secs(9),
        );
        assert_eq!(q.next_deadline(), Some(first));
        q.resolve(Some("jdev/sys/getkey"), &no_keys());
        assert_ne!(q.next_deadline(), Some(first));
    }

    #[tokio::test]
    async fn fail_all_closes_every_waiter() {
        let mut q = PendingQueue::new();
        let (tx, rx) = waiter();
        push_plain(&mut q, "jdev/sys/getkey", Some(tx), far_future());
        push_plain(&mut q, "jdev/sps/io/a/on", None, far_future());
        assert_eq!(q.fail_all("session ended"), 2);
        assert!(matches!(rx.await.unwrap(), Err(Error::Closed(_))));
        assert!(q.is_empty());
    }

    /// The point of storing the wire form: an echo that matches it byte for
    /// byte settles the correlation without touching the cipher. Proven by
    /// resolving with keys that could not possibly decrypt the blob.
    #[test]
    fn a_verbatim_echo_never_reaches_the_cipher() {
        let keys = SessionKeys::from_key_iv([9u8; 32], [3u8; 16]);
        let mut salt = SaltState::new();
        let wire = salt.encrypt(&keys, "jdev/sys/getkey2/admin").unwrap();

        let mut q = PendingQueue::new();
        q.push("jdev/sys/getkey2/admin", &wire, None, far_future());
        let resolved = q.resolve(Some(&wire), &no_keys()).unwrap();

        assert!(resolved.matched);
        assert!(
            resolved.actual.is_none(),
            "a decoded control means the slow path ran"
        );
        assert_eq!(q.mismatches(), 0);
    }

    /// The same echo with the spellings the Miniserver varies between still
    /// takes the fast path, so those quirks cost a byte scan rather than a
    /// decryption.
    #[test]
    fn the_fast_path_tolerates_the_echo_quirks() {
        let mut q = PendingQueue::new();
        for echo in [
            "/jdev/sys/enc/BLOB",
            "dev/sys/enc/BLOB",
            "jdev/sys/enc/BLOB\0",
        ] {
            q.push("jdev/sys/getkey", "jdev/sys/enc/BLOB", None, far_future());
            let resolved = q.resolve(Some(echo), &no_keys()).unwrap();
            assert!(resolved.matched, "{echo}");
            assert!(resolved.actual.is_none(), "{echo}");
        }
        assert_eq!(q.mismatches(), 0);
    }

    /// An echo that is not the blob we sent falls back to decrypting, and the
    /// decoded command is handed back for the mismatch warning.
    #[test]
    fn an_unexpected_echo_falls_back_to_decrypting() {
        let keys = SessionKeys::from_key_iv([9u8; 32], [3u8; 16]);
        let mut salt = SaltState::new();
        let sent = salt.encrypt(&keys, "jdev/sys/getkey2/admin").unwrap();
        let other = salt.encrypt(&keys, "jdev/sps/io/light/on").unwrap();

        let mut q = PendingQueue::new();
        q.push("jdev/sys/getkey2/admin", &sent, None, far_future());
        let resolved = q.resolve(Some(&other), &keys).unwrap();

        assert!(!resolved.matched);
        assert_eq!(resolved.actual.as_deref(), Some("jdev/sps/io/light/on"));
        assert_eq!(q.mismatches(), 1);
    }

    /// A firmware that re-encodes the echo instead of returning the blob
    /// verbatim would defeat the comparison. Correlation must not depend on it:
    /// the fallback recovers the plaintext and still resolves correctly.
    #[test]
    fn a_reencoded_echo_still_correlates_through_the_fallback() {
        let keys = SessionKeys::from_key_iv([5u8; 32], [7u8; 16]);
        let mut salt = SaltState::new();
        let sent = salt.encrypt(&keys, "jdev/sys/getkey").unwrap();
        // A fresh salt re-encrypts the same command into different ciphertext.
        salt.reset();
        let echoed = salt.encrypt(&keys, "jdev/sys/getkey").unwrap();
        assert_ne!(sent, echoed);

        let mut q = PendingQueue::new();
        q.push("jdev/sys/getkey", &sent, None, far_future());
        let resolved = q.resolve(Some(&echoed), &keys).unwrap();
        assert!(resolved.matched);
        assert_eq!(q.mismatches(), 0);
    }

    #[test]
    fn control_matching_tolerates_protocol_quirks() {
        assert!(control_matches("jdev/sys/getkey", "jdev/sys/getkey"));
        assert!(control_matches("dev/sys/getkey", "jdev/sys/getkey"));
        assert!(control_matches("/jdev/cfg/api", "jdev/cfg/api"));
        assert!(control_matches("jdev/sys/getkey\0", "jdev/sys/getkey"));
        // Hash arguments are elided in some echoes.
        assert!(control_matches(
            "authwithtoken/admin",
            "authwithtoken/HASH/admin"
        ));
        assert!(!control_matches(
            "jdev/sys/getkey2/admin",
            "jdev/sys/getvisusalt/admin"
        ));
        assert!(!control_matches("jdev/sps/io/x/on", "jdev/sys/getkey"));
        assert!(!control_matches(
            "jdev/sps/io/x/on",
            "authwithtoken/HASH/admin"
        ));
        // The io ack of a control command must not pass for a getkey answer.
        assert!(!control_matches(
            "jdev/sps/io/x/on",
            "jdev/sys/getkey2/admin"
        ));
    }

    #[test]
    fn getkey2_and_getvisusalt_are_distinguishable() {
        // Both answers carry key + salt + hashAlg; only the correlated command
        // tells them apart.
        let mut q = PendingQueue::new();
        push_plain(&mut q, "jdev/sys/getvisusalt/admin", None, far_future());
        let resolved = q
            .resolve(Some("jdev/sys/getvisusalt/admin"), &no_keys())
            .unwrap();
        assert!(resolved.matched);
        assert!(resolved.plaintext_cmd.starts_with("jdev/sys/getvisusalt/"));
    }

    #[test]
    fn control_scan_finds_the_field() {
        let payload = br#"{"LL": {"control": "jdev/sys/getkey", "value": "abc", "Code": "200"}}"#;
        assert_eq!(extract_ll_control(payload), Some("jdev/sys/getkey"));
    }

    /// The word-at-a-time search must agree with the obvious byte loop at every
    /// alignment, including matches that straddle a chunk boundary.
    #[test]
    fn word_search_matches_the_naive_scan() {
        let mut buf = vec![b'x'; 40];
        for pos in 0..buf.len() {
            buf.fill(b'x');
            buf[pos] = b'"';
            let naive = buf.iter().position(|b| *b == b'"');
            assert_eq!(find_byte(&buf, b'"'), naive, "quote at {pos}");

            buf.fill(b'x');
            buf[pos] = b'\\';
            let naive = buf.iter().position(|b| *b == b'"' || *b == b'\\');
            assert_eq!(find_either(&buf, b'"', b'\\'), naive, "escape at {pos}");
        }
        assert_eq!(find_byte(b"xxx", b'"'), None);
        assert_eq!(find_byte(b"", b'"'), None);
    }

    /// A quote-led candidate that is not the key must not stop the search.
    #[test]
    fn control_scan_skips_lookalike_keys() {
        let payload = br#"{"contro":"no","controlx":"no","control":"yes"}"#;
        assert_eq!(extract_ll_control(payload), Some("yes"));
    }

    /// The key has to fit inside the window completely, at any offset.
    #[test]
    fn control_scan_handles_every_key_offset() {
        for pad in 0..24 {
            let payload = format!(r#"{}{{"control":"jdev/sys/getkey"}}"#, " ".repeat(pad));
            assert_eq!(
                extract_ll_control(payload.as_bytes()),
                Some("jdev/sys/getkey"),
                "pad={pad}"
            );
        }
    }

    #[test]
    fn control_scan_ignores_payloads_without_the_field() {
        assert_eq!(extract_ll_control(br#"{"lastModified":"2024"}"#), None);
        assert_eq!(extract_ll_control(b""), None);
        // Beyond the key scan window the field is deliberately not found.
        let mut big = vec![b' '; CONTROL_KEY_SCAN_LIMIT];
        big.extend_from_slice(br#"{"LL":{"control":"jdev/sys/getkey"}}"#);
        assert_eq!(extract_ll_control(&big), None);
    }

    #[test]
    fn long_encrypted_control_values_are_still_read() {
        // An encrypted `getjwt` echo easily outgrows the key scan window; the
        // value must not be truncated with it.
        let blob = "a".repeat(CONTROL_KEY_SCAN_LIMIT * 2);
        let payload = format!(r#"{{"LL":{{"control":"jdev/sys/enc/{blob}","Code":"200"}}}}"#);
        let extracted = extract_ll_control(payload.as_bytes()).unwrap();
        assert_eq!(extracted, format!("jdev/sys/enc/{blob}"));
    }

    #[test]
    fn absurd_control_values_are_rejected() {
        let blob = "a".repeat(CONTROL_VALUE_LIMIT + 1);
        let payload = format!(r#"{{"LL":{{"control":"{blob}"}}}}"#);
        assert_eq!(extract_ll_control(payload.as_bytes()), None);
    }

    #[test]
    fn control_scan_rejects_non_string_and_escaped_values() {
        assert_eq!(extract_ll_control(br#"{"LL":{"control":123}}"#), None);
        assert_eq!(extract_ll_control(br#"{"LL":{"control":"a\/b"}}"#), None);
        assert_eq!(
            extract_ll_control(br#"{"LL":{"control":"unterminated"#),
            None
        );
    }

    #[test]
    fn encrypted_control_decodes_to_the_plaintext_command() {
        let keys = SessionKeys::from_key_iv([9u8; 32], [3u8; 16]);
        let mut salt = SaltState::new();
        let wire = salt.encrypt(&keys, "jdev/sys/getkey2/admin").unwrap();
        let decoded = decode_control(&wire, &keys).unwrap();
        assert_eq!(decoded, "jdev/sys/getkey2/admin");
        assert!(control_matches(&decoded, "jdev/sys/getkey2/admin"));
    }

    #[test]
    fn plain_control_passes_through_decode() {
        let keys = SessionKeys::from_key_iv([1u8; 32], [1u8; 16]);
        assert_eq!(
            decode_control("jdev/cfg/api", &keys).as_deref(),
            Some("jdev/cfg/api")
        );
    }

    #[test]
    fn cmd_label_keeps_secrets_out_of_logs() {
        assert_eq!(
            cmd_label("jdev/sys/getjwt/DEADBEEF/admin/4/uuid"),
            "jdev/sys/getjwt"
        );
        assert_eq!(cmd_label("authwithtoken/DEADBEEF/admin"), "authwithtoken");
        assert_eq!(cmd_label("jdev/sps/ios/VISUHASH/uuid/on"), "jdev/sps/ios");
        assert_eq!(cmd_label("keepalive"), "keepalive");
        assert_eq!(cmd_label(""), "");
    }
}
