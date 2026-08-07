//! AES-256-CBC session encryption with Loxone ZeroBytePadding.
//!
//! The session state is deliberately split in two: [`SessionKeys`] is immutable
//! and cheap to clone, so both the reader and the writer half of a connection
//! can hold one, while [`SaltState`] is mutable and must stay with the single
//! task that encrypts outgoing commands. Sharing the salt would break the
//! `salt` / `nextSalt` sequence the Miniserver expects.

use crate::error::{Error, Result};
use aes::cipher::block::{BlockModeDecrypt, BlockModeEncrypt};
use aes::cipher::{InnerIvInit, KeyInit, KeyIvInit, block_padding::NoPadding};
use aes::{Aes256, Aes256Enc};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use cbc::{Decryptor, Encryptor};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

type Aes256CbcEnc = Encryptor<Aes256Enc>;
type Aes256CbcDec = Decryptor<Aes256>;

pub const IV_BYTES: usize = 16;
pub const AES_KEY_SIZE: usize = 32;
pub const AES_BLOCK_SIZE: usize = 16;
pub const SALT_BYTES: usize = 16;
pub const SALT_MAX_AGE_SECONDS: u64 = 60 * 60;
pub const SALT_MAX_USE_COUNT: u32 = 30;
pub const CMD_ENCRYPT: &str = "jdev/sys/enc/";

/// AES session key and IV negotiated via `jdev/sys/keyexchange`.
///
/// The `Debug` implementation deliberately prints no key material.
#[derive(Clone)]
pub struct SessionKeys {
    key: [u8; AES_KEY_SIZE],
    iv: [u8; IV_BYTES],
    /// Round keys, expanded once per session.
    ///
    /// The key schedule dominated the per-command cost: every command used to
    /// build an `Encryptor` from the raw key, and expanding an AES-256 schedule
    /// is far more work than encrypting the three or four blocks a command
    /// occupies. Cloning this instead is a memcpy of the round keys.
    ///
    /// The raw `key` stays because [`Self::session_payload`] and the decrypt
    /// path still need it, and because the schedule cannot be run backwards.
    cipher: Aes256Enc,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys").finish_non_exhaustive()
    }
}

impl Default for SessionKeys {
    fn default() -> Self {
        Self::generate()
    }
}

impl SessionKeys {
    /// Draw a fresh random key/IV pair.
    pub fn generate() -> Self {
        let mut key = [0u8; AES_KEY_SIZE];
        let mut iv = [0u8; IV_BYTES];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);
        Self::from_key_iv(key, iv)
    }

    /// Construct with fixed key/iv (for tests).
    pub fn from_key_iv(key: [u8; AES_KEY_SIZE], iv: [u8; IV_BYTES]) -> Self {
        Self {
            cipher: Aes256Enc::new((&key).into()),
            key,
            iv,
        }
    }

    pub fn key(&self) -> &[u8; AES_KEY_SIZE] {
        &self.key
    }

    pub fn iv(&self) -> &[u8; IV_BYTES] {
        &self.iv
    }

    /// Hex-encoded key and IV for RSA session wrap: `"{hexKey}:{hexIv}"`.
    pub fn session_payload(&self) -> String {
        format!("{}:{}", hex::encode(self.key), hex::encode(self.iv))
    }

    /// Decrypt a control field that may be an `jdev/sys/enc/...` blob.
    ///
    /// The result still carries the `salt/…` or `nextSalt/…` prefix the command
    /// was sent with.
    pub fn decrypt_control_response(&self, response: &str) -> Result<String> {
        let encoded = response
            .rsplit(CMD_ENCRYPT)
            .next()
            .ok_or_else(|| Error::crypto("missing enc prefix"))?;
        // May still be percent-encoded from the wire.
        let decoded_pct = percent_encoding::percent_decode_str(encoded)
            .decode_utf8()
            .map_err(|e| Error::crypto(e.to_string()))?;
        let encrypted = B64
            .decode(decoded_pct.as_ref())
            .map_err(|e| Error::crypto(e.to_string()))?;
        let plain = aes_decrypt_zerobyte(&self.key, &self.iv, &encrypted)?;
        String::from_utf8(plain).map_err(|e| Error::crypto(e.to_string()))
    }
}

/// Command-salt bookkeeping for the sending side of one connection.
///
/// A default-constructed value is already "reset": the first encrypted command
/// emits `salt/{salt}/{cmd}`. Reusing a `SaltState` across connections would
/// emit `nextSalt/{stale}/…` and earn a spurious 401.
///
/// The two scratch buffers make [`Self::encrypt`] reuse one plaintext and one
/// Base64 allocation across commands instead of drawing fresh ones each time.
/// They are sound precisely because a `SaltState` already belongs to exactly
/// one task — the writer — for the same reason the salt sequence does.
#[derive(Clone, Default)]
pub struct SaltState {
    salt: String,
    salt_used_count: u32,
    salt_time_stamp: u64,
    /// Salted plaintext, then the ciphertext encrypted over it in place.
    scratch: Vec<u8>,
    /// Base64 of `scratch`, before percent-encoding.
    encoded: Vec<u8>,
}

/// Prints the salt sequence but not the scratch buffers, which hold the last
/// command in plaintext and in ciphertext.
impl std::fmt::Debug for SaltState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SaltState")
            .field("salt", &self.salt)
            .field("salt_used_count", &self.salt_used_count)
            .field("salt_time_stamp", &self.salt_time_stamp)
            .finish_non_exhaustive()
    }
}

impl SaltState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop salt state so the next command starts a fresh `salt/...` sequence.
    pub fn reset(&mut self) {
        self.salt.clear();
        self.salt_used_count = 0;
        self.salt_time_stamp = 0;
        self.scratch.clear();
        self.encoded.clear();
    }

    /// Currently active salt (empty before the first command).
    pub fn salt(&self) -> &str {
        &self.salt
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn generate_salt(&mut self) {
        let mut raw = [0u8; SALT_BYTES];
        rand::thread_rng().fill_bytes(&mut raw);
        // Python uses pathname2url(hex) — hex is already URL-safe.
        self.salt = hex::encode(raw);
        self.salt_time_stamp = Self::now_secs();
        self.salt_used_count = 0;
    }

    fn new_salt_needed(&mut self) -> bool {
        self.salt_used_count += 1;
        self.salt_used_count > SALT_MAX_USE_COUNT
            || Self::now_secs().saturating_sub(self.salt_time_stamp) > SALT_MAX_AGE_SECONDS
    }

    /// Write the salted plaintext for `command` into [`Self::scratch`],
    /// advancing the salt state.
    fn fill_salted_plaintext(&mut self, command: &str) {
        self.scratch.clear();
        if !self.salt.is_empty() && self.new_salt_needed() {
            // Reuses the outgoing salt's allocation rather than cloning it;
            // this branch runs once per `SALT_MAX_USE_COUNT` commands anyway.
            let previous = std::mem::take(&mut self.salt);
            self.generate_salt();
            self.scratch.extend_from_slice(b"nextSalt/");
            self.scratch.extend_from_slice(previous.as_bytes());
            self.scratch.push(b'/');
        } else {
            if self.salt.is_empty() {
                self.generate_salt();
            }
            self.scratch.extend_from_slice(b"salt/");
        }
        self.scratch.extend_from_slice(self.salt.as_bytes());
        self.scratch.push(b'/');
        self.scratch.extend_from_slice(command.as_bytes());
        self.scratch.push(0);
    }

    /// Build the salted plaintext for `command`, advancing the salt state.
    pub fn salted_plaintext(&mut self, command: &str) -> String {
        self.fill_salted_plaintext(command);
        String::from_utf8_lossy(&self.scratch).into_owned()
    }

    /// Encrypt a plaintext command into `jdev/sys/enc/{percent-encoded-b64}`.
    ///
    /// Everything up to the returned `String` happens in the two scratch
    /// buffers: the plaintext is zero-padded and encrypted where it was
    /// written, Base64 goes straight into the second buffer, and the percent
    /// encoding is appended to the one output allocation. What used to be five
    /// allocations and a key schedule per command is now one allocation.
    pub fn encrypt(&mut self, keys: &SessionKeys, command: &str) -> Result<String> {
        self.fill_salted_plaintext(command);
        // Loxone's ZeroBytePadding: pad with 0x00 to the block size, and pad
        // nothing at all when the plaintext already ends on a boundary.
        let padded = self.scratch.len().next_multiple_of(AES_BLOCK_SIZE);
        self.scratch.resize(padded, 0);
        Aes256CbcEnc::inner_iv_init(keys.cipher.clone(), (&keys.iv).into())
            .encrypt_padded::<NoPadding>(&mut self.scratch, padded)
            .map_err(|_| Error::crypto("AES encrypt failed"))?;

        let b64_len = padded.div_ceil(3) * 4;
        self.encoded.resize(b64_len, 0);
        let written = B64
            .encode_slice(&self.scratch, &mut self.encoded)
            .map_err(|_| Error::crypto("base64 buffer too small"))?;
        let encoded = std::str::from_utf8(&self.encoded[..written])
            .map_err(|_| Error::crypto("base64 produced non-ASCII"))?;

        // Worst case every Base64 byte needs escaping; over-reserving a few
        // hundred bytes is cheaper than a realloc mid-encode.
        let mut out = String::with_capacity(CMD_ENCRYPT.len() + 3 * written);
        out.push_str(CMD_ENCRYPT);
        percent_encode_base64(encoded, &mut out);
        Ok(out)
    }
}

/// Percent-encode Base64 into `out` exactly as `encodeURIComponent` would.
///
/// Of the Base64 alphabet only `+`, `/` and `=` are not URI-unreserved, so this
/// is byte-identical to `utf8_percent_encode(_, NON_ALPHANUMERIC)` for Base64
/// input — pinned by `percent_encoding_matches_the_general_encoder`. The
/// general encoder has to walk every character through a `Cow` iterator;
/// copying the alphanumeric runs wholesale skips that.
///
/// Input outside the Base64 alphabet is passed through rather than escaped, so
/// this is not a general-purpose URI encoder.
pub fn percent_encode_base64(encoded: &str, out: &mut String) {
    let mut run_start = 0;
    for (i, byte) in encoded.bytes().enumerate() {
        let escape = match byte {
            b'+' => "%2B",
            b'/' => "%2F",
            b'=' => "%3D",
            _ => continue,
        };
        out.push_str(&encoded[run_start..i]);
        out.push_str(escape);
        run_start = i + 1;
    }
    out.push_str(&encoded[run_start..]);
}

/// Strip the `salt/{salt}/` or `nextSalt/{prev}/{next}/` prefix from a decrypted
/// command, plus the trailing NUL terminator if it survived decryption.
///
/// Returns the input unchanged when no known prefix is present.
pub fn strip_salt_prefix(plaintext: &str) -> &str {
    let trimmed = plaintext.trim_end_matches('\0');
    if let Some(rest) = trimmed.strip_prefix("nextSalt/") {
        // Two salt segments follow.
        rest.split_once('/')
            .and_then(|(_, rest)| rest.split_once('/'))
            .map(|(_, cmd)| cmd)
            .unwrap_or(trimmed)
    } else if let Some(rest) = trimmed.strip_prefix("salt/") {
        rest.split_once('/').map(|(_, cmd)| cmd).unwrap_or(trimmed)
    } else {
        trimmed
    }
}

/// AES-256-CBC encrypt with ZeroBytePadding (pad with 0x00 to block size).
pub fn aes_encrypt_zerobyte(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    let mut buf = data.to_vec();
    let pad = (16 - (buf.len() % 16)) % 16;
    buf.extend(std::iter::repeat_n(0u8, pad));
    // When already aligned, Loxone still pads a full block of zeros? Python:
    // `data += b"\x00" * ((-len(data)) % 16)` — if len % 16 == 0, pad is 0.
    let encryptor = Aes256CbcEnc::new(key.into(), iv.into());
    let len = buf.len();
    encryptor
        .encrypt_padded::<NoPadding>(&mut buf, len)
        .map_err(|_| Error::crypto("AES encrypt failed"))?;
    Ok(buf)
}

/// AES-256-CBC decrypt and strip trailing NUL (`rstrip(0)`).
pub fn aes_decrypt_zerobyte(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        return Err(Error::crypto("ciphertext length not multiple of 16"));
    }
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    let mut buf = data.to_vec();
    decryptor
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|_| Error::crypto("AES decrypt failed"))?;
    while buf.last() == Some(&0) {
        buf.pop();
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

    /// The pipeline [`SaltState::encrypt`] replaced, kept verbatim as its
    /// oracle: allocate per stage, and percent-encode with the general encoder.
    fn reference_encrypt(keys: &SessionKeys, plaintext: &str) -> String {
        let encrypted = aes_encrypt_zerobyte(&keys.key, &keys.iv, plaintext.as_bytes()).unwrap();
        let encoded = B64.encode(encrypted);
        let encoded_url = utf8_percent_encode(&encoded, NON_ALPHANUMERIC).to_string();
        format!("{CMD_ENCRYPT}{encoded_url}")
    }

    /// Byte-for-byte agreement with the old implementation, over commands whose
    /// salted plaintext lands on either side of every block boundary.
    #[test]
    fn encrypt_matches_the_reference_pipeline() {
        let keys = SessionKeys::from_key_iv([0x31u8; 32], [0x41u8; 16]);
        for len in 0..64 {
            let command = "x".repeat(len);
            let mut salt = SaltState::new();
            let wire = salt.encrypt(&keys, &command).unwrap();

            // Recovering the plaintext through the decrypt path gives the
            // reference the exact input `encrypt` used, salt and all. The
            // terminator goes back on: `rstrip(0)` took it off with the padding.
            let plain = keys.decrypt_control_response(&wire).unwrap();
            assert_eq!(strip_salt_prefix(&plain), command);
            assert_eq!(wire, reference_encrypt(&keys, &format!("{plain}\0")));
        }
    }

    /// [`percent_encode_base64`] only special-cases `+`, `/` and `=`. That
    /// is only safe because nothing else in the Base64 alphabet needs escaping,
    /// which this pins against the general encoder over random input.
    #[test]
    fn percent_encoding_matches_the_general_encoder() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for len in 0..96 {
            // Every remainder mod 3, so all three `=` padding cases appear.
            let raw: Vec<u8> = (0..len).map(|_| rng.r#gen()).collect();
            let encoded = B64.encode(&raw);
            let mut ours = String::new();
            percent_encode_base64(&encoded, &mut ours);
            assert_eq!(
                ours,
                utf8_percent_encode(&encoded, NON_ALPHANUMERIC).to_string(),
                "input {raw:02x?}"
            );
        }
    }

    /// The runs the fast path copies wholesale must survive being adjacent to,
    /// or made entirely of, escaped bytes.
    #[test]
    fn percent_encoding_handles_runs_of_escapes() {
        for input in ["", "+", "///", "+/=", "A+B/C=", "====", "AAAA"] {
            let mut ours = String::new();
            percent_encode_base64(input, &mut ours);
            assert_eq!(
                ours,
                utf8_percent_encode(input, NON_ALPHANUMERIC).to_string(),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn roundtrip_zerobyte_padding() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        // Protocol plaintext ends with `\0`; decrypt rstrip(0) removes padding *and*
        // that terminator (matching Python `rstrip(b"\x00")`).
        let plain = b"salt/abc/jdev/sys/getkey\0";
        let ct = aes_encrypt_zerobyte(&key, &iv, plain).unwrap();
        assert_eq!(ct.len() % 16, 0);
        let pt = aes_decrypt_zerobyte(&key, &iv, &ct).unwrap();
        assert_eq!(pt, b"salt/abc/jdev/sys/getkey");
    }

    #[test]
    fn encrypt_command_prefix() {
        let keys = SessionKeys::from_key_iv([7u8; 32], [8u8; 16]);
        let mut salt = SaltState::new();
        let enc = salt.encrypt(&keys, "jdev/sys/getkey").unwrap();
        assert!(enc.starts_with(CMD_ENCRYPT));
        // Must be percent-encoded (no raw '+', '/' or '=' from base64 left
        // unencoded).
        let body = &enc[CMD_ENCRYPT.len()..];
        assert!(!body.contains('/'));
        assert!(!body.contains('+'));
        assert!(!body.contains('='));
    }

    /// The scratch buffers are reused, so a shorter command must not leave a
    /// longer predecessor's tail behind.
    #[test]
    fn a_reused_salt_state_does_not_carry_the_previous_command_over() {
        let keys = SessionKeys::from_key_iv([0x9au8; 32], [0x0eu8; 16]);
        let mut reused = SaltState::new();
        reused.encrypt(&keys, &"long".repeat(50)).unwrap();
        let wire = reused.encrypt(&keys, "short").unwrap();

        let plain = keys.decrypt_control_response(&wire).unwrap();
        assert_eq!(strip_salt_prefix(&plain), "short");
        assert_eq!(wire, reference_encrypt(&keys, &format!("{plain}\0")));
    }

    #[test]
    fn reset_clears_state() {
        let keys = SessionKeys::from_key_iv([1u8; 32], [2u8; 16]);
        let mut salt = SaltState::new();
        let _ = salt.encrypt(&keys, "a").unwrap();
        assert!(!salt.salt().is_empty());
        salt.reset();
        assert!(salt.salt().is_empty());
        assert_eq!(salt.salt_used_count, 0);
    }

    #[test]
    fn first_command_uses_salt_prefix() {
        let mut salt = SaltState::new();
        let plain = salt.salted_plaintext("jdev/sys/getkey");
        assert!(plain.starts_with("salt/"));
        assert!(plain.ends_with("/jdev/sys/getkey\0"));
        assert!(!plain.starts_with("nextSalt/"));
    }

    #[test]
    fn salt_is_reused_until_max_use_count() {
        let mut salt = SaltState::new();
        let first = salt.salted_plaintext("cmd0");
        let active = salt.salt().to_string();
        for i in 1..SALT_MAX_USE_COUNT {
            let p = salt.salted_plaintext(&format!("cmd{i}"));
            assert!(
                p.starts_with(&format!("salt/{active}/")),
                "iteration {i}: {p}"
            );
        }
        assert!(first.starts_with(&format!("salt/{active}/")));
    }

    #[test]
    fn salt_rotates_after_max_use_count() {
        let mut salt = SaltState::new();
        // The command that creates the salt does not count as a use, so the
        // salt survives `SALT_MAX_USE_COUNT` further commands.
        for i in 0..=SALT_MAX_USE_COUNT {
            salt.salted_plaintext(&format!("cmd{i}"));
        }
        let previous = salt.salt().to_string();
        let rotated = salt.salted_plaintext("rotate");
        assert!(rotated.starts_with(&format!("nextSalt/{previous}/")));
        assert!(rotated.ends_with("/rotate\0"));
        assert_ne!(salt.salt(), previous);
        // The rotation resets the counter, so the new salt is reused again.
        let after = salt.salted_plaintext("next");
        assert!(after.starts_with(&format!("salt/{}/", salt.salt())));
    }

    #[test]
    fn stale_salt_rotates_by_age() {
        let mut salt = SaltState::new();
        salt.salted_plaintext("cmd");
        let previous = salt.salt().to_string();
        salt.salt_time_stamp = SaltState::now_secs() - SALT_MAX_AGE_SECONDS - 1;
        let rotated = salt.salted_plaintext("cmd");
        assert!(rotated.starts_with(&format!("nextSalt/{previous}/")));
    }

    #[test]
    fn reset_restarts_the_salt_sequence() {
        let mut salt = SaltState::new();
        for i in 0..=SALT_MAX_USE_COUNT + 1 {
            salt.salted_plaintext(&format!("cmd{i}"));
        }
        assert!(!salt.salt().is_empty());
        salt.reset();
        assert!(salt.salted_plaintext("first").starts_with("salt/"));
    }

    #[test]
    fn session_payload_format() {
        let keys = SessionKeys::from_key_iv([0xabu8; 32], [0xcd; 16]);
        let p = keys.session_payload();
        let parts: Vec<_> = p.split(':').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 64);
        assert_eq!(parts[1].len(), 32);
    }

    #[test]
    fn encrypt_decrypt_control_roundtrip() {
        let keys = SessionKeys::from_key_iv([3u8; 32], [4u8; 16]);
        let mut salt = SaltState::new();
        let enc = salt.encrypt(&keys, "jdev/sys/getkey2/admin").unwrap();
        let plain = keys.decrypt_control_response(&enc).unwrap();
        assert_eq!(strip_salt_prefix(&plain), "jdev/sys/getkey2/admin");
    }

    #[test]
    fn strip_salt_prefix_variants() {
        assert_eq!(
            strip_salt_prefix("salt/aabb/jdev/sys/getkey"),
            "jdev/sys/getkey"
        );
        assert_eq!(
            strip_salt_prefix("nextSalt/aabb/ccdd/jdev/sps/io/x/on"),
            "jdev/sps/io/x/on"
        );
        assert_eq!(strip_salt_prefix("salt/aabb/cmd\0"), "cmd");
        assert_eq!(strip_salt_prefix("jdev/cfg/api"), "jdev/cfg/api");
        // Malformed prefixes are returned unchanged rather than truncated.
        assert_eq!(strip_salt_prefix("salt/only"), "salt/only");
        assert_eq!(strip_salt_prefix("nextSalt/a/b"), "nextSalt/a/b");
    }

    #[test]
    fn debug_hides_key_material() {
        let keys = SessionKeys::from_key_iv([0x5au8; 32], [0x5a; 16]);
        let rendered = format!("{keys:?}");
        assert!(!rendered.contains("5a"));
        assert!(!rendered.contains("90"));
    }
}
