//! RSA PKCS#1 v1.5 session-key wrap for WebSocket keyexchange.

use crate::error::{Error, Result};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};

/// Normalize a Miniserver public key into a strict SPKI PEM.
///
/// Loxone returns a SubjectPublicKeyInfo blob mislabeled as `CERTIFICATE`,
/// often as a single line with no wrapping. The `pem`/`rsa` crates reject
/// overlong Base64 lines, so we rewrite markers and wrap at 64 chars.
pub fn normalize_public_key_pem(pem: &str) -> String {
    let mut s = pem.trim().replace('\r', "");
    s = s
        .replace("-----BEGIN CERTIFICATE-----", "-----BEGIN PUBLIC KEY-----")
        .replace("-----END CERTIFICATE-----", "-----END PUBLIC KEY-----");

    // Extract Base64 body between headers (tolerate missing newlines).
    const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
    const END: &str = "-----END PUBLIC KEY-----";
    let body = if let (Some(a), Some(b)) = (s.find(BEGIN), s.find(END)) {
        let start = a + BEGIN.len();
        s[start..b]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
    } else {
        s.chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect::<String>()
    };

    let mut out = String::with_capacity(body.len() + 64);
    out.push_str(BEGIN);
    out.push('\n');
    for chunk in body.as_bytes().chunks(64) {
        // body is ASCII Base64
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(END);
    out.push('\n');
    out
}

/// Import an RSA public key from PEM (SPKI or PKCS#1).
pub fn import_public_key(pem: &str) -> Result<RsaPublicKey> {
    let normalized = normalize_public_key_pem(pem);
    match RsaPublicKey::from_public_key_pem(&normalized) {
        Ok(key) => Ok(key),
        Err(spki_err) => RsaPublicKey::from_pkcs1_pem(&normalized)
            .map_err(|pkcs1_err| Error::crypto(format!("SPKI: {spki_err}; PKCS1: {pkcs1_err}"))),
    }
}

/// RSA-encrypt `"{hexKey}:{hexIv}"` and return **raw** Base64 (no URI-encoding).
///
/// Critical: WS `jdev/sys/keyexchange/{b64}` must NOT URI-encode the Base64 —
/// the Miniserver does not URL-decode it there (verified empirically in Python).
pub fn wrap_session_key(public_key_pem: &str, session_payload: &str) -> Result<String> {
    let key = import_public_key(public_key_pem)?;
    let mut rng = rand::thread_rng();
    let encrypted = key
        .encrypt(&mut rng, Pkcs1v15Encrypt, session_payload.as_bytes())
        .map_err(|e| Error::crypto(format!("RSA encrypt failed: {e}")))?;
    Ok(B64.encode(encrypted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};

    fn test_keypair() -> (RsaPrivateKey, String) {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);
        use rsa::pkcs8::EncodePublicKey;
        let pem = pub_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        (priv_key, pem)
    }

    #[test]
    fn normalize_certificate_markers() {
        let input = "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----";
        let out = normalize_public_key_pem(input);
        assert!(out.contains("BEGIN PUBLIC KEY"));
        assert!(out.contains("END PUBLIC KEY"));
        assert!(!out.contains("CERTIFICATE"));
    }

    #[test]
    fn normalize_oneline_certificate_style_spki() {
        // Miniserver-style: mislabeled SPKI, no newlines in the body.
        let (priv_key, pem) = test_keypair();
        let body: String = pem.lines().filter(|l| !l.starts_with('-')).collect();
        let oneline = format!("-----BEGIN CERTIFICATE-----{body}-----END CERTIFICATE-----");
        let key = import_public_key(&oneline).expect("import oneline MS-style PEM");
        assert_eq!(key.n(), priv_key.n());
    }

    #[test]
    fn wrap_and_unwrap_session() {
        let (priv_key, pem) = test_keypair();
        let payload = "aabbcc:ddeeff";
        let b64 = wrap_session_key(&pem, payload).unwrap();
        // Must be raw base64 — may contain + / =
        assert!(!b64.contains('%'));
        let ct = B64.decode(&b64).unwrap();
        let pt = priv_key.decrypt(Pkcs1v15Encrypt, &ct).unwrap();
        assert_eq!(String::from_utf8(pt).unwrap(), payload);
        // Ensure public key has expected size
        assert!(priv_key.n().bits() >= 2048);
    }
}
