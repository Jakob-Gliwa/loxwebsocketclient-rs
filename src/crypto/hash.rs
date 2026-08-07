//! Password / token / visu HMAC helpers (SHA1 | SHA256).

use crate::error::{Error, Result};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::Sha256;
use sonic_rs::JsonValueTrait;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

/// Hash algorithm selected by `getkey2` / token metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashAlg {
    #[default]
    Sha1,
    Sha256,
}

impl HashAlg {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            other => Err(Error::crypto(format!(
                "unrecognised hash algorithm: {other}"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
        }
    }
}

/// Key + user-salt from `getkey2` / `getvisusalt`.
#[derive(Debug, Clone)]
pub struct KeySalt {
    pub key_hex: String,
    pub salt: String,
    pub hash_alg: HashAlg,
}

impl KeySalt {
    pub fn from_ll_value(value: &sonic_rs::Value) -> Result<Self> {
        let key = value
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::protocol("missing key in key/salt response"))?
            .to_string();
        // {userSalt} is hashed exactly as transmitted; only the {key} is
        // hex-decoded to its ASCII form (protocol doc, "Hashing").
        let salt = value
            .get("salt")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::protocol("missing salt in key/salt response"))?
            .to_string();
        let alg = value
            .get("hashAlg")
            .and_then(|v| v.as_str())
            .unwrap_or("SHA1");
        Ok(Self {
            key_hex: key,
            salt,
            hash_alg: HashAlg::parse(alg)?,
        })
    }
}

/// `{password}:{userSalt}` → uppercase hex digest.
pub fn password_hash(alg: HashAlg, password: &str, user_salt: &str) -> String {
    let data = format!("{password}:{user_salt}");
    match alg {
        HashAlg::Sha1 => {
            use sha1::Digest;
            hex::encode_upper(Sha1::digest(data.as_bytes()))
        }
        HashAlg::Sha256 => {
            use sha2::Digest;
            hex::encode_upper(Sha256::digest(data.as_bytes()))
        }
    }
}

fn hmac_hex(alg: HashAlg, key: &[u8], data: &[u8]) -> Result<String> {
    match alg {
        HashAlg::Sha1 => {
            let mut mac =
                HmacSha1::new_from_slice(key).map_err(|e| Error::crypto(e.to_string()))?;
            mac.update(data);
            Ok(hex::encode(mac.finalize().into_bytes()))
        }
        HashAlg::Sha256 => {
            let mut mac =
                HmacSha256::new_from_slice(key).map_err(|e| Error::crypto(e.to_string()))?;
            mac.update(data);
            Ok(hex::encode(mac.finalize().into_bytes()))
        }
    }
}

/// Credential hash for `getjwt`: HMAC(key, `user:pwHash`).
pub fn hash_credentials(key_salt: &KeySalt, password: &str, username: &str) -> Result<String> {
    let pw_hash = password_hash(key_salt.hash_alg, password, &key_salt.salt);
    let user_pw = format!("{username}:{pw_hash}");
    let key = hex::decode(&key_salt.key_hex).map_err(|e| Error::crypto(e.to_string()))?;
    hmac_hex(key_salt.hash_alg, &key, user_pw.as_bytes())
}

/// Visu password hash for secured IOs: HMAC(key, pwHash) — no username prefix.
pub fn hash_visu_password(key_salt: &KeySalt, visu_pw: &str) -> Result<String> {
    let pw_hash = password_hash(key_salt.hash_alg, visu_pw, &key_salt.salt);
    let key = hex::decode(&key_salt.key_hex).map_err(|e| Error::crypto(e.to_string()))?;
    hmac_hex(key_salt.hash_alg, &key, pw_hash.as_bytes())
}

/// Token hash: HMAC(getkey_result, token_bytes) using the token's hash algorithm.
pub fn hash_token(alg: HashAlg, key_hex: &str, token: &str) -> Result<String> {
    let key = hex::decode(key_hex).map_err(|e| Error::crypto(e.to_string()))?;
    hmac_hex(alg, &key, token.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_sha1_upper() {
        let h = password_hash(HashAlg::Sha1, "pass", "salt");
        assert_eq!(h, h.to_uppercase());
        assert_eq!(h.len(), 40);
    }

    #[test]
    fn password_hash_sha256_upper() {
        let h = password_hash(HashAlg::Sha256, "pass", "salt");
        assert_eq!(h, h.to_uppercase());
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn credentials_hmac_deterministic() {
        let ks = KeySalt {
            key_hex: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
            salt: "deadbeef".into(),
            hash_alg: HashAlg::Sha1,
        };
        let a = hash_credentials(&ks, "secret", "admin").unwrap();
        let b = hash_credentials(&ks, "secret", "admin").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 40);
    }

    #[test]
    fn visu_hash_no_username() {
        let ks = KeySalt {
            key_hex: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".into(),
            salt: "visusalt".into(),
            hash_alg: HashAlg::Sha256,
        };
        let h = hash_visu_password(&ks, "1234").unwrap();
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn parse_alg() {
        assert_eq!(HashAlg::parse("SHA1").unwrap(), HashAlg::Sha1);
        assert_eq!(HashAlg::parse("SHA256").unwrap(), HashAlg::Sha256);
        assert!(HashAlg::parse("MD5").is_err());
    }
}
