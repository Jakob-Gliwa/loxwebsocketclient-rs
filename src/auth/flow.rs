//! Token acquire / auth / refresh / kill command builders and response parsing.

use crate::auth::token::LxToken;
use crate::crypto::{HashAlg, KeySalt, hash_credentials, hash_token};
use crate::error::{Error, Result};
use sonic_rs::{JsonValueTrait, Value};

/// Default client identity matching Python `loxinflux` constants.
pub const DEFAULT_CLIENT_UUID: &str = "edfc5f9a-df3f-4cad-9dddcdc42c732be2";
pub const DEFAULT_CLIENT_INFO: &str = "loxinflux";

pub const CMD_GET_KEY_AND_SALT: &str = "jdev/sys/getkey2/";
pub const CMD_REQUEST_TOKEN_JWT: &str = "jdev/sys/getjwt/";
pub const CMD_GET_KEY: &str = "jdev/sys/getkey";
pub const CMD_AUTH_WITH_TOKEN: &str = "authwithtoken/";
pub const CMD_REFRESH_TOKEN_JWT: &str = "jdev/sys/refreshjwt/";
pub const CMD_CHECK_TOKEN: &str = "jdev/sys/checktoken/";
pub const CMD_KILL_TOKEN: &str = "jdev/sys/killtoken/";
pub const CMD_GET_VISUAL_PASSWD: &str = "jdev/sys/getvisusalt/";
pub const CMD_KEY_EXCHANGE: &str = "jdev/sys/keyexchange/";
pub const CMD_ENABLE_UPDATES: &str = "jdev/sps/enablebinstatusupdate";

/// Permission requested when acquiring a token.
///
/// The protocol document lists many permission bits, but only these two are
/// valid for opening a connection. The choice controls the token's lifespan:
/// `Web` tokens expire within hours, `App` tokens last weeks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum TokenPermission {
    /// Short-lived web permission (ID 2).
    Web = 2,
    /// Long-lived app permission (ID 4).
    #[default]
    App = 4,
}

impl TokenPermission {
    /// Numeric ID as it appears in the `getjwt` command.
    pub fn id(self) -> u32 {
        self as u32
    }
}

impl std::fmt::Display for TokenPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id())
    }
}

/// Read LL status code accepting both `Code` and `code` casings.
pub fn ll_status_code(ll: &Value) -> Option<&str> {
    ll.get("Code")
        .and_then(|v| v.as_str())
        .or_else(|| ll.get("code").and_then(|v| v.as_str()))
}

pub fn parse_json(payload: &[u8]) -> Result<Value> {
    sonic_rs::from_slice(payload).map_err(|e| Error::json(e.to_string()))
}

/// Human-readable hint for a non-200 LL status code.
///
/// The wording follows the "Returned Error-Codes" table of the protocol
/// document; 420 only appears in its troubleshooting section.
pub fn ll_status_hint(code: &str) -> &'static str {
    match code {
        "400" => " (bad request — command must be encrypted)",
        "401" => " (credentials or token rejected, or the request failed to decrypt)",
        "403" => " (the requesting user lacks the rights for this request)",
        "404" => " (unrecognized command)",
        "420" => " (authentication timed out)",
        "423" => " (the requesting user is disabled)",
        "500" => " (Miniserver internal error)",
        "503" => " (Miniserver is restarting and not ready for requests)",
        "901" => " (maximum number of concurrent connections reached)",
        _ => "",
    }
}

/// Whether an LL status code means the token itself is no longer usable.
///
/// Deliberately narrow. 901 is *not* in this set even though it is a refusal:
/// it reports that the Miniserver is at its connection limit, which says
/// nothing about the token. Discarding one there would throw away a valid
/// token and then ask for a replacement over the very connection the
/// Miniserver just said it has no room for.
pub fn ll_status_invalidates_token(code: &str) -> bool {
    matches!(code, "401" | "403")
}

/// The error a non-200 LL status maps to.
///
/// Two codes get a variant of their own because the supervisor has to react to
/// them differently from an ordinary authentication failure: 901 is transient
/// and earns the long backoff, 423 is administrative and cannot be retried.
pub fn ll_status_error(code: &str) -> Error {
    match code {
        "423" => Error::UserDisabled,
        "901" => Error::TooManyConnections,
        _ => Error::auth(format!("LL status {code}{}", ll_status_hint(code))),
    }
}

pub fn require_ll_ok(root: &Value) -> Result<&Value> {
    let ll = root
        .get("LL")
        .ok_or_else(|| Error::protocol("missing LL in response"))?;
    let code = ll_status_code(ll).unwrap_or("");
    if code != "200" {
        return Err(ll_status_error(code));
    }
    Ok(ll)
}

/// LL status code of a raw payload, without materializing the whole document
/// twice. Returns `None` if the payload is not an LL envelope.
pub fn payload_ll_status(payload: &[u8]) -> Option<String> {
    let root = parse_json(payload).ok()?;
    let ll = root.get("LL")?;
    ll_status_code(ll).map(str::to_string)
}

/// Build `getkey2/{user}` command.
pub fn cmd_getkey2(username: &str) -> String {
    format!("{CMD_GET_KEY_AND_SALT}{username}")
}

/// Build the `getjwt` command after hashing credentials.
pub fn cmd_request_token(
    cred_hash: &str,
    username: &str,
    permission: TokenPermission,
    client_uuid: &str,
    client_info: &str,
) -> String {
    format!(
        "{CMD_REQUEST_TOKEN_JWT}{cred_hash}/{username}/{}/{client_uuid}/{client_info}",
        permission.id()
    )
}

pub fn cmd_auth_with_token(token_hash: &str, username: &str) -> String {
    format!("{CMD_AUTH_WITH_TOKEN}{token_hash}/{username}")
}

pub fn cmd_refresh_token(token_hash: &str, username: &str) -> String {
    format!("{CMD_REFRESH_TOKEN_JWT}{token_hash}/{username}")
}

/// Build `checktoken/{tokenHash}/{user}` — validates without renewing.
pub fn cmd_check_token(token_hash: &str, username: &str) -> String {
    format!("{CMD_CHECK_TOKEN}{token_hash}/{username}")
}

/// Build `killtoken/{tokenHash}/{user}` — invalidates the token server-side.
pub fn cmd_kill_token(token_hash: &str, username: &str) -> String {
    format!("{CMD_KILL_TOKEN}{token_hash}/{username}")
}

pub fn cmd_get_visu_salt(username: &str) -> String {
    format!("{CMD_GET_VISUAL_PASSWD}{username}")
}

/// Parse getkey2 response into [`KeySalt`].
pub fn parse_key_salt(payload: &[u8]) -> Result<KeySalt> {
    let root = parse_json(payload)?;
    let ll = require_ll_ok(&root)?;
    let value = ll
        .get("value")
        .ok_or_else(|| Error::protocol("missing LL.value"))?;
    KeySalt::from_ll_value(value)
}

/// Parse getjwt / authwithtoken / refreshjwt response into token fields.
pub fn parse_token_response(payload: &[u8], hash_alg: HashAlg) -> Result<LxToken> {
    let root = parse_json(payload)?;
    let ll = require_ll_ok(&root)?;
    let value = ll
        .get("value")
        .ok_or_else(|| Error::protocol("missing LL.value in token response"))?;

    let valid_until = read_valid_until(value)?;

    let token = value
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(LxToken::new(token, valid_until, hash_alg))
}

/// Apply refresh/auth response onto an existing token (token field optional).
pub fn apply_valid_until(token: &mut LxToken, payload: &[u8]) -> Result<()> {
    let root = parse_json(payload)?;
    let ll = require_ll_ok(&root)?;
    let value = ll
        .get("value")
        .ok_or_else(|| Error::protocol("missing LL.value"))?;
    token.valid_until = read_valid_until(value)?;
    if let Some(new_tok) = value.get("token").and_then(|v| v.as_str()) {
        if !new_tok.is_empty() {
            token.token = new_tok.to_string();
        }
    }
    Ok(())
}

fn read_valid_until(value: &Value) -> Result<i64> {
    value
        .get("validUntil")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_u64().map(|u| u as i64))
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or_else(|| Error::auth("missing validUntil"))
}

/// Parse `getkey` response (HMAC key hex string in LL.value).
pub fn parse_getkey_value(payload: &[u8]) -> Result<String> {
    let root = parse_json(payload)?;
    let ll = require_ll_ok(&root)?;
    ll.get("value")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| Error::protocol("missing getkey value"))
}

/// Build credential hash + getjwt command from getkey2 payload.
///
/// The hash algorithm stays dynamic because the Miniserver selects it per user
/// via the `hashAlg` field of the `getkey2` response.
pub fn build_acquire_token_cmd(
    getkey2_payload: &[u8],
    username: &str,
    password: &str,
    permission: TokenPermission,
    client_uuid: &str,
    client_info: &str,
) -> Result<(String, HashAlg)> {
    let ks = parse_key_salt(getkey2_payload)?;
    let cred = hash_credentials(&ks, password, username)?;
    let cmd = cmd_request_token(&cred, username, permission, client_uuid, client_info);
    Ok((cmd, ks.hash_alg))
}

pub fn build_token_hash(getkey_payload: &[u8], token: &LxToken) -> Result<String> {
    let key = parse_getkey_value(getkey_payload)?;
    hash_token(token.hash_alg, &key, &token.token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ll_code_casing() {
        let a: Value = sonic_rs::from_str(r#"{"Code":"200"}"#).unwrap();
        let b: Value = sonic_rs::from_str(r#"{"code":"200"}"#).unwrap();
        assert_eq!(ll_status_code(&a), Some("200"));
        assert_eq!(ll_status_code(&b), Some("200"));
    }

    #[test]
    fn token_commands_are_jwt_only() {
        let cmd = cmd_request_token(
            "abc",
            "u",
            TokenPermission::App,
            DEFAULT_CLIENT_UUID,
            DEFAULT_CLIENT_INFO,
        );
        assert!(cmd.starts_with("jdev/sys/getjwt/"));
        assert!(cmd_refresh_token("abc", "u").starts_with("jdev/sys/refreshjwt/"));
        assert!(cmd_check_token("abc", "u").starts_with("jdev/sys/checktoken/"));
        assert!(cmd_kill_token("abc", "u").starts_with("jdev/sys/killtoken/"));
    }

    #[test]
    fn permission_id_appears_in_getjwt() {
        let web = cmd_request_token("h", "u", TokenPermission::Web, "uuid", "info");
        let app = cmd_request_token("h", "u", TokenPermission::App, "uuid", "info");
        assert_eq!(web, "jdev/sys/getjwt/h/u/2/uuid/info");
        assert_eq!(app, "jdev/sys/getjwt/h/u/4/uuid/info");
        assert_eq!(TokenPermission::default(), TokenPermission::App);
    }

    #[test]
    fn parse_token_json() {
        let body = br#"{"LL":{"code":"200","value":{"token":"eyJ","validUntil":500000000}}}"#;
        let t = parse_token_response(body, HashAlg::Sha256).unwrap();
        assert_eq!(t.token, "eyJ");
        assert_eq!(t.valid_until, 500_000_000);
        assert_eq!(t.hash_alg, HashAlg::Sha256);
    }

    #[test]
    fn ll_error_codes_carry_hints() {
        for code in ["400", "401", "403", "404", "420", "500", "503"] {
            let body = format!(r#"{{"LL":{{"code":"{code}"}}}}"#);
            let root: Value = sonic_rs::from_str(&body).unwrap();
            let err = require_ll_ok(&root).unwrap_err().to_string();
            assert!(err.contains(code), "{err}");
            assert!(err.contains('('), "no hint for {code}: {err}");
        }
    }

    /// 423 and 901 describe the Miniserver's own state rather than a bad
    /// request, and the supervisor reacts to them differently, so they need to
    /// survive as distinct variants instead of collapsing into `Auth`.
    #[test]
    fn the_two_stateful_codes_keep_their_own_variant() {
        assert!(matches!(ll_status_error("423"), Error::UserDisabled));
        assert!(ll_status_error("423").is_terminal());
        assert!(matches!(ll_status_error("901"), Error::TooManyConnections));
        assert!(ll_status_error("901").needs_long_backoff());
        assert!(matches!(ll_status_error("401"), Error::Auth(_)));
    }

    #[test]
    fn only_auth_codes_invalidate_the_token() {
        assert!(ll_status_invalidates_token("401"));
        assert!(ll_status_invalidates_token("403"));
        // 901 is the connection limit, not a verdict on the token. Discarding
        // it here would ask for a replacement over a connection the Miniserver
        // just refused.
        assert!(!ll_status_invalidates_token("901"));
        assert!(!ll_status_invalidates_token("500"));
        assert!(!ll_status_invalidates_token("503"));
        assert!(!ll_status_invalidates_token("200"));
    }

    #[test]
    fn payload_status_extraction() {
        assert_eq!(
            payload_ll_status(br#"{"LL":{"control":"x","Code":"401"}}"#).as_deref(),
            Some("401")
        );
        assert_eq!(payload_ll_status(b"not json"), None);
        assert_eq!(payload_ll_status(br#"{"other":1}"#), None);
    }
}
