//! JWT token handling, cookie builders, and CSRF helpers for TrueID.

use anyhow::Result;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use tracing::warn;
use trueid_common::model::User;

// ── Constants ──────────────────────────────────────────────

/// Access token lifetime (15 minutes).
pub const ACCESS_TOKEN_TTL: Duration = Duration::minutes(15);

/// Refresh token lifetime (7 days).
pub const REFRESH_TOKEN_TTL: Duration = Duration::days(7);

/// Cookie name for the access JWT.
pub const COOKIE_NAME: &str = "trueid_access_token";

/// Cookie name for the refresh token.
pub const REFRESH_COOKIE_NAME: &str = "trueid_refresh_token";

/// Cookie name for the CSRF token (readable by JS).
pub const CSRF_COOKIE_NAME: &str = "trueid_csrf_token";

// ── JWT Claims ─────────────────────────────────────────────

/// JWT payload embedded in access tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject: user ID as string.
    pub sub: String,
    /// User role (PascalCase).
    pub role: String,
    /// Token version — must match DB to be valid.
    pub token_version: i64,
    /// Expiration (UNIX timestamp).
    pub exp: usize,
    /// Issued at (UNIX timestamp).
    pub iat: usize,
}

// ── JwtConfig ──────────────────────────────────────────────

/// JWT signing configuration.
#[derive(Clone)]
pub struct JwtConfig {
    /// HS256 signing secret.
    pub secret: String,
    /// Whether running in dev mode (affects cookie Secure flag).
    pub dev_mode: bool,
}

impl JwtConfig {
    /// Initializes JwtConfig from environment variables.
    ///
    /// In production JWT_SECRET must already be validated by startup checks.
    /// In dev mode, generates a random secret if JWT_SECRET is not set.
    ///
    /// Parameters: `dev_mode` — whether TRUEID_DEV_MODE is active.
    /// Returns: configured `JwtConfig`.
    pub fn from_env(dev_mode: bool) -> Self {
        let secret = match std::env::var("JWT_SECRET") {
            Ok(s) if !s.is_empty() => s,
            _ => {
                if dev_mode {
                    let s = generate_random_hex(64);
                    warn!("JWT_SECRET not set — generated random dev secret (not persisted).");
                    s
                } else {
                    // Should have been caught by fail-fast in main.
                    panic!("JWT_SECRET required in production");
                }
            }
        };
        Self { secret, dev_mode }
    }
}

// ── Token functions ────────────────────────────────────────

/// Creates an HS256 access token JWT for the given user.
///
/// Parameters: `config` — JWT signing config, `user` — authenticated user.
/// Returns: encoded JWT string.
pub fn create_access_token(config: &JwtConfig, user: &User) -> Result<String> {
    let now = Utc::now();
    let exp = now + ACCESS_TOKEN_TTL;

    let claims = Claims {
        sub: user.id.to_string(),
        role: user.role.to_string(),
        token_version: user.token_version,
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(config.secret.as_bytes()),
    )?;

    Ok(token)
}

/// Validates and decodes an access token JWT.
///
/// Parameters: `config` — JWT signing config, `token` — raw JWT string.
/// Returns: decoded `Claims` or error.
pub fn validate_token(config: &JwtConfig, token: &str) -> Result<Claims> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )?;
    Ok(data.claims)
}

// ── Cookie builders ────────────────────────────────────────

/// Builds a Set-Cookie header for an auth cookie (HttpOnly, SameSite=Strict).
///
/// Parameters: `name` — cookie name, `token` — value, `max_age_secs` — lifetime,
/// `dev_mode` — if true, omits Secure flag.
/// Returns: Set-Cookie header value string.
pub fn build_auth_cookie(name: &str, token: &str, max_age_secs: i64, dev_mode: bool) -> String {
    let secure = if dev_mode { "" } else { "; Secure" };
    format!("{name}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age_secs}{secure}")
}

/// Builds a Set-Cookie header that clears a cookie (Max-Age=0).
///
/// Parameters: `name` — cookie name, `dev_mode`.
/// Returns: Set-Cookie header value string.
pub fn build_clear_cookie(name: &str, dev_mode: bool) -> String {
    let secure = if dev_mode { "" } else { "; Secure" };
    format!("{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}")
}

/// Builds a CSRF cookie (NOT HttpOnly — JS needs to read it).
///
/// Parameters: `token` — CSRF token value, `dev_mode`.
/// Returns: Set-Cookie header value string.
pub fn build_csrf_cookie(token: &str, dev_mode: bool) -> String {
    let secure = if dev_mode { "" } else { "; Secure" };
    format!(
        "{CSRF_COOKIE_NAME}={token}; SameSite=Strict; Path=/; Max-Age={}{secure}",
        ACCESS_TOKEN_TTL.num_seconds()
    )
}

// ── CSRF helper ────────────────────────────────────────────

/// Generates a random 32-byte hex CSRF token.
///
/// Returns: 64-char hex string.
pub fn generate_csrf_token() -> String {
    generate_random_hex(32)
}

/// Generates a random hex string of the given byte length.
///
/// Parameters: `bytes` — number of random bytes.
/// Returns: lowercase hex string (2 × bytes chars).
pub fn generate_random_hex(bytes: usize) -> String {
    use rand::Rng;
    let mut random_bytes = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut random_bytes);
    random_bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generates a random 64-byte refresh token as hex.
///
/// Returns: 128-char hex string.
pub fn generate_refresh_token() -> String {
    generate_random_hex(64)
}

/// Extracts a named cookie value from a raw Cookie header string.
///
/// Parameters: `cookie_header` — raw Cookie header, `name` — cookie name.
/// Returns: cookie value if found.
pub fn extract_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if let Some(val) = trimmed.strip_prefix(name) {
            if let Some(val) = val.strip_prefix('=') {
                return Some(val);
            }
        }
    }
    None
}

/// Finds a cookie across all Cookie fields, including HTTP/2 split fields.
///
/// RFC 9113 section 8.2.3 permits multiple Cookie fields. Searching each field
/// in order preserves the first-match behavior of their `; ` concatenation.
/// An unreadable field rejects extraction even when another field matched.
pub(crate) fn extract_cookie_from_headers<'a>(
    headers: &'a axum::http::HeaderMap,
    name: &str,
) -> Option<&'a str> {
    let mut found = None;
    for value in headers.get_all(axum::http::header::COOKIE) {
        let field = value.to_str().ok()?;
        if found.is_none() {
            found = extract_cookie(field, name);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode_header, errors::ErrorKind};
    use trueid_common::model::UserRole;

    fn config() -> JwtConfig {
        JwtConfig {
            secret: "test-session-signing-secret-".repeat(3),
            dev_mode: false,
        }
    }

    fn user() -> User {
        let now = Utc::now();
        User {
            id: 42,
            username: "token-test-user".to_string(),
            password_hash: String::new(),
            role: UserRole::Operator,
            auth_source: "local".to_string(),
            external_id: None,
            oidc_subject: None,
            oidc_provider: None,
            token_version: 3,
            force_password_change: false,
            totp_enabled: false,
            totp_verified_at: None,
            failed_attempts: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn cookie_fields_preserve_exact_names_values_and_first_match() {
        for (fields, expected) in [
            (
                vec!["token_extra=no", "token=first=part", "token=later"],
                Some("first=part"),
            ),
            (vec!["Token=upper", "token=", "token=later"], Some("")),
            (vec!["other=value, token=not-a-separate-cookie"], None),
        ] {
            let mut headers = axum::http::HeaderMap::new();
            for field in fields {
                headers.append(axum::http::header::COOKIE, field.parse().unwrap());
            }
            assert_eq!(extract_cookie_from_headers(&headers, "token"), expected);
        }
    }

    #[test]
    fn unreadable_cookie_fields_fail_closed_before_or_after_a_match() {
        for malformed_first in [true, false] {
            let mut headers = axum::http::HeaderMap::new();
            let invalid = axum::http::HeaderValue::from_bytes(&[0xff]).unwrap();
            let valid = axum::http::HeaderValue::from_static("token=valid");
            let fields = if malformed_first {
                [invalid, valid]
            } else {
                [valid, invalid]
            };
            for field in fields {
                headers.append(axum::http::header::COOKIE, field);
            }
            assert_eq!(extract_cookie_from_headers(&headers, "token"), None);
        }
    }

    #[test]
    fn access_token_uses_hs256() {
        let token = create_access_token(&config(), &user()).unwrap();

        assert_eq!(decode_header(&token).unwrap().alg, Algorithm::HS256);
    }

    #[test]
    fn access_token_round_trip_preserves_session_claims() {
        let config = config();
        let user = user();
        let token = create_access_token(&config, &user).unwrap();

        let claims = validate_token(&config, &token).unwrap();

        assert_eq!(claims.sub, user.id.to_string());
        assert_eq!(claims.role, user.role.to_string());
        assert_eq!(claims.token_version, user.token_version);
        assert_eq!(
            claims.exp - claims.iat,
            ACCESS_TOKEN_TTL.num_seconds() as usize
        );
    }

    #[test]
    fn access_token_rejects_wrong_secret() {
        let token = create_access_token(&config(), &user()).unwrap();
        let mut wrong_config = config();
        wrong_config.secret = "different-session-signing-secret-".repeat(3);

        let error = validate_token(&wrong_config, &token).unwrap_err();

        assert_eq!(
            error
                .downcast_ref::<jsonwebtoken::errors::Error>()
                .unwrap()
                .kind(),
            &ErrorKind::InvalidSignature
        );
    }

    #[test]
    fn access_token_rejects_valid_hs384_signature() {
        let config = config();
        let token = create_access_token(&config, &user()).unwrap();
        let claims = validate_token(&config, &token).unwrap();
        let hs384_token = encode(
            &Header::new(Algorithm::HS384),
            &claims,
            &EncodingKey::from_secret(config.secret.as_bytes()),
        )
        .unwrap();
        decode::<Claims>(
            &hs384_token,
            &DecodingKey::from_secret(config.secret.as_bytes()),
            &Validation::new(Algorithm::HS384),
        )
        .expect("the rejected token must have a valid HS384 signature");

        let error = validate_token(&config, &hs384_token).unwrap_err();

        assert_eq!(
            error
                .downcast_ref::<jsonwebtoken::errors::Error>()
                .unwrap()
                .kind(),
            &ErrorKind::InvalidAlgorithm
        );
    }

    /// Verifies a fixed HS256 vector produced outside jsonwebtoken (Python
    /// stdlib HMAC-SHA256 over base64url segments) still verifies, proving
    /// HS256 verification does not depend on the crate's signing encoder
    /// backend. The secret and token are a public test vector, not a
    /// credential. The `exp` claim is fixed to 2100-01-01Z so the case stays
    /// deterministic.
    ///
    /// Parameters: none.
    /// Returns: unit test assertion result.
    #[test]
    fn access_token_verifies_fixed_external_hs256_vector() {
        const EXTERNAL_VECTOR_SECRET: &str = "fixed-public-fake-secret-for-trueid-jwt-compat-tests";
        const EXTERNAL_HS256_HEADER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        const EXTERNAL_HS256_PAYLOAD: &str = "eyJzdWIiOiI0MiIsInJvbGUiOiJPcGVyYXRvciIsInRva2VuX3ZlcnNpb24iOjMsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwfQ";
        const EXTERNAL_HS256_SIGNATURE: &str = "aEwkcAMgoU4epJLlJ5-Kpk73yGVVbtydyNZTTNnaxMM";
        let token =
            format!("{EXTERNAL_HS256_HEADER}.{EXTERNAL_HS256_PAYLOAD}.{EXTERNAL_HS256_SIGNATURE}");
        let config = JwtConfig {
            secret: EXTERNAL_VECTOR_SECRET.to_string(),
            dev_mode: false,
        };

        let claims = validate_token(&config, &token).unwrap();

        assert_eq!(decode_header(&token).unwrap().alg, Algorithm::HS256);
        assert_eq!(claims.sub, "42");
        assert_eq!(claims.role, "Operator");
        assert_eq!(claims.token_version, 3);
    }
}
