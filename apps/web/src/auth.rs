//! JWT token handling, cookie builders, and CSRF helpers for TrueID.

use anyhow::Result;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
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
        &Header::default(),
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
        &Validation::default(),
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
    format!(
        "{name}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age_secs}{secure}"
    )
}

/// Builds a Set-Cookie header that clears a cookie (Max-Age=0).
///
/// Parameters: `name` — cookie name, `dev_mode`.
/// Returns: Set-Cookie header value string.
pub fn build_clear_cookie(name: &str, dev_mode: bool) -> String {
    let secure = if dev_mode { "" } else { "; Secure" };
    format!(
        "{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}"
    )
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
    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..bytes).map(|_| rng.gen()).collect();
    random_bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generates a random 64-byte refresh token as hex.
///
/// Returns: 128-char hex string.
pub fn generate_refresh_token() -> String {
    generate_random_hex(64)
}
