//! OIDC client utilities: discovery, authorization URL, token exchange and ID token validation.

use anyhow::{Context, Result};
use chrono::Utc;
use jsonwebtoken::{decode, decode_header, jwk::Jwk, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use trueid_common::db::Db;

static DISCOVERY_CACHE: OnceLock<RwLock<HashMap<String, CachedDiscovery>>> = OnceLock::new();

#[derive(Clone)]
struct CachedDiscovery {
    discovered_at: Instant,
    document: OidcDiscovery,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscovery {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
    jwks_uri: String,
}

/// Persisted OIDC runtime configuration loaded from database.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub enabled: bool,
    pub provider_name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: String,
    pub auto_create_users: bool,
    pub default_role: String,
    pub role_claim: Option<String>,
    pub role_mapping: String,
    pub allow_local_login: bool,
}

/// OIDC provider endpoints and client credentials.
#[derive(Debug, Clone)]
pub struct OidcProvider {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: String,
}

/// Token response returned by OIDC token endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    pub id_token: String,
    pub refresh_token: Option<String>,
}

/// Validated ID token claims used for local user provisioning/sign-in.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdTokenClaims {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub nonce: Option<String>,
    pub iss: String,
    pub aud: Value,
    pub exp: i64,
    pub iat: Option<i64>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

fn cache() -> &'static RwLock<HashMap<String, CachedDiscovery>> {
    DISCOVERY_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

impl OidcProvider {
    /// Discovers OIDC endpoints from `.well-known/openid-configuration`.
    ///
    /// Parameters: `db` - database handle, `http` - HTTP client.
    /// Returns: ready-to-use provider metadata and credentials.
    pub async fn discover(db: &Db, http: &reqwest::Client) -> Result<Self> {
        let config = load_oidc_config(db).await?;
        anyhow::ensure!(config.enabled, "OIDC is disabled");
        anyhow::ensure!(
            !config.issuer_url.trim().is_empty(),
            "OIDC issuer_url is required"
        );
        anyhow::ensure!(
            !config.client_id.trim().is_empty(),
            "OIDC client_id is required"
        );
        anyhow::ensure!(
            !config.redirect_uri.trim().is_empty(),
            "OIDC redirect_uri is required"
        );
        let issuer = config.issuer_url.trim_end_matches('/').to_string();
        let discovery = discover_document(http, &issuer).await?;
        Ok(Self {
            issuer,
            authorization_endpoint: discovery.authorization_endpoint,
            token_endpoint: discovery.token_endpoint,
            userinfo_endpoint: discovery.userinfo_endpoint,
            jwks_uri: discovery.jwks_uri,
            client_id: config.client_id,
            client_secret: config.client_secret,
            redirect_uri: config.redirect_uri,
            scopes: config.scopes,
        })
    }

    /// Builds authorization URL including state and nonce.
    ///
    /// Parameters: `state` - anti-CSRF token, `nonce` - ID token replay token.
    /// Returns: complete authorization URL.
    pub fn authorization_url(&self, state: &str, nonce: &str) -> String {
        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&nonce={}",
            self.authorization_endpoint,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.redirect_uri),
            urlencoding::encode(&self.scopes),
            urlencoding::encode(state),
            urlencoding::encode(nonce),
        )
    }

    /// Exchanges authorization code for OIDC tokens.
    ///
    /// Parameters: `code` - one-time authorization code, `http` - HTTP client.
    /// Returns: decoded token endpoint response.
    pub async fn exchange_code(&self, code: &str, http: &reqwest::Client) -> Result<TokenResponse> {
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
        ];
        let response = http
            .post(&self.token_endpoint)
            .form(&params)
            .send()
            .await
            .context("token endpoint request failed")?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("token exchange failed ({status}): {body}");
        }
        response
            .json::<TokenResponse>()
            .await
            .context("invalid token response")
    }

    /// Validates ID token signature and standard claims using JWKS.
    ///
    /// Parameters: `id_token` - JWT, `nonce` - expected nonce, `http` - HTTP client.
    /// Returns: verified claims.
    pub async fn validate_id_token(
        &self,
        id_token: &str,
        nonce: &str,
        http: &reqwest::Client,
    ) -> Result<IdTokenClaims> {
        let header = decode_header(id_token).context("invalid id_token header")?;
        let kid = header
            .kid
            .clone()
            .context("missing kid in id_token header")?;
        let jwks: Value = http
            .get(&self.jwks_uri)
            .send()
            .await
            .context("jwks request failed")?
            .json()
            .await
            .context("invalid jwks response")?;
        let keys = jwks["keys"]
            .as_array()
            .context("jwks does not contain keys array")?;
        let jwk_value = keys
            .iter()
            .find(|k| k.get("kid").and_then(Value::as_str) == Some(kid.as_str()))
            .context("matching jwk key not found")?;
        let jwk: Jwk = serde_json::from_value(jwk_value.clone()).context("invalid jwk format")?;
        let decoding_key = DecodingKey::from_jwk(&jwk).context("failed to build decoding key")?;
        let alg = header.alg;
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.client_id.as_str()]);
        let data = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
            .context("id_token signature/claims validation failed")?;
        let claims = data.claims;
        if claims.nonce.as_deref() != Some(nonce) {
            anyhow::bail!("invalid nonce");
        }
        if claims.exp <= Utc::now().timestamp() {
            anyhow::bail!("id_token expired");
        }
        Ok(claims)
    }
}

/// Loads OIDC config singleton row from database and decrypts client secret.
///
/// Parameters: `db` - database handle.
/// Returns: normalized configuration.
pub async fn load_oidc_config(db: &Db) -> Result<OidcConfig> {
    let row = sqlx::query(
        "SELECT enabled, provider_name, issuer_url, client_id, client_secret_enc, redirect_uri,
                scopes, auto_create_users, default_role, role_claim, role_mapping, allow_local_login
         FROM oidc_config WHERE id = 1",
    )
    .fetch_one(db.pool())
    .await
    .context("failed to read oidc config")?;
    let secret_enc: String = row.try_get("client_secret_enc").unwrap_or_default();
    let client_secret = if secret_enc.is_empty() {
        String::new()
    } else {
        match db.decrypt_config_value(&secret_enc) {
            Ok(value) => value,
            Err(_) => secret_enc.clone(),
        }
    };
    Ok(OidcConfig {
        enabled: row.try_get::<bool, _>("enabled").unwrap_or(false),
        provider_name: row
            .try_get::<String, _>("provider_name")
            .unwrap_or_else(|_| "OIDC".to_string()),
        issuer_url: row.try_get("issuer_url").unwrap_or_default(),
        client_id: row.try_get("client_id").unwrap_or_default(),
        client_secret,
        redirect_uri: row.try_get("redirect_uri").unwrap_or_default(),
        scopes: row
            .try_get::<String, _>("scopes")
            .unwrap_or_else(|_| "openid profile email".to_string()),
        auto_create_users: row.try_get::<bool, _>("auto_create_users").unwrap_or(true),
        default_role: row
            .try_get::<String, _>("default_role")
            .unwrap_or_else(|_| "Viewer".to_string()),
        role_claim: row.try_get("role_claim").ok(),
        role_mapping: row
            .try_get::<String, _>("role_mapping")
            .unwrap_or_else(|_| "{}".to_string()),
        allow_local_login: row.try_get::<bool, _>("allow_local_login").unwrap_or(true),
    })
}

/// Fetches and caches OIDC discovery document for one hour.
///
/// Parameters: `http` - HTTP client, `issuer` - issuer URL.
/// Returns: discovery endpoints.
pub async fn discover_document(http: &reqwest::Client, issuer: &str) -> Result<OidcDiscovery> {
    let now = Instant::now();
    {
        let guard = cache().read().await;
        if let Some(entry) = guard.get(issuer) {
            if now.duration_since(entry.discovered_at) < Duration::from_secs(3600) {
                return Ok(entry.document.clone());
            }
        }
    }
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    let document = http
        .get(discovery_url)
        .send()
        .await
        .context("oidc discovery request failed")?
        .json::<OidcDiscovery>()
        .await
        .context("invalid oidc discovery response")?;
    let mut guard = cache().write().await;
    guard.insert(
        issuer.to_string(),
        CachedDiscovery {
            discovered_at: now,
            document: document.clone(),
        },
    );
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::OidcProvider;

    /// Verifies authorization URL contains required OIDC query parameters.
    ///
    /// Parameters: none.
    /// Returns: unit test assertion result.
    #[test]
    fn test_oidc_authorization_url_format() {
        let provider = OidcProvider {
            issuer: "https://issuer.example.com".to_string(),
            authorization_endpoint: "https://issuer.example.com/auth".to_string(),
            token_endpoint: "https://issuer.example.com/token".to_string(),
            userinfo_endpoint: Some("https://issuer.example.com/userinfo".to_string()),
            jwks_uri: "https://issuer.example.com/jwks".to_string(),
            client_id: "client-123".to_string(),
            client_secret: "secret".to_string(),
            redirect_uri: "https://trueid.example.com/api/auth/oidc/callback".to_string(),
            scopes: "openid profile email".to_string(),
        };
        let url = provider.authorization_url("state123", "nonce456");
        assert!(url.contains("client_id=client-123"));
        assert!(url.contains(
            "redirect_uri=https%3A%2F%2Ftrueid.example.com%2Fapi%2Fauth%2Foidc%2Fcallback"
        ));
        assert!(url.contains("state=state123"));
        assert!(url.contains("nonce=nonce456"));
    }
}
