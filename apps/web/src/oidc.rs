//! OIDC client utilities: discovery, authorization URL, token exchange and ID token validation.

use anyhow::{Context, Result};
use chrono::Utc;
use jsonwebtoken::{decode, decode_header, jwk::Jwk, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use trueid_common::db::Db;

/// ID-token algorithms accepted from providers (asymmetric families only).
const ALLOWED_ID_TOKEN_ALGS: [Algorithm; 3] =
    [Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA];

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
    /// Parameters: `db` - database handle, `http` - HTTP client,
    /// `allow_insecure_loopback` - permit plain-HTTP loopback issuers (dev mode).
    /// Returns: ready-to-use provider metadata and credentials.
    pub async fn discover(
        db: &Db,
        http: &reqwest::Client,
        allow_insecure_loopback: bool,
    ) -> Result<Self> {
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
        let discovery = discover_document(http, &issuer, allow_insecure_loopback).await?;

        // The JWKS URL comes from the (validated) issuer's discovery document;
        // require it to stay on the issuer's origin so a compromised or
        // malicious document cannot swap key material from elsewhere.
        let issuer_url = reqwest::Url::parse(&issuer)?;
        let jwks_url = reqwest::Url::parse(&discovery.jwks_uri)?;
        anyhow::ensure!(
            same_origin(&issuer_url, &jwks_url),
            "discovery jwks_uri ({}) must share the issuer origin ({issuer})",
            discovery.jwks_uri
        );
        for (name, endpoint) in [
            ("authorization_endpoint", &discovery.authorization_endpoint),
            ("token_endpoint", &discovery.token_endpoint),
        ] {
            let url = reqwest::Url::parse(endpoint)
                .with_context(|| format!("invalid discovery {name}"))?;
            anyhow::ensure!(
                url.scheme() == "https" || (allow_insecure_loopback && url.scheme() == "http"),
                "discovery {name} must use HTTPS"
            );
        }

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
        anyhow::ensure!(
            ALLOWED_ID_TOKEN_ALGS.contains(&alg),
            "id_token algorithm not allowed: {alg:?} (allowed: RS256/ES256/EdDSA)"
        );
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

/// Validates an issuer URL: must be HTTPS, or plain HTTP only when the host
/// is loopback AND `allow_insecure_loopback` (dev mode) is set.
///
/// Parameters: `issuer` - configured issuer URL, `allow_insecure_loopback` - dev flag.
/// Returns: Ok for acceptable URLs.
pub fn validate_issuer_url(issuer: &str, allow_insecure_loopback: bool) -> Result<()> {
    let url = reqwest::Url::parse(issuer).context("issuer_url is not a valid URL")?;
    let host = url
        .host_str()
        .context("issuer_url is missing a host")?
        .to_string();
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let is_loopback = host
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false)
                || host == "localhost";
            anyhow::ensure!(
                is_loopback && allow_insecure_loopback,
                "issuer_url must use HTTPS (plain HTTP is allowed only for loopback hosts in dev mode)"
            );
            Ok(())
        }
        other => anyhow::bail!("issuer_url scheme must be https, got '{other}'"),
    }
}

/// Whether two URLs share scheme, host and effective port.
fn same_origin(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Fetches and caches OIDC discovery document for one hour.
///
/// Parameters: `http` - HTTP client, `issuer` - issuer URL,
/// `allow_insecure_loopback` - permit plain-HTTP loopback issuers (dev mode).
/// Returns: discovery endpoints.
pub async fn discover_document(
    http: &reqwest::Client,
    issuer: &str,
    allow_insecure_loopback: bool,
) -> Result<OidcDiscovery> {
    validate_issuer_url(issuer, allow_insecure_loopback)?;
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
    use super::{validate_issuer_url, OidcProvider};
    use axum::routing::get;
    use axum::Router;
    use chrono::Utc;
    use jsonwebtoken::{encode, errors::ErrorKind, jwk::Jwk, Algorithm, EncodingKey, Header};
    use serde_json::{json, Value};
    use std::time::Duration;

    #[test]
    fn issuer_must_be_https_in_production() {
        assert!(validate_issuer_url("https://sso.example.com/realms/main", false).is_ok());
        assert!(validate_issuer_url("http://sso.example.com", false).is_err());
        assert!(validate_issuer_url("ftp://sso.example.com", false).is_err());
        assert!(validate_issuer_url("http://127.0.0.1:8080", false).is_err());
        assert!(validate_issuer_url("not-a-url", false).is_err());
    }

    #[test]
    fn issuer_allows_loopback_http_only_in_dev() {
        assert!(validate_issuer_url("http://127.0.0.1:8080/realms/x", true).is_ok());
        assert!(validate_issuer_url("http://localhost:8080", true).is_ok());
        assert!(validate_issuer_url("http://192.168.1.10:8080", true).is_err());
        assert!(validate_issuer_url("http://127.0.0.1:8080", false).is_err());
    }

    #[test]
    fn same_origin_compares_scheme_host_port() {
        let a = reqwest::Url::parse("https://sso.example.com").unwrap();
        let b = reqwest::Url::parse("https://sso.example.com/jwks").unwrap();
        let c = reqwest::Url::parse("https://evil.example.com/jwks").unwrap();
        let d = reqwest::Url::parse("http://sso.example.com/jwks").unwrap();
        let e = reqwest::Url::parse("https://sso.example.com:8443/jwks").unwrap();
        assert!(super::same_origin(&a, &b));
        assert!(!super::same_origin(&a, &c));
        assert!(!super::same_origin(&a, &d));
        assert!(!super::same_origin(&a, &e));
    }

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

    // ── ID-token validation regression tests (aws_lc_rs JWT backend) ────────

    /// Directory of public upstream test keys (see tests/fixtures/oidc/README.md).
    const OIDC_FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/oidc");

    /// Test issuer mirrored into ID-token claims.
    const TEST_ISSUER: &str = "https://issuer.example.com";

    /// Test client id mirrored into ID-token claims.
    const TEST_CLIENT_ID: &str = "client-123";

    /// Test nonce mirrored into ID-token claims.
    const TEST_NONCE: &str = "nonce-456-oidc";

    /// `kid` published for the RSA-2048 fixture key.
    const KID_RSA: &str = "test-rsa-2048";

    /// `kid` published for the P-256 fixture key.
    const KID_P256: &str = "test-p256";

    /// `kid` published for the Ed25519 fixture key.
    const KID_ED25519: &str = "test-ed25519";

    /// Reads a public upstream test key fixture.
    ///
    /// Parameters: `file` - fixture name under `tests/fixtures/oidc/`.
    /// Returns: raw DER bytes of the fixture key.
    fn fixture_der(file: &str) -> Vec<u8> {
        std::fs::read(format!("{OIDC_FIXTURE_DIR}/{file}"))
            .expect("public OIDC test fixture must be present")
    }

    /// Builds the RS256 encoding key from the public RSA-2048 fixture.
    ///
    /// Parameters: none.
    /// Returns: encoding key for signing RS256 test tokens.
    fn rsa_encoding_key() -> EncodingKey {
        EncodingKey::from_rsa_der(&fixture_der("rsa-2048-pkcs1.der"))
    }

    /// Builds the ES256 encoding key from the public P-256 fixture.
    ///
    /// Parameters: none.
    /// Returns: encoding key for signing ES256 test tokens.
    fn p256_encoding_key() -> EncodingKey {
        EncodingKey::from_ec_der(&fixture_der("p256-pkcs8.der"))
    }

    /// Builds the EdDSA encoding key from the public Ed25519 fixture.
    ///
    /// Parameters: none.
    /// Returns: encoding key for signing EdDSA test tokens.
    fn ed25519_encoding_key() -> EncodingKey {
        EncodingKey::from_ed_der(&fixture_der("ed25519-pkcs8.der"))
    }

    /// Builds well-formed ID-token claims with timestamps relative to now.
    ///
    /// Parameters: none.
    /// Returns: claims JSON accepted by `validate_id_token`.
    fn id_token_claims() -> Value {
        let now = Utc::now().timestamp();
        json!({
            "sub": "user-oidc-1",
            "email": "oidc-user@example.com",
            "name": "OIDC Test User",
            "preferred_username": "oidcuser",
            "nonce": TEST_NONCE,
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "exp": now + 600,
            "iat": now,
        })
    }

    /// Builds a JWK JSON entry with a fixed `kid` for the mock JWKS.
    ///
    /// Parameters: `key` - private encoding key, `alg` - matching algorithm,
    /// `kid` - key id to publish.
    /// Returns: serialized JWK JSON object.
    fn jwk_entry(key: &EncodingKey, alg: Algorithm, kid: &str) -> Value {
        let mut jwk = Jwk::from_encoding_key(key, alg).expect("build jwk from encoding key");
        jwk.common.key_id = Some(kid.to_string());
        serde_json::to_value(&jwk).expect("serialize jwk")
    }

    /// Builds the standard mock JWKS body covering all three key families.
    ///
    /// Parameters: none.
    /// Returns: JWKS JSON string with the RSA, P-256 and Ed25519 fixture keys.
    fn standard_jwks_body() -> String {
        json!({
            "keys": [
                jwk_entry(&rsa_encoding_key(), Algorithm::RS256, KID_RSA),
                jwk_entry(&p256_encoding_key(), Algorithm::ES256, KID_P256),
                jwk_entry(&ed25519_encoding_key(), Algorithm::EdDSA, KID_ED25519),
            ]
        })
        .to_string()
    }

    /// Signs a test ID token with an explicit algorithm and optional `kid`.
    ///
    /// Parameters: `alg` - header algorithm, `kid` - optional key id,
    /// `claims` - payload, `key` - private encoding key.
    /// Returns: compact JWT string.
    fn sign_id_token(
        alg: Algorithm,
        kid: Option<&str>,
        claims: &Value,
        key: &EncodingKey,
    ) -> String {
        let mut header = Header::new(alg);
        header.kid = kid.map(str::to_string);
        encode(&header, claims, key).expect("sign test id_token")
    }

    /// Builds a provider whose `jwks_uri` points at a loopback mock.
    ///
    /// Parameters: `jwks_uri` - full URL of the mock JWKS endpoint.
    /// Returns: provider ready for `validate_id_token` calls.
    fn loopback_provider(jwks_uri: String) -> OidcProvider {
        OidcProvider {
            issuer: TEST_ISSUER.to_string(),
            authorization_endpoint: "https://issuer.example.com/auth".to_string(),
            token_endpoint: "https://issuer.example.com/token".to_string(),
            userinfo_endpoint: None,
            jwks_uri,
            client_id: TEST_CLIENT_ID.to_string(),
            client_secret: "test-secret".to_string(),
            redirect_uri: "https://trueid.example.com/api/auth/oidc/callback".to_string(),
            scopes: "openid profile email".to_string(),
        }
    }

    /// Builds a no-proxy HTTP client with bounded timeouts.
    ///
    /// Parameters: none.
    /// Returns: reqwest client for mock endpoint requests.
    fn test_http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build test http client")
    }

    /// Spawns a mock JWKS endpoint on an ephemeral loopback port.
    ///
    /// Parameters: `jwks_body` - JWKS JSON document to serve.
    /// Returns: `(jwks_uri, server_task)` for validation calls and cleanup.
    async fn spawn_mock_jwks(jwks_body: String) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/jwks",
            get(move || {
                let body = jwks_body.clone();
                async move {
                    (
                        axum::http::StatusCode::OK,
                        [("content-type", "application/json")],
                        body,
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock jwks failed");
        let addr = listener.local_addr().expect("read mock jwks addr failed");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}/jwks"), handle)
    }

    /// Flips the first character of the signature segment so only the
    /// signature becomes invalid (header and claims stay intact).
    ///
    /// Parameters: `token` - compact JWT with a valid signature.
    /// Returns: token with a corrupted signature segment.
    fn tamper_signature(token: &str) -> String {
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        assert_eq!(parts.len(), 3, "test token must have three segments");
        let mut signature: Vec<char> = parts.remove(2).chars().collect();
        signature[0] = if signature[0] == 'A' { 'B' } else { 'A' };
        parts.push(signature.into_iter().collect());
        parts.join(".")
    }

    /// Extracts the jsonwebtoken error kind from an anyhow error.
    ///
    /// Parameters: `err` - error returned by `validate_id_token`.
    /// Returns: the wrapped jsonwebtoken `ErrorKind`.
    fn jwt_error_kind(err: &anyhow::Error) -> ErrorKind {
        err.downcast_ref::<jsonwebtoken::errors::Error>()
            .unwrap_or_else(|| panic!("expected jsonwebtoken error, got: {err}"))
            .kind()
            .clone()
    }

    /// Verifies a correctly signed RS256 ID token against a loopback JWKS.
    ///
    /// Parameters: none.
    /// Returns: unit test assertion result.
    #[tokio::test]
    async fn validate_id_token_accepts_valid_rs256_signature() {
        let (jwks_uri, server) = spawn_mock_jwks(standard_jwks_body()).await;
        let provider = loopback_provider(jwks_uri);
        let token = sign_id_token(
            Algorithm::RS256,
            Some(KID_RSA),
            &id_token_claims(),
            &rsa_encoding_key(),
        );

        let result = provider
            .validate_id_token(&token, TEST_NONCE, &test_http_client())
            .await;
        server.abort();

        let claims = result.expect("valid RS256 id_token must validate");
        assert_eq!(claims.sub, "user-oidc-1");
        assert_eq!(claims.iss, TEST_ISSUER);
        assert_eq!(claims.aud, json!(TEST_CLIENT_ID));
        assert_eq!(claims.nonce.as_deref(), Some(TEST_NONCE));
    }

    /// Verifies a correctly signed ES256 (P-256) ID token against a loopback JWKS.
    ///
    /// Parameters: none.
    /// Returns: unit test assertion result.
    #[tokio::test]
    async fn validate_id_token_accepts_valid_es256_signature() {
        let (jwks_uri, server) = spawn_mock_jwks(standard_jwks_body()).await;
        let provider = loopback_provider(jwks_uri);
        let token = sign_id_token(
            Algorithm::ES256,
            Some(KID_P256),
            &id_token_claims(),
            &p256_encoding_key(),
        );

        let result = provider
            .validate_id_token(&token, TEST_NONCE, &test_http_client())
            .await;
        server.abort();

        let claims = result.expect("valid ES256 id_token must validate");
        assert_eq!(claims.sub, "user-oidc-1");
        assert_eq!(claims.nonce.as_deref(), Some(TEST_NONCE));
    }

    /// Verifies a correctly signed EdDSA (Ed25519) ID token against a loopback JWKS.
    ///
    /// Parameters: none.
    /// Returns: unit test assertion result.
    #[tokio::test]
    async fn validate_id_token_accepts_valid_eddsa_signature() {
        let (jwks_uri, server) = spawn_mock_jwks(standard_jwks_body()).await;
        let provider = loopback_provider(jwks_uri);
        let token = sign_id_token(
            Algorithm::EdDSA,
            Some(KID_ED25519),
            &id_token_claims(),
            &ed25519_encoding_key(),
        );

        let result = provider
            .validate_id_token(&token, TEST_NONCE, &test_http_client())
            .await;
        server.abort();

        let claims = result.expect("valid EdDSA id_token must validate");
        assert_eq!(claims.sub, "user-oidc-1");
        assert_eq!(claims.nonce.as_deref(), Some(TEST_NONCE));
    }

    /// Verifies a token whose signature segment was altered is rejected while
    /// its kid remains published (the failure is the signature, not lookup).
    ///
    /// Parameters: none.
    /// Returns: unit test assertion result.
    #[tokio::test]
    async fn validate_id_token_rejects_tampered_signature() {
        let (jwks_uri, server) = spawn_mock_jwks(standard_jwks_body()).await;
        let provider = loopback_provider(jwks_uri);
        let token = tamper_signature(&sign_id_token(
            Algorithm::RS256,
            Some(KID_RSA),
            &id_token_claims(),
            &rsa_encoding_key(),
        ));

        let result = provider
            .validate_id_token(&token, TEST_NONCE, &test_http_client())
            .await;
        server.abort();

        let err = result.expect_err("tampered id_token must be rejected");
        assert_eq!(jwt_error_kind(&err), ErrorKind::InvalidSignature);
    }

    /// Verifies a correctly RS512-signed token with a published kid is rejected
    /// by the production algorithm allowlist, not by a signature error.
    ///
    /// Parameters: none.
    /// Returns: unit test assertion result.
    #[tokio::test]
    async fn validate_id_token_rejects_disallowed_algorithm() {
        let (jwks_uri, server) = spawn_mock_jwks(standard_jwks_body()).await;
        let provider = loopback_provider(jwks_uri);
        let token = sign_id_token(
            Algorithm::RS512,
            Some(KID_RSA),
            &id_token_claims(),
            &rsa_encoding_key(),
        );

        let result = provider
            .validate_id_token(&token, TEST_NONCE, &test_http_client())
            .await;
        server.abort();

        let err = result.expect_err("RS512 id_token must be rejected by the allowlist");
        assert!(
            err.to_string().contains("algorithm not allowed"),
            "unexpected error: {err}"
        );
    }

    /// Verifies a correctly signed token with a foreign issuer is rejected by
    /// issuer validation (signature and kid are valid).
    ///
    /// Parameters: none.
    /// Returns: unit test assertion result.
    #[tokio::test]
    async fn validate_id_token_rejects_wrong_issuer() {
        let (jwks_uri, server) = spawn_mock_jwks(standard_jwks_body()).await;
        let provider = loopback_provider(jwks_uri);
        let mut claims = id_token_claims();
        claims["iss"] = json!("https://evil.example.com");
        let token = sign_id_token(
            Algorithm::RS256,
            Some(KID_RSA),
            &claims,
            &rsa_encoding_key(),
        );

        let result = provider
            .validate_id_token(&token, TEST_NONCE, &test_http_client())
            .await;
        server.abort();

        let err = result.expect_err("wrong-issuer id_token must be rejected");
        assert_eq!(jwt_error_kind(&err), ErrorKind::InvalidIssuer);
    }

    /// Verifies a correctly signed token for another audience is rejected by
    /// audience validation (signature and kid are valid).
    ///
    /// Parameters: none.
    /// Returns: unit test assertion result.
    #[tokio::test]
    async fn validate_id_token_rejects_wrong_audience() {
        let (jwks_uri, server) = spawn_mock_jwks(standard_jwks_body()).await;
        let provider = loopback_provider(jwks_uri);
        let mut claims = id_token_claims();
        claims["aud"] = json!("someone-else");
        let token = sign_id_token(
            Algorithm::RS256,
            Some(KID_RSA),
            &claims,
            &rsa_encoding_key(),
        );

        let result = provider
            .validate_id_token(&token, TEST_NONCE, &test_http_client())
            .await;
        server.abort();

        let err = result.expect_err("wrong-audience id_token must be rejected");
        assert_eq!(jwt_error_kind(&err), ErrorKind::InvalidAudience);
    }

    /// Verifies a valid token is rejected when the expected nonce differs.
    ///
    /// Parameters: none.
    /// Returns: unit test assertion result.
    #[tokio::test]
    async fn validate_id_token_rejects_wrong_nonce() {
        let (jwks_uri, server) = spawn_mock_jwks(standard_jwks_body()).await;
        let provider = loopback_provider(jwks_uri);
        let token = sign_id_token(
            Algorithm::RS256,
            Some(KID_RSA),
            &id_token_claims(),
            &rsa_encoding_key(),
        );

        let result = provider
            .validate_id_token(&token, "attacker-chosen-nonce", &test_http_client())
            .await;
        server.abort();

        let err = result.expect_err("mismatched nonce must be rejected");
        assert!(
            err.to_string().contains("invalid nonce"),
            "unexpected error: {err}"
        );
    }

    /// Verifies a correctly signed token with a past expiration is rejected by
    /// expiration validation (signature and kid are valid).
    ///
    /// Parameters: none.
    /// Returns: unit test assertion result.
    #[tokio::test]
    async fn validate_id_token_rejects_expired_token() {
        let (jwks_uri, server) = spawn_mock_jwks(standard_jwks_body()).await;
        let provider = loopback_provider(jwks_uri);
        let mut claims = id_token_claims();
        let now = Utc::now().timestamp();
        claims["exp"] = json!(now - 3600);
        claims["iat"] = json!(now - 7200);
        let token = sign_id_token(
            Algorithm::RS256,
            Some(KID_RSA),
            &claims,
            &rsa_encoding_key(),
        );

        let result = provider
            .validate_id_token(&token, TEST_NONCE, &test_http_client())
            .await;
        server.abort();

        let err = result.expect_err("expired id_token must be rejected");
        assert_eq!(jwt_error_kind(&err), ErrorKind::ExpiredSignature);
    }

    /// Verifies a token without a kid header is rejected before any network
    /// request (the JWKS URI points at a closed discard port on purpose).
    ///
    /// Parameters: none.
    /// Returns: unit test assertion result.
    #[tokio::test]
    async fn validate_id_token_rejects_missing_kid() {
        let provider = loopback_provider("http://127.0.0.1:9/jwks".to_string());
        let token = sign_id_token(
            Algorithm::RS256,
            None,
            &id_token_claims(),
            &rsa_encoding_key(),
        );

        let result = provider
            .validate_id_token(&token, TEST_NONCE, &test_http_client())
            .await;

        let err = result.expect_err("id_token without kid must be rejected");
        assert!(
            err.to_string().contains("missing kid"),
            "unexpected error: {err}"
        );
    }

    /// Verifies a token whose kid is absent from the JWKS is rejected.
    ///
    /// Parameters: none.
    /// Returns: unit test assertion result.
    #[tokio::test]
    async fn validate_id_token_rejects_unknown_kid() {
        let (jwks_uri, server) = spawn_mock_jwks(standard_jwks_body()).await;
        let provider = loopback_provider(jwks_uri);
        let token = sign_id_token(
            Algorithm::RS256,
            Some("ghost-kid"),
            &id_token_claims(),
            &rsa_encoding_key(),
        );

        let result = provider
            .validate_id_token(&token, TEST_NONCE, &test_http_client())
            .await;
        server.abort();

        let err = result.expect_err("id_token with unknown kid must be rejected");
        assert!(
            err.to_string().contains("matching jwk key not found"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn validate_id_token_accepts_array_audience_containing_client() {
        let (jwks_uri, server) = spawn_mock_jwks(standard_jwks_body()).await;
        let provider = loopback_provider(jwks_uri);
        let mut claims = id_token_claims();
        claims["aud"] = json!(["another-client", TEST_CLIENT_ID]);
        let token = sign_id_token(
            Algorithm::RS256,
            Some(KID_RSA),
            &claims,
            &rsa_encoding_key(),
        );

        let result = provider
            .validate_id_token(&token, TEST_NONCE, &test_http_client())
            .await;
        server.abort();

        let claims = result.expect("array audience containing the client must validate");
        assert_eq!(claims.aud, json!(["another-client", TEST_CLIENT_ID]));
        assert_eq!(claims.sub, "user-oidc-1");
    }

    #[tokio::test]
    async fn validate_id_token_rejects_array_audience_without_client() {
        let (jwks_uri, server) = spawn_mock_jwks(standard_jwks_body()).await;
        let provider = loopback_provider(jwks_uri);
        let mut claims = id_token_claims();
        claims["aud"] = json!(["another-client", "someone-else"]);
        let token = sign_id_token(
            Algorithm::RS256,
            Some(KID_RSA),
            &claims,
            &rsa_encoding_key(),
        );

        let result = provider
            .validate_id_token(&token, TEST_NONCE, &test_http_client())
            .await;
        server.abort();

        let err = result.expect_err("array audience without the client must be rejected");
        assert_eq!(jwt_error_kind(&err), ErrorKind::InvalidAudience);
    }

    #[tokio::test]
    async fn validate_id_token_rejects_recent_expiry_within_library_leeway() {
        let (jwks_uri, server) = spawn_mock_jwks(standard_jwks_body()).await;
        let provider = loopback_provider(jwks_uri);
        let mut claims = id_token_claims();
        claims["exp"] = json!(Utc::now().timestamp() - 5);
        let token = sign_id_token(
            Algorithm::RS256,
            Some(KID_RSA),
            &claims,
            &rsa_encoding_key(),
        );

        let result = provider
            .validate_id_token(&token, TEST_NONCE, &test_http_client())
            .await;
        server.abort();

        let err = result.expect_err("OIDC must reject expiry within library leeway");
        assert_eq!(err.to_string(), "id_token expired");
    }
}
