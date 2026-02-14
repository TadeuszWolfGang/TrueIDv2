//! OIDC routes: public login/callback/status and admin configuration endpoints.

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::auth::{
    build_auth_cookie, build_csrf_cookie, create_access_token, generate_csrf_token,
    generate_random_hex, generate_refresh_token, COOKIE_NAME, REFRESH_TOKEN_TTL,
};
use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::oidc::{discover_document, load_oidc_config, OidcProvider};
use crate::AppState;
use trueid_common::db_auth::sha256_hex;
use trueid_common::model::UserRole;

const OIDC_STATE_COOKIE: &str = "trueid_oidc_state";
const OIDC_NONCE_COOKIE: &str = "trueid_oidc_nonce";

#[derive(Serialize)]
struct OidcStatusResponse {
    enabled: bool,
    provider_name: String,
    allow_local_login: bool,
}

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct OidcConfigResponse {
    enabled: bool,
    provider_name: String,
    issuer_url: String,
    client_id: String,
    redirect_uri: String,
    scopes: String,
    auto_create_users: bool,
    default_role: String,
    role_claim: String,
    role_mapping: String,
    allow_local_login: bool,
    has_client_secret: bool,
}

#[derive(Deserialize)]
pub struct UpdateOidcConfigRequest {
    enabled: bool,
    provider_name: String,
    issuer_url: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
    scopes: String,
    auto_create_users: bool,
    default_role: String,
    role_claim: Option<String>,
    role_mapping: String,
    allow_local_login: bool,
}

/// Returns public OIDC status for login page rendering.
///
/// Parameters: `state` - app state.
/// Returns: OIDC enabled/provider flags.
pub async fn status(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, "")?;
    let cfg = load_oidc_config(db).await.map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to load OIDC config",
        )
    })?;
    Ok(Json(OidcStatusResponse {
        enabled: cfg.enabled,
        provider_name: cfg.provider_name,
        allow_local_login: cfg.allow_local_login,
    }))
}

/// Starts OIDC login by redirecting to provider authorization endpoint.
///
/// Parameters: `state` - app state.
/// Returns: 302 redirect response with anti-CSRF cookies.
pub async fn login(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, "")?;
    let cfg = load_oidc_config(db).await.map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to load OIDC config",
        )
    })?;
    if !cfg.enabled {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "OIDC is disabled",
        ));
    }
    let provider = OidcProvider::discover(db, &state.http_client)
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                error::INTERNAL_ERROR,
                &format!("OIDC discovery failed: {e}"),
            )
        })?;
    let state_token = generate_random_hex(24);
    let nonce_token = generate_random_hex(24);
    let redirect = provider.authorization_url(&state_token, &nonce_token);
    let mut resp = Redirect::to(&redirect).into_response();
    append_cookie(
        &mut resp,
        OIDC_STATE_COOKIE,
        &state_token,
        300,
        state.jwt_config.dev_mode,
        true,
    );
    append_cookie(
        &mut resp,
        OIDC_NONCE_COOKIE,
        &nonce_token,
        300,
        state.jwt_config.dev_mode,
        true,
    );
    Ok(resp)
}

/// Handles OIDC callback, signs in/creates user, and issues TrueID session cookies.
///
/// Parameters: `state` - app state, `query` - callback query params, `headers` - request headers.
/// Returns: redirect to dashboard with local auth cookies.
pub async fn callback(
    State(state): State<AppState>,
    Query(query): Query<OidcCallbackQuery>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(err) = query.error.as_deref() {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            error::AUTH_REQUIRED,
            &format!("OIDC login failed: {err}"),
        ));
    }
    let code = query.code.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Missing OIDC code",
        )
    })?;
    let expected_state = cookie_value(&headers, OIDC_STATE_COOKIE).unwrap_or_default();
    let expected_nonce = cookie_value(&headers, OIDC_NONCE_COOKIE).unwrap_or_default();
    if expected_state.is_empty()
        || expected_nonce.is_empty()
        || query.state.as_deref().unwrap_or_default() != expected_state
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Invalid OIDC state",
        ));
    }

    let db = helpers::require_db(&state, "")?;
    let cfg = load_oidc_config(db).await.map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to load OIDC config",
        )
    })?;
    if !cfg.enabled {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "OIDC is disabled",
        ));
    }
    let provider = OidcProvider::discover(db, &state.http_client)
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                error::INTERNAL_ERROR,
                &format!("OIDC discovery failed: {e}"),
            )
        })?;
    let tokens = provider
        .exchange_code(code, &state.http_client)
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                error::AUTH_REQUIRED,
                &format!("OIDC token exchange failed: {e}"),
            )
        })?;
    let claims = provider
        .validate_id_token(&tokens.id_token, &expected_nonce, &state.http_client)
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                error::AUTH_REQUIRED,
                &format!("OIDC ID token invalid: {e}"),
            )
        })?;

    let role = resolve_role(&claims, &cfg)?;
    let username_seed = claims
        .preferred_username
        .clone()
        .or(claims.email.clone())
        .or(claims.name.clone())
        .unwrap_or_else(|| format!("oidc-{}", claims.sub));
    let username = normalize_username(&username_seed);

    let user = if let Some(existing) = db
        .get_user_by_oidc_subject(&claims.sub)
        .await
        .map_err(internal_db_error)?
    {
        let _ = db
            .update_oidc_identity(existing.id, role, &claims.sub, &cfg.provider_name)
            .await;
        db.get_user_by_id(existing.id)
            .await
            .map_err(internal_db_error)?
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to reload OIDC user",
                )
            })?
    } else {
        if !cfg.auto_create_users {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                error::FORBIDDEN,
                "OIDC user is not provisioned",
            ));
        }
        let mut candidate = username.clone();
        let mut suffix = 1_i64;
        while db
            .get_user_by_username(&candidate)
            .await
            .map_err(internal_db_error)?
            .is_some()
        {
            candidate = format!("{username}-{suffix}");
            suffix += 1;
        }
        db.create_oidc_user(&candidate, &claims.sub, &cfg.provider_name, role)
            .await
            .map_err(internal_db_error)?
    };

    let access_token = create_access_token(&state.jwt_config, &user).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Token creation failed",
        )
    })?;
    let refresh_raw = generate_refresh_token();
    let refresh_hash = sha256_hex(&refresh_raw);
    let expires_at = chrono::Utc::now() + REFRESH_TOKEN_TTL;
    db.create_session(user.id, &refresh_hash, None, None, expires_at)
        .await
        .map_err(internal_db_error)?;
    let csrf_token = generate_csrf_token();

    let mut resp = Redirect::to("/").into_response();
    append_header_cookie(
        &mut resp,
        build_auth_cookie(COOKIE_NAME, &access_token, 900, state.jwt_config.dev_mode),
    );
    append_header_cookie(
        &mut resp,
        build_auth_cookie(
            crate::auth::REFRESH_COOKIE_NAME,
            &refresh_raw,
            604_800,
            state.jwt_config.dev_mode,
        ),
    );
    append_header_cookie(
        &mut resp,
        build_csrf_cookie(&csrf_token, state.jwt_config.dev_mode),
    );
    append_header_cookie(
        &mut resp,
        build_clear_cookie(OIDC_STATE_COOKIE, state.jwt_config.dev_mode),
    );
    append_header_cookie(
        &mut resp,
        build_clear_cookie(OIDC_NONCE_COOKIE, state.jwt_config.dev_mode),
    );
    Ok(resp)
}

/// Returns admin-readable OIDC config without secrets.
///
/// Parameters: `_auth` - authenticated admin user, `state` - app state.
/// Returns: sanitized config.
pub async fn get_config(
    _auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, "")?;
    let cfg = load_oidc_config(db).await.map_err(internal_db_error)?;
    Ok(Json(OidcConfigResponse {
        enabled: cfg.enabled,
        provider_name: cfg.provider_name,
        issuer_url: cfg.issuer_url,
        client_id: cfg.client_id,
        redirect_uri: cfg.redirect_uri,
        scopes: cfg.scopes,
        auto_create_users: cfg.auto_create_users,
        default_role: cfg.default_role,
        role_claim: cfg.role_claim.unwrap_or_default(),
        role_mapping: cfg.role_mapping,
        allow_local_login: cfg.allow_local_login,
        has_client_secret: !cfg.client_secret.is_empty(),
    }))
}

/// Updates singleton OIDC configuration and encrypts client secret at rest.
///
/// Parameters: `_auth` - authenticated admin user, `state` - app state, `body` - new config.
/// Returns: HTTP 200 when saved.
pub async fn update_config(
    _auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<UpdateOidcConfigRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, "")?;
    let _default_role: UserRole = body.default_role.parse().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "default_role must be Admin/Operator/Viewer",
        )
    })?;
    if serde_json::from_str::<Value>(&body.role_mapping).is_err() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "role_mapping must be valid JSON",
        ));
    }
    let existing = load_oidc_config(db).await.map_err(internal_db_error)?;
    let secret_plain = body
        .client_secret
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    let secret_enc = if secret_plain.is_empty() {
        if existing.client_secret.is_empty() {
            String::new()
        } else {
            db.encrypt_config_value(&existing.client_secret)
                .map_err(internal_db_error)?
        }
    } else {
        db.encrypt_config_value(&secret_plain)
            .map_err(internal_db_error)?
    };
    sqlx::query(
        "UPDATE oidc_config
         SET enabled = ?, provider_name = ?, issuer_url = ?, client_id = ?, client_secret_enc = ?,
             redirect_uri = ?, scopes = ?, auto_create_users = ?, default_role = ?, role_claim = ?,
             role_mapping = ?, allow_local_login = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
         WHERE id = 1",
    )
    .bind(body.enabled)
    .bind(body.provider_name.trim())
    .bind(body.issuer_url.trim())
    .bind(body.client_id.trim())
    .bind(secret_enc)
    .bind(body.redirect_uri.trim())
    .bind(body.scopes.trim())
    .bind(body.auto_create_users)
    .bind(body.default_role.trim())
    .bind(body.role_claim.unwrap_or_default())
    .bind(body.role_mapping)
    .bind(body.allow_local_login)
    .execute(db.pool())
    .await
    .map_err(internal_db_error)?;
    Ok(StatusCode::OK)
}

/// Tests OIDC discovery against currently saved issuer URL.
///
/// Parameters: `_auth` - authenticated admin user, `state` - app state.
/// Returns: discovery status payload.
pub async fn test_discovery(
    _auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, "")?;
    let cfg = load_oidc_config(db).await.map_err(internal_db_error)?;
    if cfg.issuer_url.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "issuer_url is required",
        ));
    }
    let issuer = cfg.issuer_url.trim_end_matches('/').to_string();
    discover_document(&state.http_client, &issuer)
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                error::INTERNAL_ERROR,
                &format!("OIDC discovery failed: {e}"),
            )
        })?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "issuer_url": issuer
    })))
}

fn internal_db_error<E: std::fmt::Display>(e: E) -> ApiError {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        error::INTERNAL_ERROR,
        &format!("Database error: {e}"),
    )
}

fn cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|part| {
                let part = part.trim();
                part.strip_prefix(&format!("{name}="))
                    .map(ToString::to_string)
            })
        })
}

fn append_cookie(
    resp: &mut axum::response::Response,
    name: &str,
    value: &str,
    max_age: i64,
    dev_mode: bool,
    http_only: bool,
) {
    let secure = if dev_mode { "" } else { "; Secure" };
    let http_only_suffix = if http_only { "; HttpOnly" } else { "" };
    let cookie = format!(
        "{name}={value}; SameSite=Strict; Path=/; Max-Age={max_age}{http_only_suffix}{secure}"
    );
    append_header_cookie(resp, cookie);
}

fn append_header_cookie(resp: &mut axum::response::Response, cookie: String) {
    if let Ok(hv) = axum::http::HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
}

fn resolve_role(
    claims: &crate::oidc::IdTokenClaims,
    cfg: &crate::oidc::OidcConfig,
) -> Result<UserRole, ApiError> {
    let default_role = cfg.default_role.parse::<UserRole>().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Invalid OIDC default role",
        )
    })?;
    let role_claim = cfg.role_claim.as_deref().unwrap_or("").trim();
    if role_claim.is_empty() {
        return Ok(default_role);
    }
    let mapping: HashMap<String, String> =
        serde_json::from_str(&cfg.role_mapping).unwrap_or_default();
    let claim_value = claims.extra.get(role_claim);
    let mut incoming_roles = Vec::<String>::new();
    if let Some(v) = claim_value {
        match v {
            Value::String(s) => incoming_roles.push(s.clone()),
            Value::Array(arr) => {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        incoming_roles.push(s.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    for role_name in incoming_roles {
        if let Some(mapped) = mapping.get(&role_name) {
            if let Ok(role) = mapped.parse::<UserRole>() {
                return Ok(role);
            }
        }
    }
    Ok(default_role)
}

fn normalize_username(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '@' {
            out.push('_');
        }
    }
    if out.is_empty() {
        "oidc_user".to_string()
    } else {
        out.chars().take(50).collect()
    }
}

fn build_clear_cookie(name: &str, dev_mode: bool) -> String {
    let secure = if dev_mode { "" } else { "; Secure" };
    format!("{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}")
}
