//! Authentication endpoints: login, logout, refresh, me, change-password, sessions.

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::auth::{
    build_auth_cookie, build_clear_cookie, build_csrf_cookie, create_access_token,
    generate_csrf_token, generate_refresh_token, COOKIE_NAME, CSRF_COOKIE_NAME,
    REFRESH_COOKIE_NAME, REFRESH_TOKEN_TTL,
};
use crate::error::{self, ApiError};
use crate::middleware::AuthUser;
use crate::AppState;
use trueid_common::auth_provider::AuthResult;
use trueid_common::db_auth::sha256_hex;
use trueid_common::model::UserPublic;

// ── Request / response types ───────────────────────────────

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    user: UserPublic,
    force_password_change: bool,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Serialize)]
struct SessionInfo {
    id: i64,
    user_agent: Option<String>,
    ip_address: Option<String>,
    created_at: String,
    last_used_at: String,
    is_current: bool,
}

#[derive(Serialize)]
struct MeResponse {
    user: UserPublic,
    force_password_change: bool,
    active_sessions_count: usize,
}

// ── Helpers ────────────────────────────────────────────────

/// Extracts client IP from X-Forwarded-For or peer address.
fn client_ip(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
}

/// Extracts a named cookie from the Cookie header.
fn extract_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
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

/// Builds the three Set-Cookie headers for login/refresh.
fn auth_cookies(
    access_token: &str,
    refresh_token: &str,
    csrf_token: &str,
    dev_mode: bool,
) -> Vec<(header::HeaderName, String)> {
    vec![
        (
            header::SET_COOKIE,
            build_auth_cookie(COOKIE_NAME, access_token, 900, dev_mode),
        ),
        (
            header::SET_COOKIE,
            build_auth_cookie(REFRESH_COOKIE_NAME, refresh_token, 604_800, dev_mode),
        ),
        (
            header::SET_COOKIE,
            build_csrf_cookie(csrf_token, dev_mode),
        ),
    ]
}

/// Builds Set-Cookie headers that clear all auth cookies.
fn clear_cookies(dev_mode: bool) -> Vec<(header::HeaderName, String)> {
    vec![
        (
            header::SET_COOKIE,
            build_clear_cookie(COOKIE_NAME, dev_mode),
        ),
        (
            header::SET_COOKIE,
            build_clear_cookie(REFRESH_COOKIE_NAME, dev_mode),
        ),
        (
            header::SET_COOKIE,
            build_clear_cookie(CSRF_COOKIE_NAME, dev_mode),
        ),
    ]
}

// ── POST /api/auth/login ───────────────────────────────────

/// Authenticates a user with username/password. Sets JWT + refresh + CSRF cookies.
pub async fn login(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let rid = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let ip = client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let db = state.db.as_ref().ok_or_else(|| {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error::SERVICE_UNAVAILABLE, "Database unavailable")
    })?;
    let auth_chain = state.auth_chain.as_ref().ok_or_else(|| {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error::SERVICE_UNAVAILABLE, "Auth not available")
    })?;

    // Authenticate via provider chain (handles lookup, lockout, password verify).
    let user = match auth_chain.authenticate(&body.username, &body.password).await {
        AuthResult::Success(u) => u,
        AuthResult::InvalidCredentials => {
            let _ = db.write_audit_log(
                None, &body.username, "system", "login_failed",
                None, None, ip.as_deref(), Some(&rid),
            ).await;
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                error::INVALID_CREDENTIALS,
                "Invalid credentials",
            ).with_request_id(&rid));
        }
        AuthResult::AccountLocked { .. } => {
            let _ = db.write_audit_log(
                None, &body.username, "system", "login_failed_locked",
                None, None, ip.as_deref(), Some(&rid),
            ).await;
            return Err(ApiError::new(
                StatusCode::LOCKED,
                error::ACCOUNT_LOCKED,
                "Account is locked due to too many failed attempts",
            ).with_request_id(&rid));
        }
        AuthResult::Error(msg) => {
            warn!(error = %msg, "Auth provider error");
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Authentication error",
            ).with_request_id(&rid));
        }
    };

    // Issue tokens.

    let access_token = create_access_token(&state.jwt_config, &user)
        .map_err(|e| {
            warn!(error = %e, "Failed to create access token");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error::INTERNAL_ERROR, "Token creation failed")
        })?;

    let refresh_raw = generate_refresh_token();
    let refresh_hash = sha256_hex(&refresh_raw);
    let expires_at = chrono::Utc::now() + REFRESH_TOKEN_TTL;

    let _ = db.create_session(
        user.id, &refresh_hash, ua.as_deref(), ip.as_deref(), expires_at,
    ).await;

    let csrf_token = generate_csrf_token();

    let _ = db.write_audit_log(
        Some(user.id), &user.username, "user", "login_success",
        None, None, ip.as_deref(), Some(&rid),
    ).await;

    let cookies = auth_cookies(&access_token, &refresh_raw, &csrf_token, state.jwt_config.dev_mode);
    let force = user.force_password_change;
    let resp_body = LoginResponse {
        user: UserPublic::from(user),
        force_password_change: force,
    };

    let mut resp = (StatusCode::OK, Json(resp_body)).into_response();
    for (name, value) in cookies {
        if let Ok(hv) = axum::http::HeaderValue::from_str(&value) {
            resp.headers_mut().append(name, hv);
        }
    }
    Ok(resp)
}

// ── POST /api/auth/logout ──────────────────────────────────

/// Logs out the current session (revokes refresh token, clears cookies).
pub async fn logout(
    auth: AuthUser,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let db = state.db.as_ref().ok_or_else(|| {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error::SERVICE_UNAVAILABLE, "Database unavailable")
    })?;
    let ip = client_ip(&headers);

    // Revoke the specific refresh session.
    let cookie_header = headers.get(header::COOKIE)
        .and_then(|v| v.to_str().ok()).unwrap_or("");
    if let Some(rt) = extract_cookie(cookie_header, REFRESH_COOKIE_NAME) {
        let hash = sha256_hex(rt);
        if let Ok(Some(session)) = db.get_session_by_token_hash(&hash).await {
            let _ = db.revoke_session(session.id).await;
        }
    }

    let _ = db.write_audit_log(
        Some(auth.user_id), &auth.username, &auth.principal_type, "logout",
        None, None, ip.as_deref(), Some(&auth.request_id),
    ).await;

    let cookies = clear_cookies(state.jwt_config.dev_mode);
    let mut resp = StatusCode::OK.into_response();
    for (name, value) in cookies {
        if let Ok(hv) = axum::http::HeaderValue::from_str(&value) {
            resp.headers_mut().append(name, hv);
        }
    }
    Ok(resp)
}

// ── POST /api/auth/logout-all ──────────────────────────────

/// Revokes ALL sessions for the user and bumps token_version.
pub async fn logout_all(
    auth: AuthUser,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let db = state.db.as_ref().ok_or_else(|| {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error::SERVICE_UNAVAILABLE, "Database unavailable")
    })?;
    let ip = client_ip(&headers);

    let count = db.revoke_all_sessions(auth.user_id).await.unwrap_or(0);
    let _ = db.bump_token_version(auth.user_id).await;

    let _ = db.write_audit_log(
        Some(auth.user_id), &auth.username, &auth.principal_type, "logout_all",
        None, Some(&format!("{{\"sessions_revoked\":{count}}}")),
        ip.as_deref(), Some(&auth.request_id),
    ).await;

    let cookies = clear_cookies(state.jwt_config.dev_mode);
    let mut resp = StatusCode::OK.into_response();
    for (name, value) in cookies {
        if let Ok(hv) = axum::http::HeaderValue::from_str(&value) {
            resp.headers_mut().append(name, hv);
        }
    }
    Ok(resp)
}

// ── POST /api/auth/refresh ─────────────────────────────────

/// Rotates the refresh token. Detects token reuse (replay attack).
pub async fn refresh(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let rid = headers.get("x-request-id")
        .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();

    let db = state.db.as_ref().ok_or_else(|| {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error::SERVICE_UNAVAILABLE, "Database unavailable")
    })?;

    let cookie_header = headers.get(header::COOKIE)
        .and_then(|v| v.to_str().ok()).unwrap_or("");
    let rt = extract_cookie(cookie_header, REFRESH_COOKIE_NAME).ok_or_else(|| {
        ApiError::new(StatusCode::UNAUTHORIZED, error::AUTH_REQUIRED, "Refresh token missing")
            .with_request_id(&rid)
    })?;

    let old_hash = sha256_hex(rt);
    let new_raw = generate_refresh_token();
    let new_hash = sha256_hex(&new_raw);
    let new_expires = chrono::Utc::now() + REFRESH_TOKEN_TTL;

    let new_session = db.rotate_session(&old_hash, &new_hash, new_expires).await
        .map_err(|e| {
            warn!(error = %e, "Session rotation error");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error::INTERNAL_ERROR, "Session rotation failed")
                .with_request_id(&rid)
        })?;

    let Some(new_session) = new_session else {
        // Token reuse detected — all sessions revoked by rotate_session.
        let cookies = clear_cookies(state.jwt_config.dev_mode);
        let mut resp = ApiError::new(
            StatusCode::UNAUTHORIZED, error::AUTH_REQUIRED,
            "Refresh token reuse detected — all sessions revoked",
        ).with_request_id(&rid).into_response();
        for (name, value) in cookies {
            if let Ok(hv) = axum::http::HeaderValue::from_str(&value) {
                resp.headers_mut().append(name, hv);
            }
        }
        return Ok(resp);
    };

    // Fetch user for new access token.
    let user = db.get_user_by_id(new_session.user_id).await
        .ok().flatten()
        .ok_or_else(|| {
            ApiError::new(StatusCode::UNAUTHORIZED, error::AUTH_REQUIRED, "User not found")
                .with_request_id(&rid)
        })?;

    let access_token = create_access_token(&state.jwt_config, &user)
        .map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error::INTERNAL_ERROR, "Token creation failed")
                .with_request_id(&rid)
        })?;

    let csrf_token = generate_csrf_token();
    let cookies = auth_cookies(&access_token, &new_raw, &csrf_token, state.jwt_config.dev_mode);

    let mut resp = StatusCode::OK.into_response();
    for (name, value) in cookies {
        if let Ok(hv) = axum::http::HeaderValue::from_str(&value) {
            resp.headers_mut().append(name, hv);
        }
    }
    Ok(resp)
}

// ── GET /api/auth/me ───────────────────────────────────────

/// Returns current user info and active session count.
pub async fn me(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = state.db.as_ref().ok_or_else(|| {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error::SERVICE_UNAVAILABLE, "Database unavailable")
    })?;

    let user = db.get_user_by_id(auth.user_id).await.ok().flatten()
        .ok_or_else(|| {
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "User not found")
                .with_request_id(&auth.request_id)
        })?;

    let sessions = db.list_active_sessions(auth.user_id).await.unwrap_or_default();

    Ok(Json(MeResponse {
        force_password_change: user.force_password_change,
        active_sessions_count: sessions.len(),
        user: UserPublic::from(user),
    }))
}

// ── POST /api/auth/change-password ─────────────────────────

/// Changes the current user's password. Cookie auth only (not API key).
pub async fn change_password(
    auth: AuthUser,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Only cookie-auth users can change password.
    if auth.principal_type != "user" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN, error::FORBIDDEN,
            "Password change is only available for cookie-authenticated users",
        ).with_request_id(&auth.request_id));
    }

    if body.new_password.len() < 12 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST, error::INVALID_INPUT,
            "New password must be at least 12 characters",
        ).with_request_id(&auth.request_id));
    }
    if body.new_password == body.current_password {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST, error::INVALID_INPUT,
            "New password must differ from current password",
        ).with_request_id(&auth.request_id));
    }

    let db = state.db.as_ref().ok_or_else(|| {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error::SERVICE_UNAVAILABLE, "Database unavailable")
    })?;
    let auth_chain = state.auth_chain.as_ref().ok_or_else(|| {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error::SERVICE_UNAVAILABLE, "Auth not available")
    })?;
    let ip = client_ip(&headers);

    // Determine user's auth source.
    let user_rec = db.get_user_by_id(auth.user_id).await.ok().flatten()
        .ok_or_else(|| {
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "User not found")
        })?;

    if !auth_chain.supports_password_change(&user_rec.auth_source) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST, error::INVALID_INPUT,
            "Password changes are not supported for this account type. Change password in Active Directory.",
        ).with_request_id(&auth.request_id));
    }

    // Change password via provider chain (handles verify + update).
    auth_chain.change_password(auth.user_id, &user_rec.auth_source, &body.current_password, &body.new_password)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("incorrect") {
                ApiError::new(StatusCode::UNAUTHORIZED, error::INVALID_CREDENTIALS, "Current password is incorrect")
                    .with_request_id(&auth.request_id)
            } else {
                warn!(error = %e, "Password change failed");
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error::INTERNAL_ERROR, "Password change failed")
            }
        })?;

    // Re-fetch user (token_version bumped).
    let user = db.get_user_by_id(auth.user_id).await.ok().flatten()
        .ok_or_else(|| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error::INTERNAL_ERROR, "User refetch failed")
        })?;

    // Issue fresh tokens.
    let access_token = create_access_token(&state.jwt_config, &user)
        .map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error::INTERNAL_ERROR, "Token creation failed")
        })?;

    let refresh_raw = generate_refresh_token();
    let refresh_hash = sha256_hex(&refresh_raw);
    let expires_at = chrono::Utc::now() + REFRESH_TOKEN_TTL;
    let ua = headers.get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok()).map(|s| s.to_string());

    let _ = db.create_session(
        user.id, &refresh_hash, ua.as_deref(), ip.as_deref(), expires_at,
    ).await;

    let csrf_token = generate_csrf_token();

    let _ = db.write_audit_log(
        Some(auth.user_id), &auth.username, &auth.principal_type, "password_changed",
        Some(&format!("user:{}", auth.user_id)), None, ip.as_deref(), Some(&auth.request_id),
    ).await;

    let cookies = auth_cookies(&access_token, &refresh_raw, &csrf_token, state.jwt_config.dev_mode);
    let mut resp = StatusCode::OK.into_response();
    for (name, value) in cookies {
        if let Ok(hv) = axum::http::HeaderValue::from_str(&value) {
            resp.headers_mut().append(name, hv);
        }
    }
    Ok(resp)
}

// ── GET /api/auth/sessions ─────────────────────────────────

/// Lists active sessions for the current user.
pub async fn list_sessions(
    auth: AuthUser,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let db = state.db.as_ref().ok_or_else(|| {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error::SERVICE_UNAVAILABLE, "Database unavailable")
    })?;

    let sessions = db.list_active_sessions(auth.user_id).await.map_err(|e| {
        warn!(error = %e, "Failed to list sessions");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error::INTERNAL_ERROR, "Failed to list sessions")
    })?;

    // Determine current session by refresh token hash.
    let cookie_header = headers.get(header::COOKIE)
        .and_then(|v| v.to_str().ok()).unwrap_or("");
    let current_hash = extract_cookie(cookie_header, REFRESH_COOKIE_NAME)
        .map(sha256_hex);

    let infos: Vec<SessionInfo> = sessions.iter().map(|s| {
        SessionInfo {
            id: s.id,
            user_agent: s.user_agent.clone(),
            ip_address: s.ip_address.clone(),
            created_at: s.created_at.to_rfc3339(),
            last_used_at: s.last_used_at.to_rfc3339(),
            is_current: current_hash.as_deref() == Some(&s.refresh_token_hash),
        }
    }).collect();

    Ok(Json(infos))
}

// ── DELETE /api/auth/sessions/{id} ─────────────────────────

/// Revokes a specific session (logout that device). Cannot revoke current session.
pub async fn revoke_session(
    auth: AuthUser,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(session_id): Path<i64>,
) -> Result<impl IntoResponse, ApiError> {
    let db = state.db.as_ref().ok_or_else(|| {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error::SERVICE_UNAVAILABLE, "Database unavailable")
    })?;
    let ip = client_ip(&headers);

    // Ensure session belongs to user.
    let sessions = db.list_active_sessions(auth.user_id).await.unwrap_or_default();
    let target = sessions.iter().find(|s| s.id == session_id);
    let Some(_target) = target else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND, error::NOT_FOUND, "Session not found",
        ).with_request_id(&auth.request_id));
    };

    // Check not revoking current session.
    let cookie_header = headers.get(header::COOKIE)
        .and_then(|v| v.to_str().ok()).unwrap_or("");
    if let Some(rt) = extract_cookie(cookie_header, REFRESH_COOKIE_NAME) {
        let hash = sha256_hex(rt);
        if sessions.iter().any(|s| s.id == session_id && s.refresh_token_hash == hash) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST, error::INVALID_INPUT,
                "Cannot revoke current session — use /api/auth/logout instead",
            ).with_request_id(&auth.request_id));
        }
    }

    db.revoke_session(session_id).await.map_err(|e| {
        warn!(error = %e, "Failed to revoke session");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error::INTERNAL_ERROR, "Failed to revoke session")
    })?;

    let _ = db.write_audit_log(
        Some(auth.user_id), &auth.username, &auth.principal_type, "session_revoked",
        Some(&format!("session:{session_id}")), None, ip.as_deref(), Some(&auth.request_id),
    ).await;

    Ok(StatusCode::OK)
}
