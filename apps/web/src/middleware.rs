//! Auth extractors and CSRF guard for TrueID web.
//!
//! `AuthUser` — Axum extractor: JWT cookie or X-API-Key header.
//! `OptionalAuthUser` — same but returns `Option`.
//! `csrf_guard` — rejects mutating cookie-auth requests without valid CSRF token.
//! `require_*` role-check helpers.

use async_trait::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts, Request, State},
    http::{header, request::Parts, Method, StatusCode},
    middleware::Next,
    response::Response,
};
use tracing::warn;

use crate::auth::{self, extract_cookie, validate_token, COOKIE_NAME, CSRF_COOKIE_NAME};
use crate::error::{self, ApiError};
use crate::helpers;
use crate::AppState;
use crate::RequestId;
use trueid_common::model::UserRole;

// ── AuthUser ───────────────────────────────────────────────

/// Authenticated principal extracted from cookie JWT or API key header.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: i64,
    pub username: String,
    pub role: UserRole,
    /// "user" for cookie/JWT auth, "api_key" for API key auth.
    pub principal_type: String,
    pub request_id: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let rid = parts
            .extensions
            .get::<RequestId>()
            .map(|r| r.0.clone())
            .unwrap_or_default();

        // 1) Try X-API-Key header.
        if let Some(api_key_value) = parts.headers.get("x-api-key") {
            if let Ok(raw_key) = api_key_value.to_str() {
                if let Some(ref db) = app_state.db {
                    match db.validate_api_key(raw_key).await {
                        Ok(Some(record)) => {
                            return Ok(AuthUser {
                                user_id: record.created_by,
                                username: format!("apikey:{}", record.key_prefix),
                                role: record.role,
                                principal_type: "api_key".to_string(),
                                request_id: rid,
                            });
                        }
                        Ok(None) => {
                            return Err(ApiError::new(
                                StatusCode::UNAUTHORIZED,
                                error::AUTH_REQUIRED,
                                "Invalid or expired API key",
                            )
                            .with_request_id(&rid));
                        }
                        Err(e) => {
                            warn!(error = %e, "API key validation error");
                            return Err(ApiError::new(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                error::INTERNAL_ERROR,
                                "Internal error during API key validation",
                            )
                            .with_request_id(&rid));
                        }
                    }
                }
            }
        }

        // 2) Try JWT from cookie.
        let cookie_header = parts
            .headers
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let token = extract_cookie(cookie_header, COOKIE_NAME);
        let Some(token) = token else {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                error::AUTH_REQUIRED,
                "Authentication required",
            )
            .with_request_id(&rid));
        };
        let token = token.to_string();

        // Validate JWT.
        let claims = match validate_token(&app_state.jwt_config, &token) {
            Ok(c) => c,
            Err(_) => {
                return Err(ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    error::AUTH_REQUIRED,
                    "Invalid or expired token",
                )
                .with_request_id(&rid));
            }
        };

        let user_id: i64 = claims.sub.parse().unwrap_or(0);

        // Verify user still exists and token_version matches.
        let db = helpers::require_db(&app_state, &rid)?;

        let user = db.get_user_by_id(user_id).await.ok().flatten();
        let Some(user) = user else {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                error::AUTH_REQUIRED,
                "User no longer exists",
            )
            .with_request_id(&rid));
        };

        // Check token_version.
        if user.token_version != claims.token_version {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                error::AUTH_REQUIRED,
                "Token invalidated — please log in again",
            )
            .with_request_id(&rid));
        }

        // Check account locked.
        if db.is_account_locked(&user) {
            return Err(ApiError::new(
                StatusCode::LOCKED,
                error::ACCOUNT_LOCKED,
                "Account is locked",
            )
            .with_request_id(&rid));
        }

        // Session hardening checks (cookie auth only).
        let refresh_token = extract_cookie(cookie_header, auth::REFRESH_COOKIE_NAME).ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                error::AUTH_REQUIRED,
                "Refresh token missing",
            )
            .with_request_id(&rid)
        })?;
        let refresh_hash = trueid_common::db_auth::sha256_hex(refresh_token);
        let session = db
            .get_session_for_security_checks(&refresh_hash)
            .await
            .ok()
            .flatten()
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    error::AUTH_REQUIRED,
                    "Session is invalid or revoked",
                )
                .with_request_id(&rid)
            })?;

        if session.user_id != user.id {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                error::AUTH_REQUIRED,
                "Session does not belong to authenticated user",
            )
            .with_request_id(&rid));
        }

        let idle_limit = app_state.config.read().await.session_idle_minutes;
        if idle_limit <= 0
            || session.last_active_at + chrono::Duration::minutes(idle_limit) < chrono::Utc::now()
        {
            let _ = db.revoke_session(session.id).await;
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                error::AUTH_REQUIRED,
                "Session expired due to inactivity",
            )
            .with_request_id(&rid));
        }
        let max_hours = app_state.config.read().await.session_max_hours;
        if max_hours <= 0
            || session.created_at + chrono::Duration::hours(max_hours) < chrono::Utc::now()
        {
            let _ = db.revoke_session(session.id).await;
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                error::AUTH_REQUIRED,
                "Session expired",
            )
            .with_request_id(&rid));
        }

        if let Some(bound_ip) = session.ip_address.as_deref() {
            let request_ip = parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(str::trim)
                .or_else(|| {
                    parts
                        .headers
                        .get("x-real-ip")
                        .and_then(|v| v.to_str().ok())
                        .map(str::trim)
                });
            if let Some(ip) = request_ip {
                if ip != bound_ip {
                    return Err(ApiError::new(
                        StatusCode::UNAUTHORIZED,
                        error::AUTH_REQUIRED,
                        "Session IP mismatch",
                    )
                    .with_request_id(&rid));
                }
            }
        }
        if let Some(bound_ua) = session.user_agent.as_deref() {
            let request_ua = parts
                .headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok());
            if let Some(ua) = request_ua {
                if ua != bound_ua {
                    return Err(ApiError::new(
                        StatusCode::UNAUTHORIZED,
                        error::AUTH_REQUIRED,
                        "Session user-agent mismatch",
                    )
                    .with_request_id(&rid));
                }
            }
        }
        let _ = db.touch_session_activity(session.id).await;

        Ok(AuthUser {
            user_id: user.id,
            username: user.username.clone(),
            role: user.role,
            principal_type: "user".to_string(),
            request_id: rid,
        })
    }
}

// ── OptionalAuthUser ───────────────────────────────────────

/// Like `AuthUser` but returns `None` instead of 401 for unauthenticated requests.
pub struct OptionalAuthUser(pub Option<AuthUser>);

#[async_trait]
impl<S> FromRequestParts<S> for OptionalAuthUser
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match AuthUser::from_request_parts(parts, state).await {
            Ok(user) => Ok(Self(Some(user))),
            Err(_) => Ok(Self(None)),
        }
    }
}

// ── CSRF guard ─────────────────────────────────────────────

/// Middleware that validates CSRF token for mutating requests with cookie auth.
///
/// Compares X-CSRF-Token header against trueid_csrf_token cookie.
/// Skips validation for GET/HEAD/OPTIONS and for API-key auth.
pub async fn csrf_guard(req: Request, next: Next) -> Result<Response, ApiError> {
    let method = req.method().clone();

    // Safe methods: skip.
    if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        return Ok(next.run(req).await);
    }

    let rid = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();

    let cookie_header = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Only enforce CSRF if there is a cookie-based auth token present.
    // API key requests (no auth cookie) bypass CSRF.
    let has_auth_cookie = extract_cookie(&cookie_header, auth::COOKIE_NAME).is_some();
    if !has_auth_cookie {
        return Ok(next.run(req).await);
    }

    // Check if request uses API key header (skip CSRF for API keys).
    if req.headers().contains_key("x-api-key") {
        return Ok(next.run(req).await);
    }

    let csrf_cookie = extract_cookie(&cookie_header, CSRF_COOKIE_NAME)
        .unwrap_or("")
        .to_string();
    let csrf_header = req
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if csrf_cookie.is_empty() || csrf_header.is_empty() || csrf_cookie != csrf_header {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            error::CSRF_FAILED,
            "CSRF token missing or invalid",
        )
        .with_request_id(&rid));
    }

    Ok(next.run(req).await)
}

// ── Role helpers ───────────────────────────────────────────

/// Checks if user has one of the allowed roles.
///
/// Parameters: `user`, `allowed` — slice of permitted roles.
/// Returns: `Ok(())` or `ApiError::FORBIDDEN`.
pub fn require_role(user: &AuthUser, allowed: &[UserRole]) -> Result<(), ApiError> {
    if allowed.contains(&user.role) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            error::FORBIDDEN,
            "Insufficient permissions",
        )
        .with_request_id(&user.request_id))
    }
}

/// Requires Admin role.
pub fn require_admin(user: &AuthUser) -> Result<(), ApiError> {
    require_role(user, &[UserRole::Admin])
}

/// Requires Admin or Operator role.
pub fn require_operator(user: &AuthUser) -> Result<(), ApiError> {
    require_role(user, &[UserRole::Admin, UserRole::Operator])
}

/// Requires any authenticated role (Admin, Operator, or Viewer).
pub fn require_viewer(user: &AuthUser) -> Result<(), ApiError> {
    require_role(
        user,
        &[UserRole::Admin, UserRole::Operator, UserRole::Viewer],
    )
}

// ── Router-level role middleware layers ─────────────────────

/// Middleware layer: requires any authenticated user (Viewer+).
///
/// Apply on a Router group to enforce auth on all routes in the group.
pub async fn require_viewer_layer(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let (mut parts, body) = req.into_parts();
    let auth = AuthUser::from_request_parts(&mut parts, &state).await?;
    require_viewer(&auth)?;
    Ok(next.run(Request::from_parts(parts, body)).await)
}

/// Middleware layer: requires Admin or Operator role.
pub async fn require_operator_layer(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let (mut parts, body) = req.into_parts();
    let auth = AuthUser::from_request_parts(&mut parts, &state).await?;
    require_operator(&auth)?;
    Ok(next.run(Request::from_parts(parts, body)).await)
}

/// Middleware layer: requires Admin role.
pub async fn require_admin_layer(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let (mut parts, body) = req.into_parts();
    let auth = AuthUser::from_request_parts(&mut parts, &state).await?;
    require_admin(&auth)?;
    Ok(next.run(Request::from_parts(parts, body)).await)
}

// extract_cookie is imported from crate::auth
