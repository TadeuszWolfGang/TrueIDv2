//! TrueID Web library — router, handlers, and shared app state.
//!
//! The binary crate (`main.rs`) handles startup and server binding.

pub mod auth;
pub mod cursor;
pub mod error;
pub mod helpers;
pub mod middleware;
pub mod oidc;
pub mod password_policy;
pub mod rate_limit;
pub mod routes;
pub mod routes_alerts;
pub mod routes_analytics;
pub mod routes_api_keys;
pub mod routes_audit;
pub mod routes_auth;
pub mod routes_conflicts;
pub mod routes_dns;
pub mod routes_fingerprints;
pub mod routes_firewall;
pub mod routes_geo;
pub mod routes_import;
pub mod routes_ldap;
pub mod routes_map;
pub mod routes_notifications;
pub mod routes_oidc;
pub mod routes_proxy;
pub mod routes_report_schedules;
pub mod routes_retention;
pub mod routes_search;
pub mod routes_security;
pub mod routes_siem;
pub mod routes_sse;
pub mod routes_subnets;
pub mod routes_switches;
pub mod routes_tags;
pub mod routes_timeline;
pub mod routes_totp;
pub mod routes_users;
pub mod routes_v1;

use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware as axum_mw,
    response::{IntoResponse, Response},
    Json, Router,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use trueid_common::db::Db;

use crate::auth::JwtConfig;

/// Default engine API URL used by the proxy routes.
pub const DEFAULT_ENGINE_URL: &str = "http://127.0.0.1:8080";

/// Per-request ID stored in extensions.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Shared application state for all handlers and middleware.
#[derive(Clone)]
pub struct AppState {
    pub db: Option<Arc<Db>>,
    pub config: Arc<tokio::sync::RwLock<trueid_common::app_config::AppConfig>>,
    pub engine_url: String,
    pub http_client: reqwest::Client,
    pub jwt_config: JwtConfig,
    pub engine_service_token: Option<String>,
    pub metrics_token: Option<String>,
    pub login_limiter: Arc<rate_limit::RateLimiter>,
    pub per_key_limiter: Arc<rate_limit::PerKeyLimiter>,
    pub session_limiter: Arc<rate_limit::PerKeyLimiter>,
    pub auth_chain: Option<Arc<trueid_common::auth_provider::AuthProviderChain>>,
}

/// Middleware that generates a UUID v4 request_id for each request,
/// stores it in extensions, and adds X-Request-Id response header.
async fn request_id_layer(mut req: Request, next: axum_mw::Next) -> Response {
    let rid = uuid::Uuid::new_v4().to_string();
    req.extensions_mut().insert(RequestId(rid.clone()));
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        "x-request-id",
        axum::http::HeaderValue::from_str(&rid)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("unknown")),
    );
    resp
}

/// Middleware that rate-limits login attempts by client IP.
///
/// Extracts client IP from X-Forwarded-For header or peer address.
/// Returns 429 Too Many Requests with Retry-After header when limit exceeded.
pub(crate) async fn login_rate_limit(
    State(state): State<AppState>,
    req: Request,
    next: axum_mw::Next,
) -> Response {
    let ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    if !state.login_limiter.check(&ip) {
        let body = serde_json::json!({
            "error": "Too many login attempts. Try again later.",
            "code": "RATE_LIMITED"
        });
        let mut resp = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
        resp.headers_mut()
            .insert("retry-after", axum::http::HeaderValue::from_static("60"));
        return resp;
    }
    next.run(req).await
}

/// Middleware that adds security headers to every response.
///
/// Sets CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
/// and Permissions-Policy on all outgoing responses.
async fn security_headers_layer(req: Request, next: axum_mw::Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    // TODO: migrate to nonce-based CSP when dashboard moves to external JS files
    h.insert(
        "content-security-policy",
        axum::http::HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; \
             style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
             connect-src 'self'; frame-ancestors 'none'",
        ),
    );
    h.insert(
        "x-frame-options",
        axum::http::HeaderValue::from_static("DENY"),
    );
    h.insert(
        "x-content-type-options",
        axum::http::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        "referrer-policy",
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        "permissions-policy",
        axum::http::HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    resp
}

/// Middleware that enforces auth principal rate limits and emits rate-limit headers.
///
/// Parameters: `state` - shared state, `req` - incoming request, `next` - next handler.
/// Returns: throttled or forwarded response with rate-limit headers.
pub(crate) async fn auth_rate_limit_layer(
    State(state): State<AppState>,
    req: Request,
    next: axum_mw::Next,
) -> Response {
    let reset_epoch = next_minute_epoch();
    let rate_headers = |resp: &mut Response, limit: u32, remaining: u32, reset: u64| {
        if let Ok(v) = HeaderValue::from_str(&limit.to_string()) {
            resp.headers_mut().insert("x-ratelimit-limit", v);
        }
        if let Ok(v) = HeaderValue::from_str(&remaining.to_string()) {
            resp.headers_mut().insert("x-ratelimit-remaining", v);
        }
        if let Ok(v) = HeaderValue::from_str(&reset.to_string()) {
            resp.headers_mut().insert("x-ratelimit-reset", v);
        }
    };

    if let Some(api_key) = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    {
        if let Some(db) = state.db.as_ref() {
            if let Ok(Some(record)) = db.lookup_api_key(&api_key).await {
                let rpm = record.rate_limit_rpm.max(1) as u32;
                let burst = record.rate_limit_burst.max(1) as u32;
                match state
                    .per_key_limiter
                    .check(&format!("api_key:{}", record.id), rpm, burst)
                {
                    Ok(remaining) => {
                        let mut resp = next.run(req).await;
                        rate_headers(&mut resp, rpm, remaining, reset_epoch);
                        let status = resp.status();
                        let db_clone = Arc::clone(db);
                        tokio::spawn(async move {
                            let _ = db_clone
                                .record_api_key_usage(record.id, status.as_u16() >= 400)
                                .await;
                        });
                        return resp;
                    }
                    Err(retry_after) => {
                        let body = serde_json::json!({
                            "error": "Rate limit exceeded",
                            "code": "RATE_LIMITED",
                        });
                        let mut resp = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
                        if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
                            resp.headers_mut().insert("retry-after", v);
                        }
                        rate_headers(&mut resp, rpm, 0, reset_epoch);
                        let db_clone = Arc::clone(db);
                        tokio::spawn(async move {
                            let _ = db_clone.record_api_key_usage(record.id, true).await;
                        });
                        return resp;
                    }
                }
            }
        }
        return next.run(req).await;
    }

    let cookie_header = req
        .headers()
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Some(token) = crate::auth::extract_cookie(cookie_header, crate::auth::COOKIE_NAME) {
        if let Ok(claims) = crate::auth::validate_token(&state.jwt_config, token) {
            let rpm = 300_u32;
            let burst = 60_u32;
            match state
                .session_limiter
                .check(&format!("user:{}", claims.sub), rpm, burst)
            {
                Ok(remaining) => {
                    let mut resp = next.run(req).await;
                    rate_headers(&mut resp, rpm, remaining, reset_epoch);
                    return resp;
                }
                Err(retry_after) => {
                    let body = serde_json::json!({
                        "error": "Rate limit exceeded",
                        "code": "RATE_LIMITED",
                    });
                    let mut resp = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
                    if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
                        resp.headers_mut().insert("retry-after", v);
                    }
                    rate_headers(&mut resp, rpm, 0, reset_epoch);
                    return resp;
                }
            }
        }
    }

    next.run(req).await
}

/// Returns UNIX timestamp for the next minute boundary.
///
/// Parameters: none.
/// Returns: seconds since UNIX epoch.
fn next_minute_epoch() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    ((now / 60) + 1) * 60
}

/// Builds the application router with all routes and middleware.
///
/// Used by both production startup and in-process integration tests.
///
/// Parameters: `state` - fully initialized application state.
/// Returns: configured Axum router.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .merge(routes::system_routes())
        .merge(routes::auth_routes(state.clone()))
        .merge(routes::v1_routes(state.clone()))
        .merge(routes::v2_routes(state.clone()))
        .merge(routes::admin_routes(state.clone()))
        .merge(routes::operator_routes(state.clone()))
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            auth_rate_limit_layer,
        ))
        .layer(axum_mw::from_fn(middleware::csrf_guard))
        .layer(axum_mw::from_fn(request_id_layer))
        .layer(axum_mw::from_fn(security_headers_layer))
        .with_state(state)
}
