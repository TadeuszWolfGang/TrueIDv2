//! TrueID Web library — router, handlers, and shared app state.
//!
//! The binary crate (`main.rs`) handles startup and server binding.

pub mod auth;
pub mod error;
pub mod middleware;
pub mod rate_limit;
pub mod routes_alerts;
pub mod routes_api_keys;
pub mod routes_audit;
pub mod routes_auth;
pub mod routes_conflicts;
pub mod routes_proxy;
pub mod routes_search;
pub mod routes_subnets;
pub mod routes_timeline;
pub mod routes_users;
pub mod routes_v1;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware as axum_mw,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use std::sync::Arc;
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
    pub engine_url: String,
    pub http_client: reqwest::Client,
    pub jwt_config: JwtConfig,
    pub engine_service_token: Option<String>,
    pub login_limiter: Arc<rate_limit::RateLimiter>,
    pub api_key_limiter: Arc<rate_limit::RateLimiter>,
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
async fn login_rate_limit(
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

/// Builds the application router with all routes and middleware.
///
/// Used by both production startup and in-process integration tests.
///
/// Parameters: `state` - fully initialized application state.
/// Returns: configured Axum router.
pub fn build_router(state: AppState) -> Router {
    let login_route = Router::new()
        .route("/api/auth/login", post(routes_auth::login))
        .layer(axum_mw::from_fn_with_state(state.clone(), login_rate_limit));

    let public_routes = Router::new()
        .route("/health", get(routes_v1::health))
        .route("/api/auth/refresh", post(routes_auth::refresh))
        .merge(login_route);

    let viewer_routes = Router::new()
        .route("/api/v1/mappings", get(routes_v1::api_v1_mappings))
        .route("/api/v1/events", get(routes_v1::api_v1_events))
        .route("/api/v2/search", get(routes_search::search))
        .route(
            "/api/v2/export/mappings",
            get(routes_search::export_mappings),
        )
        .route("/api/v2/export/events", get(routes_search::export_events))
        .route(
            "/api/v2/timeline/ip/{ip}",
            get(routes_timeline::timeline_ip),
        )
        .route(
            "/api/v2/timeline/user/{user}",
            get(routes_timeline::timeline_user),
        )
        .route(
            "/api/v2/timeline/mac/{mac}",
            get(routes_timeline::timeline_mac),
        )
        .route("/api/v2/conflicts", get(routes_conflicts::list_conflicts))
        .route(
            "/api/v2/conflicts/stats",
            get(routes_conflicts::conflict_stats),
        )
        .route("/api/v2/subnets", get(routes_subnets::list_subnets))
        .route("/api/v2/subnets/stats", get(routes_subnets::subnet_stats))
        .route(
            "/api/v2/subnets/{id}/mappings",
            get(routes_subnets::subnet_mappings),
        )
        .route("/api/v2/alerts/history", get(routes_alerts::alert_history))
        .route("/api/v2/alerts/stats", get(routes_alerts::alert_stats))
        .route("/api/v1/stats", get(routes_v1::api_v1_stats))
        .route("/lookup/:ip", get(routes_v1::lookup))
        .route("/api/recent", get(routes_v1::recent))
        .route(
            "/api/v1/admin/adapters",
            get(routes_proxy::proxy_admin_adapters),
        )
        .route(
            "/api/v1/admin/agents",
            get(routes_proxy::proxy_admin_agents),
        )
        .route(
            "/api/v1/admin/runtime-config",
            get(routes_proxy::proxy_admin_runtime_config),
        )
        .route("/api/auth/me", get(routes_auth::me))
        .route("/api/auth/sessions", get(routes_auth::list_sessions))
        .route("/api/auth/logout", post(routes_auth::logout))
        .route("/api/auth/logout-all", post(routes_auth::logout_all))
        .route(
            "/api/auth/change-password",
            post(routes_auth::change_password),
        )
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::require_viewer_layer,
        ));

    let operator_routes = Router::new()
        .route("/api/v1/mappings", post(routes_proxy::proxy_post_mapping))
        .route(
            "/api/v1/mappings/{ip}",
            delete(routes_proxy::proxy_delete_mapping),
        )
        .route(
            "/api/auth/sessions/{id}",
            delete(routes_auth::revoke_session),
        )
        .route(
            "/api/v2/conflicts/{id}/resolve",
            post(routes_conflicts::resolve_conflict),
        )
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::require_operator_layer,
        ));

    let admin_routes = Router::new()
        .route(
            "/api/v1/admin/config/ttl",
            get(routes_proxy::proxy_get_ttl).put(routes_proxy::proxy_put_ttl),
        )
        .route(
            "/api/v1/admin/config/source-priority",
            get(routes_proxy::proxy_get_source_priority)
                .put(routes_proxy::proxy_put_source_priority),
        )
        .route(
            "/api/v1/admin/config/sycope",
            get(routes_proxy::proxy_get_sycope).put(routes_proxy::proxy_put_sycope),
        )
        .route(
            "/api/v1/users",
            get(routes_users::list_users).post(routes_users::create_user),
        )
        .route(
            "/api/v1/users/{id}",
            get(routes_users::get_user).delete(routes_users::delete_user),
        )
        .route("/api/v1/users/{id}/role", put(routes_users::change_role))
        .route(
            "/api/v1/users/{id}/reset-password",
            post(routes_users::reset_password),
        )
        .route(
            "/api/v1/users/{id}/unlock",
            post(routes_users::unlock_account),
        )
        .route(
            "/api/v1/api-keys",
            get(routes_api_keys::list_keys).post(routes_api_keys::create_key),
        )
        .route("/api/v1/api-keys/{id}", delete(routes_api_keys::revoke_key))
        .route(
            "/api/v2/alerts/rules",
            get(routes_alerts::list_rules).post(routes_alerts::create_rule),
        )
        .route(
            "/api/v2/alerts/rules/{id}",
            put(routes_alerts::update_rule).delete(routes_alerts::delete_rule),
        )
        .route("/api/v2/subnets", post(routes_subnets::create_subnet))
        .route(
            "/api/v2/subnets/{id}",
            put(routes_subnets::update_subnet).delete(routes_subnets::delete_subnet),
        )
        .route("/api/v1/audit-logs", get(routes_audit::list_audit_logs))
        .route("/api/v1/audit-logs/stats", get(routes_audit::audit_stats))
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::require_admin_layer,
        ));

    Router::new()
        .merge(public_routes)
        .merge(viewer_routes)
        .merge(operator_routes)
        .merge(admin_routes)
        .layer(axum_mw::from_fn(middleware::csrf_guard))
        .layer(axum_mw::from_fn(request_id_layer))
        .layer(axum_mw::from_fn(security_headers_layer))
        .with_state(state)
}
