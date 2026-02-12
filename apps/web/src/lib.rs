//! TrueID Web library — router, handlers, and shared app state.
//!
//! The binary crate (`main.rs`) handles startup and server binding.

pub mod auth;
pub mod error;
pub mod middleware;
pub mod rate_limit;
pub mod routes_api_keys;
pub mod routes_alerts;
pub mod routes_audit;
pub mod routes_auth;
pub mod routes_conflicts;
pub mod routes_search;
pub mod routes_timeline;
pub mod routes_users;

use anyhow::Result;
use axum::{
    extract::{Path, Query, Request, State},
    http::StatusCode,
    middleware as axum_mw,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::Arc;
use tracing::warn;
use trueid_common::db::Db;
use trueid_common::model::DeviceMapping;

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
async fn login_rate_limit(State(state): State<AppState>, req: Request, next: axum_mw::Next) -> Response {
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
    h.insert("x-frame-options", axum::http::HeaderValue::from_static("DENY"));
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

/// Extracts the DB handle from state or returns a 503 JSON response.
fn require_db(state: &AppState) -> Result<&Arc<Db>, (StatusCode, Json<serde_json::Value>)> {
    state.db.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Database unavailable",
                "hint": "Run 'cargo run -p trueid-engine' to initialize the database, then restart the web server.",
                "docs": "See README.md for setup instructions."
            })),
        )
    })
}

/// Proxies a request to the engine admin API, returning its response verbatim.
async fn proxy_to_engine(
    state: &AppState,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    let url = format!("{}{}", state.engine_url, path);
    let mut req = state.http_client.request(method, &url);
    if let Some(ref token) = state.engine_service_token {
        req = req.header("X-Service-Token", token);
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await.map_err(|e| {
        warn!(error = %e, url = %url, "Engine proxy request failed");
        StatusCode::BAD_GATEWAY
    })?;
    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let json_body = resp
        .json::<serde_json::Value>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok((status, Json(json_body)))
}

/// Health endpoint.
async fn health() -> StatusCode {
    StatusCode::OK
}

/// Proxies stats endpoint to engine.
async fn api_v1_stats(State(s): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/status/stats", None).await
}

/// Query params for mappings list.
#[derive(Deserialize)]
struct MappingsQuery {
    source: Option<String>,
    search: Option<String>,
    active: Option<bool>,
    page: Option<i64>,
    per_page: Option<i64>,
    sort: Option<String>,
    order: Option<String>,
}

/// Paginated mappings response.
#[derive(Serialize)]
struct PaginatedMappings {
    data: Vec<DeviceMapping>,
    total: i64,
    page: i64,
    per_page: i64,
}

/// Lists mappings with filters and pagination.
async fn api_v1_mappings(
    Query(q): Query<MappingsQuery>,
    State(s): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let db = require_db(&s)?;
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * per_page;

    let sort_col = match q.sort.as_deref() {
        Some("ip") => "ip",
        Some("user") => "user",
        Some("confidence") => "confidence",
        Some("source") => "source",
        _ => "last_seen",
    };
    let order = if q.order.as_deref() == Some("asc") {
        "ASC"
    } else {
        "DESC"
    };

    let mut conditions = Vec::new();
    let mut binds: Vec<String> = Vec::new();

    if let Some(ref src) = q.source {
        conditions.push("source = ?");
        binds.push(src.clone());
    }
    if let Some(active) = q.active {
        if active {
            conditions.push("is_active = true");
        } else {
            conditions.push("is_active = false");
        }
    }
    if let Some(ref search) = q.search {
        conditions.push("(ip LIKE ? OR user LIKE ? OR mac LIKE ? OR vendor LIKE ?)");
        let like = format!("%{}%", search);
        binds.push(like.clone());
        binds.push(like.clone());
        binds.push(like.clone());
        binds.push(like);
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) as c FROM mappings {}", where_clause);
    let data_sql = format!(
        "SELECT ip, user, source, last_seen, confidence, mac, is_active, vendor \
         FROM mappings {} ORDER BY {} {} LIMIT ? OFFSET ?",
        where_clause, sort_col, order,
    );

    let pool = db.pool();

    let total: i64 = {
        let mut q = sqlx::query_scalar::<_, i64>(&count_sql);
        for b in &binds {
            q = q.bind(b.clone());
        }
        q.fetch_one(pool).await.map_err(|e| {
            warn!(error = %e, "Mappings count query failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "query failed"})),
            )
        })?
    };

    let rows = {
        let mut q = sqlx::query(&data_sql);
        for b in &binds {
            q = q.bind(b.clone());
        }
        q = q.bind(per_page).bind(offset);
        q.fetch_all(pool).await.map_err(|e| {
            warn!(error = %e, "Mappings data query failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "query failed"})),
            )
        })?
    };

    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        let ip: String = row.try_get("ip").unwrap_or_default();
        let user: String = row.try_get("user").unwrap_or_default();
        let source_str: String = row.try_get("source").unwrap_or_default();
        let mac: Option<String> = row.try_get("mac").ok();
        let last_seen = row.try_get("last_seen").unwrap_or_else(|_| Utc::now());
        let confidence: i64 = row.try_get("confidence").unwrap_or(0);
        let is_active: bool = row.try_get("is_active").unwrap_or(false);
        let vendor: Option<String> = row.try_get("vendor").ok();

        data.push(DeviceMapping {
            ip,
            mac,
            current_users: vec![user],
            last_seen,
            source: trueid_common::model::source_from_str(&source_str),
            confidence_score: u8::try_from(confidence).unwrap_or(0),
            is_active,
            vendor,
        });
    }

    Ok(Json(PaginatedMappings {
        data,
        total,
        page,
        per_page,
    }))
}

/// Query params for events list.
#[derive(Deserialize)]
struct EventsQuery {
    source: Option<String>,
    ip: Option<String>,
    user: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
    limit: Option<i64>,
}

/// Lists events with filters.
async fn api_v1_events(
    Query(q): Query<EventsQuery>,
    State(s): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let db = require_db(&s)?;
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let since_dt = q
        .since
        .and_then(|ts| Utc.timestamp_opt(ts, 0).single())
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap());

    let mut conditions = vec!["timestamp > ?".to_string()];
    let mut str_binds: Vec<String> = Vec::new();

    if let Some(ref src) = q.source {
        conditions.push("source = ?".into());
        str_binds.push(src.clone());
    }
    if let Some(ref ip) = q.ip {
        conditions.push("ip = ?".into());
        str_binds.push(ip.clone());
    }
    if let Some(ref user) = q.user {
        conditions.push("user = ?".into());
        str_binds.push(user.clone());
    }

    let q_until = q.until;
    if q_until.is_some() {
        conditions.push("timestamp < ?".into());
    }

    let where_clause = format!("WHERE {}", conditions.join(" AND "));
    let sql = format!(
        "SELECT id, ip, user, source, timestamp, raw_data FROM events {} ORDER BY timestamp DESC LIMIT ?",
        where_clause,
    );

    let pool = db.pool();
    let rows = {
        let mut q = sqlx::query(&sql).bind(since_dt);
        for b in &str_binds {
            q = q.bind(b.clone());
        }
        if let Some(until_ts) = q_until {
            let until_dt = Utc.timestamp_opt(until_ts, 0).single().unwrap_or_else(Utc::now);
            q = q.bind(until_dt);
        }
        q = q.bind(limit);
        q.fetch_all(pool).await.map_err(|e| {
            warn!(error = %e, "Events query failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "query failed"})),
            )
        })?
    };

    let mut results = Vec::with_capacity(rows.len());
    for r in rows {
        results.push(trueid_common::model::StoredEvent {
            id: r.try_get("id").unwrap_or(0),
            ip: r.try_get("ip").unwrap_or_default(),
            user: r.try_get("user").unwrap_or_default(),
            source: r.try_get("source").unwrap_or_default(),
            timestamp: r.try_get("timestamp").unwrap_or_else(|_| Utc::now()),
            raw_data: r.try_get("raw_data").unwrap_or_default(),
        });
    }

    Ok(Json(results))
}

/// Lookup endpoint response.
#[derive(Serialize)]
struct LookupDetailResponse {
    mapping: Option<DeviceMapping>,
    recent_events: Vec<trueid_common::model::StoredEvent>,
}

/// Returns mapping and recent events for IP.
async fn lookup(
    Path(ip): Path<String>,
    State(s): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let db = require_db(&s)?;
    let mapping = db.get_mapping(&ip).await.map_err(|e| {
        warn!(error = %e, %ip, "Lookup failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "query failed"})),
        )
    })?;
    let events = db.get_events_for_ip(&ip, 20).await.unwrap_or_default();
    Ok(Json(LookupDetailResponse {
        mapping,
        recent_events: events,
    }))
}

/// Query params for recent mappings endpoint.
#[derive(Deserialize)]
struct RecentQuery {
    limit: Option<i64>,
}

/// Returns most recent mappings.
async fn recent(
    Query(query): Query<RecentQuery>,
    State(s): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let db = require_db(&s)?;
    let limit = query.limit.unwrap_or(50).max(1);
    match db.get_recent_mappings(limit).await {
        Ok(mappings) => Ok(Json(mappings)),
        Err(err) => {
            warn!(error = %err, "Recent mappings query failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "query failed"})),
            ))
        }
    }
}

/// Proxies adapters status.
async fn proxy_admin_adapters(State(s): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/status/adapters", None).await
}

/// Proxies agents status.
async fn proxy_admin_agents(State(s): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/status/agents", None).await
}

/// Proxies runtime config status.
async fn proxy_admin_runtime_config(
    State(s): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/status/runtime-config", None).await
}

/// Proxies TTL config read.
async fn proxy_get_ttl(State(s): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/config/ttl", None).await
}

/// Proxies TTL config update.
async fn proxy_put_ttl(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::PUT, "/engine/config/ttl", Some(body)).await
}

/// Proxies source-priority config read.
async fn proxy_get_source_priority(
    State(s): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(
        &s,
        reqwest::Method::GET,
        "/engine/config/source-priority",
        None,
    )
    .await
}

/// Proxies source-priority config update.
async fn proxy_put_source_priority(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(
        &s,
        reqwest::Method::PUT,
        "/engine/config/source-priority",
        Some(body),
    )
    .await
}

/// Proxies Sycope config read.
async fn proxy_get_sycope(State(s): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/config/sycope", None).await
}

/// Proxies Sycope config update.
async fn proxy_put_sycope(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::PUT, "/engine/config/sycope", Some(body)).await
}

/// Proxies mapping create.
async fn proxy_post_mapping(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::POST, "/engine/mappings", Some(body)).await
}

/// Proxies mapping delete.
async fn proxy_delete_mapping(
    State(s): State<AppState>,
    Path(ip): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(
        &s,
        reqwest::Method::DELETE,
        &format!("/engine/mappings/{}", ip),
        None,
    )
    .await
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
        .route("/health", get(health))
        .route("/api/auth/refresh", post(routes_auth::refresh))
        .merge(login_route);

    let viewer_routes = Router::new()
        .route("/api/v1/mappings", get(api_v1_mappings))
        .route("/api/v1/events", get(api_v1_events))
        .route("/api/v2/search", get(routes_search::search))
        .route("/api/v2/export/mappings", get(routes_search::export_mappings))
        .route("/api/v2/export/events", get(routes_search::export_events))
        .route("/api/v2/timeline/ip/{ip}", get(routes_timeline::timeline_ip))
        .route("/api/v2/timeline/user/{user}", get(routes_timeline::timeline_user))
        .route("/api/v2/timeline/mac/{mac}", get(routes_timeline::timeline_mac))
        .route("/api/v2/conflicts", get(routes_conflicts::list_conflicts))
        .route("/api/v2/conflicts/stats", get(routes_conflicts::conflict_stats))
        .route("/api/v2/alerts/history", get(routes_alerts::alert_history))
        .route("/api/v2/alerts/stats", get(routes_alerts::alert_stats))
        .route("/api/v1/stats", get(api_v1_stats))
        .route("/lookup/*ip", get(lookup))
        .route("/lookup/{ip}", get(lookup))
        .route("/api/recent", get(recent))
        .route("/api/v1/admin/adapters", get(proxy_admin_adapters))
        .route("/api/v1/admin/agents", get(proxy_admin_agents))
        .route(
            "/api/v1/admin/runtime-config",
            get(proxy_admin_runtime_config),
        )
        .route("/api/auth/me", get(routes_auth::me))
        .route("/api/auth/sessions", get(routes_auth::list_sessions))
        .route("/api/auth/logout", post(routes_auth::logout))
        .route("/api/auth/logout-all", post(routes_auth::logout_all))
        .route("/api/auth/change-password", post(routes_auth::change_password))
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::require_viewer_layer,
        ));

    let operator_routes = Router::new()
        .route("/api/v1/mappings", post(proxy_post_mapping))
        .route("/api/v1/mappings/{ip}", delete(proxy_delete_mapping))
        .route("/api/auth/sessions/{id}", delete(routes_auth::revoke_session))
        .route(
            "/api/v2/conflicts/{id}/resolve",
            post(routes_conflicts::resolve_conflict),
        )
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::require_operator_layer,
        ));

    let admin_routes = Router::new()
        .route("/api/v1/admin/config/ttl", get(proxy_get_ttl).put(proxy_put_ttl))
        .route(
            "/api/v1/admin/config/source-priority",
            get(proxy_get_source_priority).put(proxy_put_source_priority),
        )
        .route(
            "/api/v1/admin/config/sycope",
            get(proxy_get_sycope).put(proxy_put_sycope),
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
        .route("/api/v1/users/{id}/unlock", post(routes_users::unlock_account))
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
