//! TrueID Web — HTTP dashboard and API gateway.
//!
//! Read-only queries go directly to SQLite.
//! Write/admin operations are proxied to engine :8080.

mod auth;
mod error;
pub mod middleware;
pub mod rate_limit;
mod routes_api_keys;
mod routes_audit;
mod routes_auth;
mod routes_conflicts;
mod routes_search;
mod routes_users;

use anyhow::Result;
use axum::{
    extract::{Path, Query, Request, State},
    http::StatusCode,
    middleware as axum_mw,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use sqlx::Row;
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use trueid_common::db::Db;
use trueid_common::model::{DeviceMapping, UserRole};
use trueid_common::{env_or_default, parse_socket_addr};

use crate::auth::JwtConfig;

const DEFAULT_DB_URL: &str = "sqlite://net-identity.db?mode=rwc";
const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:3000";
const DEFAULT_ASSETS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");
const DEFAULT_ENGINE_URL: &str = "http://127.0.0.1:8080";

/// Per-request ID stored in extensions.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

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
async fn request_id_layer(
    mut req: Request,
    next: axum_mw::Next,
) -> Response {
    let rid = uuid::Uuid::new_v4().to_string();
    req.extensions_mut().insert(RequestId(rid.clone()));
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        "x-request-id",
        axum::http::HeaderValue::from_str(&rid).unwrap_or_else(|_| {
            axum::http::HeaderValue::from_static("unknown")
        }),
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
        resp.headers_mut().insert(
            "retry-after",
            axum::http::HeaderValue::from_static("60"),
        );
        return resp;
    }
    next.run(req).await
}

/// Middleware that adds security headers to every response.
///
/// Sets CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
/// and Permissions-Policy on all outgoing responses.
async fn security_headers_layer(
    req: Request,
    next: axum_mw::Next,
) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    // TODO: migrate to nonce-based CSP when dashboard moves to external JS files
    h.insert(
        "content-security-policy",
        axum::http::HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; \
             style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
             connect-src 'self'; frame-ancestors 'none'"
        ),
    );
    h.insert("x-frame-options", axum::http::HeaderValue::from_static("DENY"));
    h.insert("x-content-type-options", axum::http::HeaderValue::from_static("nosniff"));
    h.insert("referrer-policy", axum::http::HeaderValue::from_static("no-referrer"));
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

// ── Proxy helper ────────────────────────────────────────────

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
    let status = StatusCode::from_u16(resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let json_body = resp.json::<serde_json::Value>().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok((status, Json(json_body)))
}

// ── Health ──────────────────────────────────────────────────

async fn health() -> StatusCode {
    StatusCode::OK
}

// ── W1: Stats (proxy to engine) ─────────────────────────────

async fn api_v1_stats(State(s): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/status/stats", None).await
}

// ── W2: Mappings (extended with filters + pagination) ───────

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

#[derive(Serialize)]
struct PaginatedMappings {
    data: Vec<DeviceMapping>,
    total: i64,
    page: i64,
    per_page: i64,
}

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
    let order = if q.order.as_deref() == Some("asc") { "ASC" } else { "DESC" };

    // Build WHERE clauses dynamically (safe — only literals injected are from match above).
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

    // Execute count query.
    let pool = db.pool();

    // SQLx doesn't support dynamic bind count easily, so build a raw query with
    // explicit bind calls.  query_scalar needs a concrete type annotation.
    let total: i64 = {
        let mut q = sqlx::query_scalar::<_, i64>(&count_sql);
        for b in &binds { q = q.bind(b.clone()); }
        q.fetch_one(pool).await.map_err(|e| {
            warn!(error = %e, "Mappings count query failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "query failed"})))
        })?
    };

    // Execute data query.
    let rows = {
        let mut q = sqlx::query(&data_sql);
        for b in &binds { q = q.bind(b.clone()); }
        q = q.bind(per_page).bind(offset);
        q.fetch_all(pool).await.map_err(|e| {
            warn!(error = %e, "Mappings data query failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "query failed"})))
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

    Ok(Json(PaginatedMappings { data, total, page, per_page }))
}

// ── W3: Events (extended with filters) ──────────────────────

#[derive(Deserialize)]
struct EventsQuery {
    source: Option<String>,
    ip: Option<String>,
    user: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
    limit: Option<i64>,
}

async fn api_v1_events(
    Query(q): Query<EventsQuery>,
    State(s): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let db = require_db(&s)?;
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let since_dt = q.since
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
        for b in &str_binds { q = q.bind(b.clone()); }
        if let Some(until_ts) = q_until {
            let until_dt = Utc.timestamp_opt(until_ts, 0).single().unwrap_or_else(Utc::now);
            q = q.bind(until_dt);
        }
        q = q.bind(limit);
        q.fetch_all(pool).await.map_err(|e| {
            warn!(error = %e, "Events query failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "query failed"})))
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

// ── W4: Lookup detail (mapping + recent events) ─────────────

#[derive(Serialize)]
struct LookupDetailResponse {
    mapping: Option<DeviceMapping>,
    recent_events: Vec<trueid_common::model::StoredEvent>,
}

async fn lookup(
    Path(ip): Path<String>,
    State(s): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let db = require_db(&s)?;
    let mapping = db.get_mapping(&ip).await.map_err(|e| {
        warn!(error = %e, %ip, "Lookup failed");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "query failed"})))
    })?;
    let events = db.get_events_for_ip(&ip, 20).await.unwrap_or_default();
    Ok(Json(LookupDetailResponse { mapping, recent_events: events }))
}

// ── Legacy /api/recent (unchanged) ──────────────────────────

#[derive(Deserialize)]
struct RecentQuery {
    limit: Option<i64>,
}

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
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "query failed"}))))
        }
    }
}

// ── W5–W12: Proxy routes to engine ─────────────────────────

async fn proxy_admin_adapters(State(s): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/status/adapters", None).await
}

async fn proxy_admin_agents(State(s): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/status/agents", None).await
}

async fn proxy_admin_runtime_config(State(s): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/status/runtime-config", None).await
}

async fn proxy_get_ttl(State(s): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/config/ttl", None).await
}

async fn proxy_put_ttl(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::PUT, "/engine/config/ttl", Some(body)).await
}

async fn proxy_get_source_priority(State(s): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/config/source-priority", None).await
}

async fn proxy_put_source_priority(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::PUT, "/engine/config/source-priority", Some(body)).await
}

async fn proxy_get_sycope(State(s): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/config/sycope", None).await
}

async fn proxy_put_sycope(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::PUT, "/engine/config/sycope", Some(body)).await
}

async fn proxy_post_mapping(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::POST, "/engine/mappings", Some(body)).await
}

async fn proxy_delete_mapping(
    State(s): State<AppState>,
    Path(ip): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::DELETE, &format!("/engine/mappings/{}", ip), None).await
}

// ── Main ────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    // ── Production startup validation ──────────────────────
    let dev_mode = std::env::var("TRUEID_DEV_MODE")
        .map(|v| v == "true")
        .unwrap_or(false);

    if dev_mode {
        warn!("DEV MODE ENABLED — relaxed security. Do NOT use in production.");
    } else {
        let jwt = std::env::var("JWT_SECRET").unwrap_or_default();
        if jwt.len() < 32 {
            error!("FATAL: JWT_SECRET must be set and at least 32 chars in production. Set TRUEID_DEV_MODE=true to bypass.");
            std::process::exit(1);
        }
        let est = std::env::var("ENGINE_SERVICE_TOKEN").unwrap_or_default();
        if est.len() < 32 {
            error!("FATAL: ENGINE_SERVICE_TOKEN must be set and at least 32 chars in production. Set TRUEID_DEV_MODE=true to bypass.");
            std::process::exit(1);
        }
        let cek = std::env::var("CONFIG_ENCRYPTION_KEY").unwrap_or_default();
        if cek.len() != 64 || !cek.chars().all(|c| c.is_ascii_hexdigit()) {
            error!("FATAL: CONFIG_ENCRYPTION_KEY must be 64 hex chars (32 bytes) in production. Set TRUEID_DEV_MODE=true to bypass.");
            std::process::exit(1);
        }
        info!("Production mode: all required secrets verified.");
    }

    let db_url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => {
            warn!("DATABASE_URL not set — using default: {}", DEFAULT_DB_URL);
            DEFAULT_DB_URL.to_string()
        }
    };
    let http_addr = parse_socket_addr(
        &env_or_default("HTTP_BIND", DEFAULT_HTTP_ADDR),
        DEFAULT_HTTP_ADDR,
    )?;
    let engine_url = env_or_default("ENGINE_API_URL", DEFAULT_ENGINE_URL);

    info!(db_url = %db_url, "Initializing database (read-only dashboard)");
    let db = match trueid_common::db::init_db(&db_url).await {
        Ok(d) => {
            info!("Database connected successfully");

            // ── Admin bootstrap ──────────────────────────────
            match d.count_users().await {
                Ok(0) => {
                    let admin_user = std::env::var("TRUEID_ADMIN_USER").unwrap_or_default();
                    let admin_pass = std::env::var("TRUEID_ADMIN_PASS").unwrap_or_default();
                    if !admin_user.is_empty() && !admin_pass.is_empty() {
                        if admin_pass.len() < 12 {
                            error!("FATAL: TRUEID_ADMIN_PASS must be at least 12 characters.");
                            std::process::exit(1);
                        }
                        match d.create_user(&admin_user, &admin_pass, UserRole::Admin).await {
                            Ok(user) => {
                                let _ = d.set_force_password_change(user.id, true).await;
                                let _ = d.write_audit_log(
                                    Some(user.id), &admin_user, "system",
                                    "bootstrap_admin_created", None, None, None, None,
                                ).await;
                                info!(
                                    "Bootstrap: Created initial admin user '{}'. Password change required on first login.",
                                    admin_user
                                );
                            }
                            Err(e) => {
                                error!("Failed to create bootstrap admin: {e:#}");
                            }
                        }
                    } else {
                        warn!(
                            "No users in database and TRUEID_ADMIN_USER/TRUEID_ADMIN_PASS not set. \
                             Authentication will be non-functional until an admin is bootstrapped."
                        );
                    }
                }
                Ok(_) => { /* normal startup, users already exist */ }
                Err(e) => warn!("Could not count users during bootstrap: {e:#}"),
            }

            Some(Arc::new(d))
        }
        Err(e) => {
            error!(
                "Database connection failed: {e:#}\n\
                 -> Check DATABASE_URL in .env\n\
                 -> Run 'cargo run -p trueid-engine' first to create tables\n\
                 -> Server will start but API will return 503"
            );
            None
        }
    };

    // ── Background: session cleanup every hour ─────────────
    if let Some(ref db_ref) = db {
        let cleanup_db = Arc::clone(db_ref);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                match cleanup_db.cleanup_expired_sessions().await {
                    Ok(n) if n > 0 => info!(deleted = n, "Cleaned up expired sessions"),
                    Ok(_) => {}
                    Err(e) => warn!(error = %e, "Session cleanup failed"),
                }
            }
        });
    }

    let jwt_config = JwtConfig::from_env(dev_mode);

    let engine_service_token = std::env::var("ENGINE_SERVICE_TOKEN").ok().filter(|s| !s.is_empty());
    let login_limiter = Arc::new(rate_limit::RateLimiter::new(10, 60));
    let api_key_limiter = Arc::new(rate_limit::RateLimiter::new(100, 60));

    let auth_chain = db.as_ref().map(|d| {
        Arc::new(trueid_common::auth_provider::AuthProviderChain::default_chain(
            Arc::clone(d),
        ))
    });

    let state = AppState {
        db,
        engine_url,
        http_client: reqwest::Client::new(),
        jwt_config,
        engine_service_token,
        login_limiter: login_limiter.clone(),
        api_key_limiter: api_key_limiter.clone(),
        auth_chain,
    };

    // ── Background: rate limiter cleanup every 5 min ─────
    {
        let ll = login_limiter;
        let al = api_key_limiter;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                ll.cleanup();
                al.cleanup();
            }
        });
    }

    // ── Public routes — no auth required ───────────────────
    let login_route = Router::new()
        .route("/api/auth/login", post(routes_auth::login))
        .layer(axum_mw::from_fn_with_state(state.clone(), login_rate_limit));

    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/api/auth/refresh", post(routes_auth::refresh))
        .merge(login_route);

    // ── Viewer+ routes — any authenticated user ──────────
    let viewer_routes = Router::new()
        .route("/api/v1/mappings", get(api_v1_mappings))
        .route("/api/v1/events", get(api_v1_events))
        .route("/api/v2/search", get(routes_search::search))
        .route("/api/v2/export/mappings", get(routes_search::export_mappings))
        .route("/api/v2/export/events", get(routes_search::export_events))
        .route("/api/v2/conflicts", get(routes_conflicts::list_conflicts))
        .route("/api/v2/conflicts/stats", get(routes_conflicts::conflict_stats))
        .route("/api/v1/stats", get(api_v1_stats))
        .route("/lookup/{ip}", get(lookup))
        .route("/api/recent", get(recent))
        .route("/api/v1/admin/adapters", get(proxy_admin_adapters))
        .route("/api/v1/admin/agents", get(proxy_admin_agents))
        .route("/api/v1/admin/runtime-config", get(proxy_admin_runtime_config))
        .route("/api/auth/me", get(routes_auth::me))
        .route("/api/auth/sessions", get(routes_auth::list_sessions))
        .route("/api/auth/logout", post(routes_auth::logout))
        .route("/api/auth/logout-all", post(routes_auth::logout_all))
        .route("/api/auth/change-password", post(routes_auth::change_password))
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::require_viewer_layer,
        ));

    // ── Operator+ routes — Admin or Operator ─────────────
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

    // ── Admin routes — Admin only ────────────────────────
    let admin_routes = Router::new()
        .route("/api/v1/admin/config/ttl", get(proxy_get_ttl).put(proxy_put_ttl))
        .route("/api/v1/admin/config/source-priority", get(proxy_get_source_priority).put(proxy_put_source_priority))
        .route("/api/v1/admin/config/sycope", get(proxy_get_sycope).put(proxy_put_sycope))
        // User management
        .route("/api/v1/users", get(routes_users::list_users).post(routes_users::create_user))
        .route("/api/v1/users/{id}", get(routes_users::get_user).delete(routes_users::delete_user))
        .route("/api/v1/users/{id}/role", put(routes_users::change_role))
        .route("/api/v1/users/{id}/reset-password", post(routes_users::reset_password))
        .route("/api/v1/users/{id}/unlock", post(routes_users::unlock_account))
        // API key management
        .route("/api/v1/api-keys", get(routes_api_keys::list_keys).post(routes_api_keys::create_key))
        .route("/api/v1/api-keys/{id}", delete(routes_api_keys::revoke_key))
        // Audit logs (read-only, append-only — no DELETE/UPDATE by design)
        .route("/api/v1/audit-logs", get(routes_audit::list_audit_logs))
        .route("/api/v1/audit-logs/stats", get(routes_audit::audit_stats))
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::require_admin_layer,
        ));

    // ── Merge all routers ────────────────────────────────
    let app = Router::new()
        .merge(public_routes)
        .merge(viewer_routes)
        .merge(operator_routes)
        .merge(admin_routes)
        .layer(axum_mw::from_fn(middleware::csrf_guard))
        .layer(axum_mw::from_fn(request_id_layer))
        .layer(axum_mw::from_fn(security_headers_layer))
        .with_state(state)
        .fallback_service(ServeDir::new(env_or_default("ASSETS_DIR", DEFAULT_ASSETS_DIR)));

    // ── TLS or plain TCP ──────────────────────────────────
    let tls_cert = std::env::var("TLS_CERT").ok().filter(|s| !s.is_empty());
    let tls_key = std::env::var("TLS_KEY").ok().filter(|s| !s.is_empty());

    match (tls_cert, tls_key) {
        (Some(cert_path), Some(key_path)) => {
            info!(%http_addr, cert = %cert_path, "Starting HTTPS server (native TLS)");
            let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                .await
                .map_err(|e| anyhow::anyhow!("TLS config error: {e}"))?;
            axum_server::bind_rustls(http_addr, tls_config)
                .serve(app.into_make_service())
                .await?;
        }
        _ => {
            if !dev_mode {
                warn!("TLS_CERT/TLS_KEY not set — serving plain HTTP. Use a reverse proxy with TLS in production.");
            }
            info!(%http_addr, "Starting HTTP server");
            let listener = tokio::net::TcpListener::bind(http_addr).await?;
            axum::serve(listener, app)
                .with_graceful_shutdown(async { tokio::signal::ctrl_c().await.ok(); })
                .await?;
        }
    }

    info!("Web server stopped");
    Ok(())
}
