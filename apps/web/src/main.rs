//! TrueID Web — HTTP dashboard and API gateway.
//!
//! Read-only queries go directly to SQLite.
//! Write/admin operations are proxied to engine :8080.

use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use sqlx::Row;
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use trueid_common::db::Db;
use trueid_common::model::DeviceMapping;
use trueid_common::{env_or_default, parse_socket_addr};

const DEFAULT_DB_URL: &str = "sqlite://trueid.db?mode=rwc";
const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:3000";
const DEFAULT_ASSETS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");
const DEFAULT_ENGINE_URL: &str = "http://127.0.0.1:8080";

#[derive(Clone)]
struct AppState {
    db: Arc<Db>,
    engine_url: String,
    http_client: reqwest::Client,
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
) -> Result<impl IntoResponse, StatusCode> {
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
    let pool = s.db.pool();

    // SQLx doesn't support dynamic bind count easily, so build a raw query with
    // explicit bind calls.  query_scalar needs a concrete type annotation.
    let total: i64 = {
        let mut q = sqlx::query_scalar::<_, i64>(&count_sql);
        for b in &binds { q = q.bind(b.clone()); }
        q.fetch_one(pool).await.map_err(|e| {
            warn!(error = %e, "Mappings count query failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    };

    // Execute data query.
    let rows = {
        let mut q = sqlx::query(&data_sql);
        for b in &binds { q = q.bind(b.clone()); }
        q = q.bind(per_page).bind(offset);
        q.fetch_all(pool).await.map_err(|e| {
            warn!(error = %e, "Mappings data query failed");
            StatusCode::INTERNAL_SERVER_ERROR
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
) -> Result<impl IntoResponse, StatusCode> {
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

    let pool = s.db.pool();
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
            StatusCode::INTERNAL_SERVER_ERROR
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
) -> Result<impl IntoResponse, StatusCode> {
    let mapping = s.db.get_mapping(&ip).await.map_err(|e| {
        warn!(error = %e, %ip, "Lookup failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let events = s.db.get_events_for_ip(&ip, 20).await.unwrap_or_default();
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
) -> Result<impl IntoResponse, StatusCode> {
    let limit = query.limit.unwrap_or(50).max(1);
    match s.db.get_recent_mappings(limit).await {
        Ok(mappings) => Ok(Json(mappings)),
        Err(err) => {
            warn!(error = %err, "Recent mappings query failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
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

    let db_url = env_or_default("DATABASE_URL", DEFAULT_DB_URL);
    let http_addr = parse_socket_addr(
        &env_or_default("HTTP_BIND", DEFAULT_HTTP_ADDR),
        DEFAULT_HTTP_ADDR,
    )?;
    let engine_url = env_or_default("ENGINE_API_URL", DEFAULT_ENGINE_URL);

    info!(db_url = %db_url, "Initializing database (read-only dashboard)");
    let db = Arc::new(trueid_common::db::init_db(&db_url).await?);

    let state = AppState {
        db,
        engine_url,
        http_client: reqwest::Client::new(),
    };

    let app = Router::new()
        .route("/health", get(health))
        // Legacy
        .route("/api/recent", get(recent))
        // V1 read-only (direct SQLite)
        .route("/api/v1/mappings", get(api_v1_mappings).post(proxy_post_mapping))
        .route("/api/v1/mappings/{ip}", delete(proxy_delete_mapping))
        .route("/api/v1/events", get(api_v1_events))
        .route("/api/v1/stats", get(api_v1_stats))
        .route("/lookup/{ip}", get(lookup))
        // Admin proxies
        .route("/api/v1/admin/adapters", get(proxy_admin_adapters))
        .route("/api/v1/admin/agents", get(proxy_admin_agents))
        .route("/api/v1/admin/runtime-config", get(proxy_admin_runtime_config))
        .route("/api/v1/admin/config/ttl", get(proxy_get_ttl).put(proxy_put_ttl))
        .route("/api/v1/admin/config/source-priority", get(proxy_get_source_priority).put(proxy_put_source_priority))
        .route("/api/v1/admin/config/sycope", get(proxy_get_sycope).put(proxy_put_sycope))
        .with_state(state)
        .fallback_service(ServeDir::new(env_or_default("ASSETS_DIR", DEFAULT_ASSETS_DIR)));

    info!(%http_addr, "Starting HTTP server");
    let listener = tokio::net::TcpListener::bind(http_addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async { tokio::signal::ctrl_c().await.ok(); })
        .await?;

    info!("Web server stopped");
    Ok(())
}
