//! Legacy v1 and lookup handlers used by dashboard and regressions.

use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::Arc;
use tracing::warn;
use trueid_common::db::Db;
use trueid_common::model::DeviceMapping;

use crate::routes_proxy::proxy_to_engine;
use crate::AppState;

/// Extracts the DB handle from state or returns a 503 JSON response.
///
/// Parameters: `state` - shared app state.
/// Returns: database handle or HTTP error tuple when DB is unavailable.
pub(crate) fn require_db(
    state: &AppState,
) -> Result<&Arc<Db>, (StatusCode, Json<serde_json::Value>)> {
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

/// Health endpoint.
///
/// Parameters: none.
/// Returns: HTTP 200 status code.
pub(crate) async fn health() -> StatusCode {
    StatusCode::OK
}

/// Proxies v1 stats endpoint to engine.
///
/// Parameters: `s` - shared app state.
/// Returns: proxied stats response.
pub(crate) async fn api_v1_stats(
    State(s): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/status/stats", None).await
}

/// Query params for mappings list.
#[derive(Deserialize)]
pub(crate) struct MappingsQuery {
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
pub(crate) struct PaginatedMappings {
    data: Vec<DeviceMapping>,
    total: i64,
    page: i64,
    per_page: i64,
}

/// Lists mappings with filters and pagination.
///
/// Parameters: `q` - filter and pagination query, `s` - shared app state.
/// Returns: paginated mappings payload or structured HTTP error.
pub(crate) async fn api_v1_mappings(
    Query(q): Query<MappingsQuery>,
    State(s): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let db = require_db(&s)?;
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * per_page;

    let sort_col = match q.sort.as_deref() {
        Some("ip") => "m.ip",
        Some("user") => "m.user",
        Some("confidence") => "m.confidence",
        Some("source") => "m.source",
        _ => "m.last_seen",
    };
    let order = if q.order.as_deref() == Some("asc") {
        "ASC"
    } else {
        "DESC"
    };

    let mut conditions = Vec::new();
    let mut binds: Vec<String> = Vec::new();

    if let Some(ref src) = q.source {
        conditions.push("m.source = ?");
        binds.push(src.clone());
    }
    if let Some(active) = q.active {
        if active {
            conditions.push("m.is_active = true");
        } else {
            conditions.push("m.is_active = false");
        }
    }
    if let Some(ref search) = q.search {
        conditions.push("(m.ip LIKE ? OR m.user LIKE ? OR m.mac LIKE ? OR m.vendor LIKE ?)");
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

    let count_sql = format!("SELECT COUNT(*) as c FROM mappings m {}", where_clause);
    let data_sql = format!(
        "SELECT m.ip, m.user, m.source, m.last_seen, m.confidence, m.mac, m.is_active, m.vendor,
                m.subnet_id, s.name as subnet_name, d.hostname, m.device_type
         FROM mappings m
         LEFT JOIN subnets s ON m.subnet_id = s.id
         LEFT JOIN dns_cache d ON m.ip = d.ip
         {} ORDER BY {} {} LIMIT ? OFFSET ?",
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
        let mapping = DeviceMapping::from_row(&row).map_err(|e| {
            warn!(error = %e, "Mappings row decode failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "query failed"})),
            )
        })?;
        data.push(mapping);
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
pub(crate) struct EventsQuery {
    source: Option<String>,
    ip: Option<String>,
    user: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
    limit: Option<i64>,
}

/// Lists events with filters.
///
/// Parameters: `q` - filter query, `s` - shared app state.
/// Returns: event array or structured HTTP error.
pub(crate) async fn api_v1_events(
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
            let until_dt = Utc
                .timestamp_opt(until_ts, 0)
                .single()
                .unwrap_or_else(Utc::now);
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
pub(crate) struct LookupDetailResponse {
    mapping: Option<DeviceMapping>,
    recent_events: Vec<trueid_common::model::StoredEvent>,
}

/// Returns mapping and recent events for an IP.
///
/// Parameters: `ip` - lookup key, `s` - shared app state.
/// Returns: mapping details and recent events.
pub(crate) async fn lookup(
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
pub(crate) struct RecentQuery {
    limit: Option<i64>,
}

/// Returns most recent mappings.
///
/// Parameters: `query` - optional result limit, `s` - shared app state.
/// Returns: recent mapping list or structured HTTP error.
pub(crate) async fn recent(
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
