//! Unified v2 search and export endpoints.

use axum::{
    extract::{Query, State},
    http::{
        header::{CONTENT_DISPOSITION, CONTENT_TYPE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::time::Instant;
use tracing::warn;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;
use trueid_common::db::MAPPING_SELECT;
use trueid_common::model::{DeviceMapping, StoredEvent};
use trueid_common::pagination::PaginationParams;

const DEFAULT_PAGE: u32 = 1;
const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 200;
const EXPORT_EVENTS_MAX_ROWS: i64 = 100_000;

/// Raw bind parameter for dynamic SQL queries.
#[derive(Debug, Clone)]
enum BindParam {
    Text(String),
    DateTime(DateTime<Utc>),
    I64(i64),
}

/// Scope selector for unified search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchScope {
    All,
    Mappings,
    Events,
}

/// Query parameters for unified search endpoint.
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
    pub ip: Option<String>,
    pub user: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub source: Option<String>,
    pub active: Option<bool>,
    #[serde(rename = "from")]
    pub from_ts: Option<String>,
    #[serde(rename = "to")]
    pub to_ts: Option<String>,
    pub scope: Option<String>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub sort: Option<String>,
    pub order: Option<String>,
}

/// Query parameters for mappings export.
#[derive(Debug, Deserialize)]
pub struct ExportMappingsQuery {
    pub format: Option<String>,
    pub ip: Option<String>,
    pub user: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub source: Option<String>,
    pub active: Option<bool>,
    #[serde(rename = "from")]
    pub from_ts: Option<String>,
    #[serde(rename = "to")]
    pub to_ts: Option<String>,
}

/// Query parameters for events export.
#[derive(Debug, Deserialize)]
pub struct ExportEventsQuery {
    pub format: Option<String>,
    pub ip: Option<String>,
    pub user: Option<String>,
    pub source: Option<String>,
    #[serde(rename = "from")]
    pub from_ts: Option<String>,
    #[serde(rename = "to")]
    pub to_ts: Option<String>,
}

/// Paginated section for a single entity type.
#[derive(Debug, Serialize)]
struct SearchSection<T> {
    data: Vec<T>,
    total: i64,
}

/// Response model for `/api/v2/search`.
#[derive(Debug, Serialize)]
struct SearchResponse {
    mappings: Option<SearchSection<DeviceMapping>>,
    events: Option<SearchSection<StoredEvent>>,
    page: u32,
    limit: u32,
    query_time_ms: u128,
}

/// Parses RFC3339 or naive datetime string into UTC timestamp.
///
/// Parameters: `raw` - datetime string from query parameter.
/// Returns: parsed timestamp or `None` when unsupported format.
fn parse_datetime(raw: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S") {
        return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S") {
        return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
    }
    None
}

/// Parses optional datetime query parameter and returns API error on invalid value.
///
/// Parameters: `raw` - optional raw query value, `field_name` - parameter name,
/// `request_id` - request identifier for consistent API errors.
/// Returns: parsed optional UTC datetime.
fn parse_datetime_param(
    raw: &Option<String>,
    field_name: &str,
    request_id: &str,
) -> Result<Option<DateTime<Utc>>, ApiError> {
    match raw {
        Some(value) => parse_datetime(value).map(Some).ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                &format!("Invalid datetime for '{field_name}'"),
            )
            .with_request_id(request_id)
        }),
        None => Ok(None),
    }
}

/// Parses search scope query parameter.
///
/// Parameters: `raw` - optional scope string.
/// Returns: parsed scope or validation error.
fn parse_scope(raw: Option<&str>, request_id: &str) -> Result<SearchScope, ApiError> {
    match raw {
        None | Some("all") => Ok(SearchScope::All),
        Some("mappings") => Ok(SearchScope::Mappings),
        Some("events") => Ok(SearchScope::Events),
        Some(_) => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Invalid 'scope' value. Use: all, mappings, events",
        )
        .with_request_id(request_id)),
    }
}

/// Parses export format (`json` or `csv`) with default `json`.
///
/// Parameters: `raw` - optional format string.
/// Returns: normalized format value.
fn parse_export_format(raw: Option<&str>, request_id: &str) -> Result<&'static str, ApiError> {
    match raw {
        None | Some("json") => Ok("json"),
        Some("csv") => Ok("csv"),
        Some(_) => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Invalid 'format' value. Use: json or csv",
        )
        .with_request_id(request_id)),
    }
}

/// Returns normalized order direction (`ASC` or `DESC`).
///
/// Parameters: `raw` - optional order value.
/// Returns: SQL-safe order direction.
fn parse_order(raw: Option<&str>) -> &'static str {
    if raw == Some("asc") {
        "ASC"
    } else {
        "DESC"
    }
}

/// Maps sort key to safe mappings column.
///
/// Parameters: `raw` - optional sort field from query.
/// Returns: SQL-safe column name for mappings.
fn mappings_sort_column(raw: Option<&str>) -> &'static str {
    match raw {
        Some("ip") => "m.ip",
        Some("user") => "m.user",
        Some("source") => "m.source",
        Some("last_seen") => "m.last_seen",
        _ => "m.last_seen",
    }
}

/// Maps sort key to safe events column.
///
/// Parameters: `raw` - optional sort field from query.
/// Returns: SQL-safe column name for events.
fn events_sort_column(raw: Option<&str>) -> &'static str {
    match raw {
        Some("ip") => "ip",
        Some("user") => "user",
        Some("source") => "source",
        Some("timestamp") => "timestamp",
        _ => "timestamp",
    }
}

/// Applies dynamic bind list to a SQLx query.
///
/// Parameters: `query` - SQLx raw query, `binds` - parameters in placeholder order.
/// Returns: query with all bind values attached.
fn apply_binds<'q>(
    mut query: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    binds: &'q [BindParam],
) -> sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    for bind in binds {
        query = match bind {
            BindParam::Text(v) => query.bind(v),
            BindParam::DateTime(v) => query.bind(v),
            BindParam::I64(v) => query.bind(v),
        };
    }
    query
}

/// Builds mappings filter SQL and bind values.
///
/// Parameters: `q` - search query, `from_dt`/`to_dt` - parsed time range, `include_free_text`.
/// Returns: tuple of conditions and bind parameters.
fn build_mappings_filters(
    q: &SearchQuery,
    from_dt: Option<DateTime<Utc>>,
    to_dt: Option<DateTime<Utc>>,
    include_free_text: bool,
) -> (Vec<String>, Vec<BindParam>) {
    let mut conditions = Vec::new();
    let mut binds = Vec::new();

    if include_free_text {
        if let Some(search) = &q.q {
            conditions.push(
                "(m.ip LIKE ? OR m.user LIKE ? OR m.mac LIKE ? OR m.vendor LIKE ?)".to_string(),
            );
            let like = format!("%{search}%");
            binds.push(BindParam::Text(like.clone()));
            binds.push(BindParam::Text(like.clone()));
            binds.push(BindParam::Text(like.clone()));
            binds.push(BindParam::Text(like));
        }
    }
    if let Some(ip) = &q.ip {
        conditions.push("m.ip = ?".to_string());
        binds.push(BindParam::Text(ip.clone()));
    }
    if let Some(user) = &q.user {
        conditions.push("m.user = ?".to_string());
        binds.push(BindParam::Text(user.clone()));
    }
    if let Some(mac) = &q.mac {
        conditions.push("m.mac = ?".to_string());
        binds.push(BindParam::Text(mac.clone()));
    }
    if let Some(vendor) = &q.vendor {
        conditions.push("m.vendor LIKE ?".to_string());
        binds.push(BindParam::Text(format!("%{vendor}%")));
    }
    if let Some(source) = &q.source {
        conditions.push("m.source = ?".to_string());
        binds.push(BindParam::Text(source.clone()));
    }
    if let Some(active) = q.active {
        if active {
            conditions.push("m.is_active = true".to_string());
        } else {
            conditions.push("m.is_active = false".to_string());
        }
    }
    if let Some(from) = from_dt {
        conditions.push("m.last_seen >= ?".to_string());
        binds.push(BindParam::DateTime(from));
    }
    if let Some(to) = to_dt {
        conditions.push("m.last_seen <= ?".to_string());
        binds.push(BindParam::DateTime(to));
    }

    (conditions, binds)
}

/// Builds events filter SQL and bind values.
///
/// Parameters: `q` - search query, `from_dt`/`to_dt` - parsed time range, `include_free_text`.
/// Returns: tuple of conditions and bind parameters.
fn build_events_filters(
    q: &SearchQuery,
    from_dt: Option<DateTime<Utc>>,
    to_dt: Option<DateTime<Utc>>,
    include_free_text: bool,
) -> (Vec<String>, Vec<BindParam>) {
    let mut conditions = Vec::new();
    let mut binds = Vec::new();

    if include_free_text {
        if let Some(search) = &q.q {
            conditions.push("(ip LIKE ? OR user LIKE ?)".to_string());
            let like = format!("%{search}%");
            binds.push(BindParam::Text(like.clone()));
            binds.push(BindParam::Text(like));
        }
    }
    if let Some(ip) = &q.ip {
        conditions.push("ip = ?".to_string());
        binds.push(BindParam::Text(ip.clone()));
    }
    if let Some(user) = &q.user {
        conditions.push("user = ?".to_string());
        binds.push(BindParam::Text(user.clone()));
    }
    if let Some(source) = &q.source {
        conditions.push("source = ?".to_string());
        binds.push(BindParam::Text(source.clone()));
    }
    if let Some(from) = from_dt {
        conditions.push("timestamp >= ?".to_string());
        binds.push(BindParam::DateTime(from));
    }
    if let Some(to) = to_dt {
        conditions.push("timestamp <= ?".to_string());
        binds.push(BindParam::DateTime(to));
    }

    (conditions, binds)
}

/// Escapes CSV field according to RFC4180-compatible minimal rules.
///
/// Parameters: `value` - raw field value.
/// Returns: escaped value safe for CSV output.
fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Converts source enum into stable storage/API string representation.
///
/// Parameters: `source` - source enum from mapping record.
/// Returns: canonical source label string.
fn source_to_str(source: trueid_common::model::SourceType) -> &'static str {
    match source {
        trueid_common::model::SourceType::Radius => "Radius",
        trueid_common::model::SourceType::AdLog => "AdLog",
        trueid_common::model::SourceType::DhcpLease => "DhcpLease",
        trueid_common::model::SourceType::Manual => "Manual",
        trueid_common::model::SourceType::VpnAnyConnect => "vpn_anyconnect",
        trueid_common::model::SourceType::VpnGlobalProtect => "vpn_globalprotect",
        trueid_common::model::SourceType::VpnFortinet => "vpn_fortinet",
    }
}

/// Builds export response with attachment headers.
///
/// Parameters: `content_type` - MIME type, `filename` - output filename,
/// `body` - serialized payload, `truncated` - whether result was capped.
/// Returns: HTTP response payload with headers.
fn build_export_response(
    content_type: &str,
    filename: &str,
    body: String,
    truncated: bool,
    request_id: &str,
) -> Result<impl IntoResponse, ApiError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(content_type).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to set Content-Type header",
            )
            .with_request_id(request_id)
        })?,
    );
    headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to set Content-Disposition header",
            )
            .with_request_id(request_id)
        })?,
    );
    if truncated {
        headers.insert("x-trueid-truncated", HeaderValue::from_static("true"));
    }
    Ok((headers, body))
}

/// Performs unified v2 search over mappings/events based on scope and filters.
///
/// Parameters: `auth` - authenticated user context, `q` - filter/query params, `state` - app state.
/// Returns: paginated search result with total counts and query duration.
pub async fn search(
    auth: AuthUser,
    Query(q): Query<SearchQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let scope = parse_scope(q.scope.as_deref(), &auth.request_id)?;
    let from_dt = parse_datetime_param(&q.from_ts, "from", &auth.request_id)?;
    let to_dt = parse_datetime_param(&q.to_ts, "to", &auth.request_id)?;
    let pagination = PaginationParams {
        page: q.page,
        limit: q.limit,
    };
    let page = pagination.page_or(DEFAULT_PAGE);
    let limit = pagination.limit_or(DEFAULT_LIMIT, MAX_LIMIT);
    let offset = pagination.offset(DEFAULT_LIMIT, MAX_LIMIT);
    let order = parse_order(q.order.as_deref());
    let start = Instant::now();
    let pool = db.pool();

    let mut mappings: Option<SearchSection<DeviceMapping>> = None;
    let mut events: Option<SearchSection<StoredEvent>> = None;

    if scope == SearchScope::All || scope == SearchScope::Mappings {
        let (conditions, mut binds) = build_mappings_filters(&q, from_dt, to_dt, true);
        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };
        let count_sql = format!("SELECT COUNT(*) as c FROM mappings m {where_clause}");
        let data_sql = format!(
            "{MAPPING_SELECT}
             FROM mappings m
             LEFT JOIN subnets s ON m.subnet_id = s.id
             LEFT JOIN dns_cache d ON m.ip = d.ip
             {where_clause} ORDER BY {} {} LIMIT ? OFFSET ?",
            mappings_sort_column(q.sort.as_deref()),
            order
        );

        let total: i64 = apply_binds(sqlx::query(&count_sql), &binds)
            .fetch_one(pool)
            .await
            .map_err(|e| {
                warn!(error = %e, "Search mappings count query failed");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to execute mappings count query",
                )
                .with_request_id(&auth.request_id)
            })?
            .try_get("c")
            .unwrap_or(0);

        binds.push(BindParam::I64(i64::from(limit)));
        binds.push(BindParam::I64(offset));
        let rows = apply_binds(sqlx::query(&data_sql), &binds)
            .fetch_all(pool)
            .await
            .map_err(|e| {
                warn!(error = %e, "Search mappings data query failed");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to execute mappings query",
                )
                .with_request_id(&auth.request_id)
            })?;

        let mut data = Vec::with_capacity(rows.len());
        for row in rows {
            let mapping = DeviceMapping::from_row(&row).map_err(|e| {
                warn!(error = %e, "Search mappings row decode failed");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to decode mappings row",
                )
                .with_request_id(&auth.request_id)
            })?;
            data.push(mapping);
        }

        mappings = Some(SearchSection { data, total });
    }

    if scope == SearchScope::All || scope == SearchScope::Events {
        let (conditions, mut binds) = build_events_filters(&q, from_dt, to_dt, true);
        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };
        let count_sql = format!("SELECT COUNT(*) as c FROM events {where_clause}");
        let data_sql = format!(
            "SELECT id, ip, user, source, timestamp, raw_data \
             FROM events {where_clause} ORDER BY {} {} LIMIT ? OFFSET ?",
            events_sort_column(q.sort.as_deref()),
            order
        );

        let total: i64 = apply_binds(sqlx::query(&count_sql), &binds)
            .fetch_one(pool)
            .await
            .map_err(|e| {
                warn!(error = %e, "Search events count query failed");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to execute events count query",
                )
                .with_request_id(&auth.request_id)
            })?
            .try_get("c")
            .unwrap_or(0);

        binds.push(BindParam::I64(i64::from(limit)));
        binds.push(BindParam::I64(offset));
        let rows = apply_binds(sqlx::query(&data_sql), &binds)
            .fetch_all(pool)
            .await
            .map_err(|e| {
                warn!(error = %e, "Search events data query failed");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to execute events query",
                )
                .with_request_id(&auth.request_id)
            })?;

        let mut data = Vec::with_capacity(rows.len());
        for row in rows {
            data.push(StoredEvent {
                id: row.try_get("id").unwrap_or(0),
                ip: row.try_get("ip").unwrap_or_default(),
                user: row.try_get("user").unwrap_or_default(),
                source: row.try_get("source").unwrap_or_default(),
                timestamp: row.try_get("timestamp").unwrap_or_else(|_| Utc::now()),
                raw_data: row.try_get("raw_data").unwrap_or_default(),
            });
        }

        events = Some(SearchSection { data, total });
    }

    Ok(Json(SearchResponse {
        mappings,
        events,
        page,
        limit,
        query_time_ms: start.elapsed().as_millis(),
    }))
}

/// Exports filtered mappings as JSON or CSV attachment.
///
/// Parameters: `auth` - authenticated user context, `q` - export filters, `state` - app state.
/// Returns: downloadable file response.
pub async fn export_mappings(
    auth: AuthUser,
    Query(q): Query<ExportMappingsQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let format = parse_export_format(q.format.as_deref(), &auth.request_id)?;
    let from_dt = parse_datetime_param(&q.from_ts, "from", &auth.request_id)?;
    let to_dt = parse_datetime_param(&q.to_ts, "to", &auth.request_id)?;

    let search_like = SearchQuery {
        q: None,
        ip: q.ip.clone(),
        user: q.user.clone(),
        mac: q.mac.clone(),
        vendor: q.vendor.clone(),
        source: q.source.clone(),
        active: q.active,
        from_ts: q.from_ts.clone(),
        to_ts: q.to_ts.clone(),
        scope: None,
        page: None,
        limit: None,
        sort: Some("last_seen".to_string()),
        order: Some("desc".to_string()),
    };
    let (conditions, binds) = build_mappings_filters(&search_like, from_dt, to_dt, false);
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };
    let sql = format!(
        "{MAPPING_SELECT}
         FROM mappings m
         LEFT JOIN subnets s ON m.subnet_id = s.id
         LEFT JOIN dns_cache d ON m.ip = d.ip
         {where_clause} ORDER BY m.last_seen DESC"
    );

    let rows = apply_binds(sqlx::query(&sql), &binds)
        .fetch_all(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Export mappings query failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to export mappings",
            )
            .with_request_id(&auth.request_id)
        })?;

    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        let mapping = DeviceMapping::from_row(&row).map_err(|e| {
            warn!(error = %e, "Export mappings row decode failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to decode mappings row",
            )
            .with_request_id(&auth.request_id)
        })?;
        data.push(mapping);
    }

    let details = format!("format={format}, filters={q:?}");
    helpers::audit(db, &auth, "export_mappings", None, Some(&details)).await;

    let date = Utc::now().format("%Y%m%d").to_string();
    if format == "json" {
        let body = serde_json::to_string(&data).map_err(|e| {
            warn!(error = %e, "Mappings JSON serialization failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to serialize mappings export",
            )
            .with_request_id(&auth.request_id)
        })?;
        return build_export_response(
            "application/json",
            &format!("trueid-mappings-{date}.json"),
            body,
            false,
            &auth.request_id,
        );
    }

    let mut csv = String::from(
        "ip,user,mac,source,last_seen,confidence,is_active,vendor,subnet_id,subnet_name,hostname,device_type,multi_user,current_users,groups\n",
    );
    for row in &data {
        let user = row.current_users.first().cloned().unwrap_or_default();
        let current_users = row.current_users.join(";");
        let groups = row.groups.as_ref().map(|g| g.join(";")).unwrap_or_default();
        let line = format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            csv_escape(&row.ip),
            csv_escape(&user),
            csv_escape(row.mac.as_deref().unwrap_or("")),
            csv_escape(source_to_str(row.source)),
            csv_escape(&row.last_seen.to_rfc3339()),
            row.confidence_score,
            row.is_active,
            csv_escape(row.vendor.as_deref().unwrap_or("")),
            row.subnet_id.map(|v| v.to_string()).unwrap_or_default(),
            csv_escape(row.subnet_name.as_deref().unwrap_or("")),
            csv_escape(row.hostname.as_deref().unwrap_or("")),
            csv_escape(row.device_type.as_deref().unwrap_or("")),
            row.multi_user,
            csv_escape(&current_users),
            csv_escape(&groups),
        );
        csv.push_str(&line);
    }

    build_export_response(
        "text/csv",
        &format!("trueid-mappings-{date}.csv"),
        csv,
        false,
        &auth.request_id,
    )
}

/// Exports filtered events as JSON or CSV attachment with safety cap.
///
/// Parameters: `auth` - authenticated user context, `q` - export filters, `state` - app state.
/// Returns: downloadable file response and truncation header when capped.
pub async fn export_events(
    auth: AuthUser,
    Query(q): Query<ExportEventsQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let format = parse_export_format(q.format.as_deref(), &auth.request_id)?;
    let from_dt = parse_datetime_param(&q.from_ts, "from", &auth.request_id)?;
    let to_dt = parse_datetime_param(&q.to_ts, "to", &auth.request_id)?;

    let search_like = SearchQuery {
        q: None,
        ip: q.ip.clone(),
        user: q.user.clone(),
        mac: None,
        vendor: None,
        source: q.source.clone(),
        active: None,
        from_ts: q.from_ts.clone(),
        to_ts: q.to_ts.clone(),
        scope: None,
        page: None,
        limit: None,
        sort: Some("timestamp".to_string()),
        order: Some("desc".to_string()),
    };
    let (conditions, mut binds) = build_events_filters(&search_like, from_dt, to_dt, false);
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) as c FROM events {where_clause}");
    let total: i64 = apply_binds(sqlx::query(&count_sql), &binds)
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Export events count query failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to count events for export",
            )
            .with_request_id(&auth.request_id)
        })?
        .try_get("c")
        .unwrap_or(0);

    let truncated = total > EXPORT_EVENTS_MAX_ROWS;
    let sql = format!(
        "SELECT id, ip, user, source, timestamp, raw_data \
         FROM events {where_clause} ORDER BY timestamp DESC LIMIT ?"
    );
    binds.push(BindParam::I64(EXPORT_EVENTS_MAX_ROWS));
    let rows = apply_binds(sqlx::query(&sql), &binds)
        .fetch_all(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Export events query failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to export events",
            )
            .with_request_id(&auth.request_id)
        })?;

    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        data.push(StoredEvent {
            id: row.try_get("id").unwrap_or(0),
            ip: row.try_get("ip").unwrap_or_default(),
            user: row.try_get("user").unwrap_or_default(),
            source: row.try_get("source").unwrap_or_default(),
            timestamp: row.try_get("timestamp").unwrap_or_else(|_| Utc::now()),
            raw_data: row.try_get("raw_data").unwrap_or_default(),
        });
    }

    let details = format!("format={format}, filters={q:?}");
    helpers::audit(db, &auth, "export_events", None, Some(&details)).await;

    let date = Utc::now().format("%Y%m%d").to_string();
    if format == "json" {
        let body = serde_json::to_string(&data).map_err(|e| {
            warn!(error = %e, "Events JSON serialization failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to serialize events export",
            )
            .with_request_id(&auth.request_id)
        })?;
        return build_export_response(
            "application/json",
            &format!("trueid-events-{date}.json"),
            body,
            truncated,
            &auth.request_id,
        );
    }

    let mut csv = String::from("id,ip,user,source,timestamp,raw_data\n");
    for row in &data {
        let line = format!(
            "{},{},{},{},{},{}\n",
            row.id,
            csv_escape(&row.ip),
            csv_escape(&row.user),
            csv_escape(&row.source),
            csv_escape(&row.timestamp.to_rfc3339()),
            csv_escape(&row.raw_data),
        );
        csv.push_str(&line);
    }

    build_export_response(
        "text/csv",
        &format!("trueid-events-{date}.csv"),
        csv,
        truncated,
        &auth.request_id,
    )
}
