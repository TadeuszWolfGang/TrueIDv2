//! Timeline endpoints for IP/user/MAC investigations.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tracing::warn;

use crate::error::{self, ApiError};
use crate::middleware::AuthUser;
use crate::AppState;

/// Shared query parameters for timeline endpoints.
#[derive(Debug, Deserialize)]
pub struct TimelineQuery {
    #[serde(rename = "from")]
    pub from_ts: Option<String>,
    #[serde(rename = "to")]
    pub to_ts: Option<String>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// Generic paginated response section.
#[derive(Debug, Serialize)]
struct Paginated<T> {
    data: Vec<T>,
    total: i64,
    page: u32,
    limit: u32,
}

/// Current mapping details for IP timeline.
#[derive(Debug, Serialize)]
struct CurrentIpMapping {
    user: String,
    mac: Option<String>,
    source: String,
    last_seen: DateTime<Utc>,
    confidence: i64,
    is_active: bool,
    vendor: Option<String>,
}

/// Event record returned by IP timeline endpoint.
#[derive(Debug, Serialize)]
struct IpTimelineEvent {
    id: i64,
    user: String,
    source: String,
    timestamp: DateTime<Utc>,
}

/// User transition item for IP timeline.
#[derive(Debug, Serialize)]
struct UserChange {
    from_user: String,
    to_user: String,
    changed_at: DateTime<Utc>,
    source: String,
}

/// Response for IP timeline endpoint.
#[derive(Debug, Serialize)]
struct IpTimelineResponse {
    ip: String,
    current_mapping: Option<CurrentIpMapping>,
    events: Paginated<IpTimelineEvent>,
    user_changes: Vec<UserChange>,
    conflicts_count: i64,
}

/// Active mapping item for user timeline endpoint.
#[derive(Debug, Serialize)]
struct UserActiveMapping {
    ip: String,
    mac: Option<String>,
    source: String,
    last_seen: DateTime<Utc>,
    vendor: Option<String>,
}

/// Event item for user timeline endpoint.
#[derive(Debug, Serialize)]
struct UserTimelineEvent {
    id: i64,
    ip: String,
    source: String,
    timestamp: DateTime<Utc>,
}

/// Response for user timeline endpoint.
#[derive(Debug, Serialize)]
struct UserTimelineResponse {
    user: String,
    active_mappings: Vec<UserActiveMapping>,
    events: Paginated<UserTimelineEvent>,
    ip_addresses_used: Vec<String>,
}

/// Current mapping item for MAC timeline endpoint.
#[derive(Debug, Serialize)]
struct MacCurrentMapping {
    ip: String,
    user: String,
    source: String,
    last_seen: DateTime<Utc>,
    is_active: bool,
}

/// Response for MAC timeline endpoint.
#[derive(Debug, Serialize)]
struct MacTimelineResponse {
    mac: String,
    current_mappings: Vec<MacCurrentMapping>,
    ip_history: Vec<String>,
}

/// Bind parameter type for dynamic SQL.
#[derive(Debug, Clone)]
enum BindParam {
    Text(String),
    DateTime(DateTime<Utc>),
    I64(i64),
}

/// Parses RFC3339 or naive datetime string into UTC timestamp.
///
/// Parameters: `raw` - datetime string from query parameter.
/// Returns: parsed UTC datetime or `None` for unsupported format.
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

/// Parses optional datetime parameter with API-style validation errors.
///
/// Parameters: `raw` - optional datetime string, `field_name` - query field name, `request_id` - request correlation ID.
/// Returns: parsed optional UTC datetime or validation error.
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

/// Resolves timeline range with defaults and validates ordering.
///
/// Parameters: `q` - timeline query, `request_id` - request correlation ID.
/// Returns: tuple `(from_dt, to_dt)` in UTC.
fn resolve_time_range(
    q: &TimelineQuery,
    request_id: &str,
) -> Result<(DateTime<Utc>, DateTime<Utc>), ApiError> {
    let now = Utc::now();
    let from_dt = parse_datetime_param(&q.from_ts, "from", request_id)?
        .unwrap_or_else(|| now - Duration::days(7));
    let to_dt = parse_datetime_param(&q.to_ts, "to", request_id)?.unwrap_or(now);

    if from_dt > to_dt {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "'from' must be earlier than or equal to 'to'",
        )
        .with_request_id(request_id));
    }
    Ok((from_dt, to_dt))
}

/// Applies dynamic bind parameters to a SQLx query.
///
/// Parameters: `query` - SQL query object, `binds` - bind values in placeholder order.
/// Returns: query with all binds attached.
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

/// Returns full timeline for a single IP address.
///
/// Parameters: `auth` - authenticated principal, `ip` - IP path parameter, `q` - time/pagination query, `state` - app state.
/// Returns: current mapping, paginated events, detected user transitions, and unresolved conflicts count.
pub async fn timeline_ip(
    auth: AuthUser,
    Path(ip): Path<String>,
    Query(q): Query<TimelineQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = state.db.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            error::SERVICE_UNAVAILABLE,
            "Database unavailable",
        )
        .with_request_id(&auth.request_id)
    })?;

    let (from_dt, to_dt) = resolve_time_range(&q, &auth.request_id)?;
    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let offset = i64::from((page - 1) * limit);

    let current_mapping = sqlx::query(
        "SELECT user, mac, source, last_seen, confidence, is_active, vendor
         FROM mappings
         WHERE ip = ?",
    )
    .bind(&ip)
    .fetch_optional(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, ip = %ip, "Failed to query current mapping");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query timeline",
        )
        .with_request_id(&auth.request_id)
    })?
    .map(|row| CurrentIpMapping {
        user: row.try_get("user").unwrap_or_default(),
        mac: row.try_get("mac").ok(),
        source: row.try_get("source").unwrap_or_default(),
        last_seen: row.try_get("last_seen").unwrap_or_else(|_| Utc::now()),
        confidence: row.try_get("confidence").unwrap_or(0),
        is_active: row.try_get("is_active").unwrap_or(false),
        vendor: row.try_get("vendor").ok(),
    });

    let count_sql = "SELECT COUNT(*) as c
                     FROM events
                     WHERE ip = ? AND timestamp >= ? AND timestamp <= ?";
    let total_row = apply_binds(
        sqlx::query(count_sql),
        &[
            BindParam::Text(ip.clone()),
            BindParam::DateTime(from_dt),
            BindParam::DateTime(to_dt),
        ],
    )
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, ip = %ip, "Failed to count IP timeline events");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query timeline",
        )
        .with_request_id(&auth.request_id)
    })?;
    let total: i64 = total_row.try_get("c").unwrap_or(0);

    let data_sql = "SELECT id, user, source, timestamp
                    FROM events
                    WHERE ip = ? AND timestamp >= ? AND timestamp <= ?
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?";
    let rows = apply_binds(
        sqlx::query(data_sql),
        &[
            BindParam::Text(ip.clone()),
            BindParam::DateTime(from_dt),
            BindParam::DateTime(to_dt),
            BindParam::I64(i64::from(limit)),
            BindParam::I64(offset),
        ],
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, ip = %ip, "Failed to fetch IP timeline events");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query timeline",
        )
        .with_request_id(&auth.request_id)
    })?;

    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        events.push(IpTimelineEvent {
            id: row.try_get("id").unwrap_or(0),
            user: row.try_get("user").unwrap_or_default(),
            source: row.try_get("source").unwrap_or_default(),
            timestamp: row.try_get("timestamp").unwrap_or_else(|_| Utc::now()),
        });
    }

    let transitions_rows = apply_binds(
        sqlx::query(
            "SELECT id, user, source, timestamp
             FROM events
             WHERE ip = ? AND timestamp >= ? AND timestamp <= ?
             ORDER BY timestamp ASC
             LIMIT 500",
        ),
        &[
            BindParam::Text(ip.clone()),
            BindParam::DateTime(from_dt),
            BindParam::DateTime(to_dt),
        ],
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, ip = %ip, "Failed to fetch transition events");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query timeline",
        )
        .with_request_id(&auth.request_id)
    })?;

    let mut transition_events = Vec::with_capacity(transitions_rows.len());
    for row in transitions_rows {
        transition_events.push(IpTimelineEvent {
            id: row.try_get("id").unwrap_or(0),
            user: row.try_get("user").unwrap_or_default(),
            source: row.try_get("source").unwrap_or_default(),
            timestamp: row.try_get("timestamp").unwrap_or_else(|_| Utc::now()),
        });
    }

    let mut user_changes = Vec::new();
    for pair in transition_events.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        if previous.user != current.user {
            user_changes.push(UserChange {
                from_user: previous.user.clone(),
                to_user: current.user.clone(),
                changed_at: current.timestamp,
                source: current.source.clone(),
            });
        }
    }
    user_changes.reverse();

    let conflicts_count = match sqlx::query(
        "SELECT COUNT(*) as c
         FROM conflicts
         WHERE ip = ? AND resolved_at IS NULL",
    )
    .bind(&ip)
    .fetch_one(db.pool())
    .await
    {
        Ok(row) => row.try_get("c").unwrap_or(0),
        Err(e) => {
            warn!(error = %e, ip = %ip, "Conflicts count unavailable; defaulting to 0");
            0
        }
    };

    Ok(Json(IpTimelineResponse {
        ip,
        current_mapping,
        events: Paginated {
            data: events,
            total,
            page,
            limit,
        },
        user_changes,
        conflicts_count,
    }))
}

/// Returns timeline for a single user across all IP activity.
///
/// Parameters: `auth` - authenticated principal, `user` - username path parameter, `q` - time/pagination query, `state` - app state.
/// Returns: active mappings, paginated events, and distinct IP list.
pub async fn timeline_user(
    auth: AuthUser,
    Path(user): Path<String>,
    Query(q): Query<TimelineQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = state.db.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            error::SERVICE_UNAVAILABLE,
            "Database unavailable",
        )
        .with_request_id(&auth.request_id)
    })?;

    let (from_dt, to_dt) = resolve_time_range(&q, &auth.request_id)?;
    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let offset = i64::from((page - 1) * limit);

    let active_rows = sqlx::query(
        "SELECT ip, mac, source, last_seen, vendor
         FROM mappings
         WHERE user = ? AND is_active = true
         ORDER BY last_seen DESC",
    )
    .bind(&user)
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, user = %user, "Failed to fetch active user mappings");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query timeline",
        )
        .with_request_id(&auth.request_id)
    })?;
    let mut active_mappings = Vec::with_capacity(active_rows.len());
    for row in active_rows {
        active_mappings.push(UserActiveMapping {
            ip: row.try_get("ip").unwrap_or_default(),
            mac: row.try_get("mac").ok(),
            source: row.try_get("source").unwrap_or_default(),
            last_seen: row.try_get("last_seen").unwrap_or_else(|_| Utc::now()),
            vendor: row.try_get("vendor").ok(),
        });
    }

    let total_row = apply_binds(
        sqlx::query(
            "SELECT COUNT(*) as c
             FROM events
             WHERE user = ? AND timestamp >= ? AND timestamp <= ?",
        ),
        &[
            BindParam::Text(user.clone()),
            BindParam::DateTime(from_dt),
            BindParam::DateTime(to_dt),
        ],
    )
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, user = %user, "Failed to count user timeline events");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query timeline",
        )
        .with_request_id(&auth.request_id)
    })?;
    let total: i64 = total_row.try_get("c").unwrap_or(0);

    let event_rows = apply_binds(
        sqlx::query(
            "SELECT id, ip, source, timestamp
             FROM events
             WHERE user = ? AND timestamp >= ? AND timestamp <= ?
             ORDER BY timestamp DESC
             LIMIT ? OFFSET ?",
        ),
        &[
            BindParam::Text(user.clone()),
            BindParam::DateTime(from_dt),
            BindParam::DateTime(to_dt),
            BindParam::I64(i64::from(limit)),
            BindParam::I64(offset),
        ],
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, user = %user, "Failed to fetch user timeline events");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query timeline",
        )
        .with_request_id(&auth.request_id)
    })?;
    let mut events = Vec::with_capacity(event_rows.len());
    for row in event_rows {
        events.push(UserTimelineEvent {
            id: row.try_get("id").unwrap_or(0),
            ip: row.try_get("ip").unwrap_or_default(),
            source: row.try_get("source").unwrap_or_default(),
            timestamp: row.try_get("timestamp").unwrap_or_else(|_| Utc::now()),
        });
    }

    let distinct_rows = apply_binds(
        sqlx::query(
            "SELECT DISTINCT ip
             FROM events
             WHERE user = ? AND timestamp >= ? AND timestamp <= ?
             ORDER BY ip
             LIMIT 200",
        ),
        &[
            BindParam::Text(user.clone()),
            BindParam::DateTime(from_dt),
            BindParam::DateTime(to_dt),
        ],
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, user = %user, "Failed to fetch user distinct IPs");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query timeline",
        )
        .with_request_id(&auth.request_id)
    })?;
    let mut ip_addresses_used = Vec::with_capacity(distinct_rows.len());
    for row in distinct_rows {
        ip_addresses_used.push(row.try_get("ip").unwrap_or_default());
    }

    Ok(Json(UserTimelineResponse {
        user,
        active_mappings,
        events: Paginated {
            data: events,
            total,
            page,
            limit,
        },
        ip_addresses_used,
    }))
}

/// Returns timeline for a single MAC address.
///
/// Parameters: `auth` - authenticated principal, `mac` - MAC path parameter, `_q` - unused timeline query, `state` - app state.
/// Returns: current mappings and distinct IP history for this MAC.
pub async fn timeline_mac(
    auth: AuthUser,
    Path(mac): Path<String>,
    Query(_q): Query<TimelineQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = state.db.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            error::SERVICE_UNAVAILABLE,
            "Database unavailable",
        )
        .with_request_id(&auth.request_id)
    })?;

    let rows = sqlx::query(
        "SELECT ip, user, source, last_seen, is_active
         FROM mappings
         WHERE mac = ?
         ORDER BY last_seen DESC",
    )
    .bind(&mac)
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, mac = %mac, "Failed to fetch MAC current mappings");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query timeline",
        )
        .with_request_id(&auth.request_id)
    })?;

    let mut current_mappings = Vec::with_capacity(rows.len());
    for row in rows {
        current_mappings.push(MacCurrentMapping {
            ip: row.try_get("ip").unwrap_or_default(),
            user: row.try_get("user").unwrap_or_default(),
            source: row.try_get("source").unwrap_or_default(),
            last_seen: row.try_get("last_seen").unwrap_or_else(|_| Utc::now()),
            is_active: row.try_get("is_active").unwrap_or(false),
        });
    }

    let ip_rows = sqlx::query(
        "SELECT DISTINCT ip
         FROM mappings
         WHERE mac = ?
         ORDER BY ip",
    )
    .bind(&mac)
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, mac = %mac, "Failed to fetch MAC IP history");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query timeline",
        )
        .with_request_id(&auth.request_id)
    })?;

    let mut ip_history = Vec::with_capacity(ip_rows.len());
    for row in ip_rows {
        ip_history.push(row.try_get("ip").unwrap_or_default());
    }

    Ok(Json(MacTimelineResponse {
        mac,
        current_mappings,
        ip_history,
    }))
}
