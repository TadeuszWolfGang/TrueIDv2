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
use std::fmt::Write as _;
use tracing::warn;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;

/// Shared query parameters for timeline endpoints.
#[derive(Debug, Deserialize)]
pub struct TimelineQuery {
    #[serde(rename = "from")]
    pub from_ts: Option<String>,
    #[serde(rename = "to")]
    pub to_ts: Option<String>,
    pub cursor: Option<String>,
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
    next_cursor: Option<String>,
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
    current_mappings_total: i64,
    current_mappings_page: u32,
    current_mappings_limit: u32,
    current_mappings_next_cursor: Option<String>,
    ip_history: Vec<String>,
    ip_history_truncated: bool,
}

/// Bind parameter type for dynamic SQL.
#[derive(Debug, Clone)]
enum BindParam {
    Text(String),
    DateTime(DateTime<Utc>),
    I64(i64),
}

const DEFAULT_TIMELINE_LIMIT: u32 = 100;
const MAX_TIMELINE_LIMIT: u32 = 500;
const MAX_DEPRECATED_OFFSET: u64 = 50_000;
const AUXILIARY_TIMELINE_MULTIPLIER: u32 = 5;
const MAX_USER_CHANGES: u32 = 1_000;
const MAX_USER_IP_HISTORY: u32 = 1_000;
const MAX_MAC_IP_HISTORY: u32 = 1_000;
const MAX_ACTIVE_USER_MAPPINGS: u32 = 1_000;

/// Cursor for event lists ordered by `(timestamp DESC, id DESC)`.
#[derive(Debug, Clone)]
struct EventCursor {
    timestamp: DateTime<Utc>,
    id: i64,
}

/// Cursor for MAC current mappings ordered by `(last_seen DESC, ip DESC, user DESC)`.
#[derive(Debug, Clone)]
struct MacMappingCursor {
    last_seen: DateTime<Utc>,
    ip: String,
    user: String,
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

/// Resolves timeline pagination parameters and keeps deprecated page path for compatibility.
///
/// Parameters: `q` - timeline query.
/// Returns: normalized `(page, limit)`.
fn resolve_pagination(q: &TimelineQuery) -> (u32, u32) {
    let page = q.page.unwrap_or(1).max(1);
    let limit = q
        .limit
        .unwrap_or(DEFAULT_TIMELINE_LIMIT)
        .clamp(1, MAX_TIMELINE_LIMIT);
    (page, limit)
}

/// Computes bounded helper-list limit from the main page size.
///
/// Parameters: `limit` - requested page size, `max` - hard upper bound for helper list.
/// Returns: bounded SQL limit.
fn auxiliary_limit(limit: u32, max: u32) -> i64 {
    i64::from(
        limit
            .saturating_mul(AUXILIARY_TIMELINE_MULTIPLIER)
            .clamp(1, max),
    )
}

/// Builds a uniform validation error for malformed timeline cursors.
fn invalid_cursor(request_id: &str, message: &str) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, error::INVALID_INPUT, message)
        .with_request_id(request_id)
}

/// Hex-encodes cursor payload into a query-safe opaque token.
fn encode_cursor_payload(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
    for byte in payload.bytes() {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Decodes an opaque hex cursor payload into UTF-8 string content.
fn decode_cursor_payload(raw: &str, request_id: &str, message: &str) -> Result<String, ApiError> {
    if raw.is_empty() || raw.len() % 2 != 0 {
        return Err(invalid_cursor(request_id, message));
    }

    let mut bytes = Vec::with_capacity(raw.len() / 2);
    for idx in (0..raw.len()).step_by(2) {
        let byte = u8::from_str_radix(&raw[idx..idx + 2], 16)
            .map_err(|_| invalid_cursor(request_id, message))?;
        bytes.push(byte);
    }

    String::from_utf8(bytes).map_err(|_| invalid_cursor(request_id, message))
}

/// Resolves deprecated page-based offset and rejects pathological scans.
fn deprecated_offset(page: u32, limit: u32, request_id: &str) -> Result<Option<i64>, ApiError> {
    if page <= 1 {
        return Ok(None);
    }

    let offset = u64::from(page.saturating_sub(1)) * u64::from(limit);
    if offset > MAX_DEPRECATED_OFFSET {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Deprecated page pagination exceeds the maximum offset; use cursor pagination",
        )
        .with_request_id(request_id));
    }

    Ok(Some(offset as i64))
}

/// Encodes event cursor into query-safe string.
///
/// Parameters: `timestamp` - event timestamp, `id` - event ID.
/// Returns: opaque cursor string for clients.
fn encode_event_cursor(timestamp: DateTime<Utc>, id: i64) -> String {
    encode_cursor_payload(&format!("{}\n{}", timestamp.to_rfc3339(), id))
}

/// Decodes event cursor from client query.
///
/// Parameters: `raw` - raw cursor string, `request_id` - correlation ID.
/// Returns: parsed event cursor or validation error.
fn decode_event_cursor(raw: &str, request_id: &str) -> Result<EventCursor, ApiError> {
    let payload = decode_cursor_payload(raw, request_id, "Invalid timeline cursor")?;
    let (timestamp_raw, id_raw) = payload
        .split_once('\n')
        .ok_or_else(|| invalid_cursor(request_id, "Invalid timeline cursor"))?;
    let timestamp = parse_datetime(timestamp_raw)
        .ok_or_else(|| invalid_cursor(request_id, "Invalid timeline cursor timestamp"))?;
    let id = id_raw
        .parse::<i64>()
        .map_err(|_| invalid_cursor(request_id, "Invalid timeline cursor id"))?;
    Ok(EventCursor { timestamp, id })
}

/// Encodes MAC current-mapping cursor into query-safe string.
///
/// Parameters: `last_seen` - mapping timestamp, `ip` - mapping IP, `user` - mapped user.
/// Returns: opaque cursor string for clients.
fn encode_mac_mapping_cursor(last_seen: DateTime<Utc>, ip: &str, user: &str) -> String {
    encode_cursor_payload(&format!("{}\n{}\n{}", last_seen.to_rfc3339(), ip, user))
}

/// Decodes MAC current-mapping cursor from client query.
///
/// Parameters: `raw` - raw cursor string, `request_id` - correlation ID.
/// Returns: parsed cursor or validation error.
fn decode_mac_mapping_cursor(raw: &str, request_id: &str) -> Result<MacMappingCursor, ApiError> {
    let payload = decode_cursor_payload(raw, request_id, "Invalid MAC timeline cursor")?;
    let mut parts = payload.splitn(3, '\n');
    let timestamp_raw = parts.next().unwrap_or("");
    let ip = parts.next().unwrap_or("").to_string();
    let user = parts.next().unwrap_or("").to_string();
    if ip.is_empty() || user.is_empty() {
        return Err(invalid_cursor(request_id, "Invalid MAC timeline cursor"));
    }
    let last_seen = parse_datetime(timestamp_raw)
        .ok_or_else(|| invalid_cursor(request_id, "Invalid MAC timeline cursor timestamp"))?;
    Ok(MacMappingCursor {
        last_seen,
        ip,
        user,
    })
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

/// Fetches one IP event page using keyset pagination by default and offset only for deprecated page>1 fallback.
///
/// Parameters: `pool` - SQLite pool, `ip` - target IP, `from_dt` - range start, `to_dt` - range end,
/// `limit` - page size, `page` - deprecated page number, `cursor` - optional keyset cursor.
/// Returns: `(events, next_cursor)`.
async fn fetch_ip_event_page(
    pool: &sqlx::SqlitePool,
    ip: &str,
    from_dt: DateTime<Utc>,
    to_dt: DateTime<Utc>,
    limit: u32,
    deprecated_offset: Option<i64>,
    cursor: Option<&EventCursor>,
) -> Result<(Vec<IpTimelineEvent>, Option<String>), sqlx::Error> {
    let rows = if let Some(cursor) = cursor {
        sqlx::query(
            "SELECT id, user, source, timestamp
             FROM events
             WHERE ip = ? AND timestamp >= ? AND timestamp <= ?
               AND (timestamp < ? OR (timestamp = ? AND id < ?))
             ORDER BY timestamp DESC, id DESC
             LIMIT ?",
        )
        .bind(ip)
        .bind(from_dt)
        .bind(to_dt)
        .bind(cursor.timestamp)
        .bind(cursor.timestamp)
        .bind(cursor.id)
        .bind(i64::from(limit) + 1)
        .fetch_all(pool)
        .await?
    } else if let Some(offset) = deprecated_offset {
        sqlx::query(
            "SELECT id, user, source, timestamp
             FROM events
             WHERE ip = ? AND timestamp >= ? AND timestamp <= ?
             ORDER BY timestamp DESC, id DESC
             LIMIT ? OFFSET ?",
        )
        .bind(ip)
        .bind(from_dt)
        .bind(to_dt)
        .bind(i64::from(limit) + 1)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query(
            "SELECT id, user, source, timestamp
             FROM events
             WHERE ip = ? AND timestamp >= ? AND timestamp <= ?
             ORDER BY timestamp DESC, id DESC
             LIMIT ?",
        )
        .bind(ip)
        .bind(from_dt)
        .bind(to_dt)
        .bind(i64::from(limit) + 1)
        .fetch_all(pool)
        .await?
    };

    let mut events = Vec::with_capacity(rows.len().min(limit as usize));
    for row in rows {
        events.push(IpTimelineEvent {
            id: row.try_get("id").unwrap_or(0),
            user: row.try_get("user").unwrap_or_default(),
            source: row.try_get("source").unwrap_or_default(),
            timestamp: row.try_get("timestamp").unwrap_or_else(|_| Utc::now()),
        });
    }

    let next_cursor = if events.len() > limit as usize {
        events.truncate(limit as usize);
        events
            .last()
            .map(|last| encode_event_cursor(last.timestamp, last.id))
    } else {
        None
    };

    Ok((events, next_cursor))
}

/// Fetches one user event page using keyset pagination by default and offset only for deprecated page>1 fallback.
///
/// Parameters: `pool` - SQLite pool, `user` - target user, `from_dt` - range start, `to_dt` - range end,
/// `limit` - page size, `page` - deprecated page number, `cursor` - optional keyset cursor.
/// Returns: `(events, next_cursor)`.
async fn fetch_user_event_page(
    pool: &sqlx::SqlitePool,
    user: &str,
    from_dt: DateTime<Utc>,
    to_dt: DateTime<Utc>,
    limit: u32,
    deprecated_offset: Option<i64>,
    cursor: Option<&EventCursor>,
) -> Result<(Vec<UserTimelineEvent>, Option<String>), sqlx::Error> {
    let rows = if let Some(cursor) = cursor {
        sqlx::query(
            "SELECT id, ip, source, timestamp
             FROM events
             WHERE user = ? AND timestamp >= ? AND timestamp <= ?
               AND (timestamp < ? OR (timestamp = ? AND id < ?))
             ORDER BY timestamp DESC, id DESC
             LIMIT ?",
        )
        .bind(user)
        .bind(from_dt)
        .bind(to_dt)
        .bind(cursor.timestamp)
        .bind(cursor.timestamp)
        .bind(cursor.id)
        .bind(i64::from(limit) + 1)
        .fetch_all(pool)
        .await?
    } else if let Some(offset) = deprecated_offset {
        sqlx::query(
            "SELECT id, ip, source, timestamp
             FROM events
             WHERE user = ? AND timestamp >= ? AND timestamp <= ?
             ORDER BY timestamp DESC, id DESC
             LIMIT ? OFFSET ?",
        )
        .bind(user)
        .bind(from_dt)
        .bind(to_dt)
        .bind(i64::from(limit) + 1)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query(
            "SELECT id, ip, source, timestamp
             FROM events
             WHERE user = ? AND timestamp >= ? AND timestamp <= ?
             ORDER BY timestamp DESC, id DESC
             LIMIT ?",
        )
        .bind(user)
        .bind(from_dt)
        .bind(to_dt)
        .bind(i64::from(limit) + 1)
        .fetch_all(pool)
        .await?
    };

    let mut events = Vec::with_capacity(rows.len().min(limit as usize));
    for row in rows {
        events.push(UserTimelineEvent {
            id: row.try_get("id").unwrap_or(0),
            ip: row.try_get("ip").unwrap_or_default(),
            source: row.try_get("source").unwrap_or_default(),
            timestamp: row.try_get("timestamp").unwrap_or_else(|_| Utc::now()),
        });
    }

    let next_cursor = if events.len() > limit as usize {
        events.truncate(limit as usize);
        events
            .last()
            .map(|last| encode_event_cursor(last.timestamp, last.id))
    } else {
        None
    };

    Ok((events, next_cursor))
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
    let db = helpers::require_db(&state, &auth.request_id)?;

    let (from_dt, to_dt) = resolve_time_range(&q, &auth.request_id)?;
    let (page, limit) = resolve_pagination(&q);
    let cursor = q
        .cursor
        .as_deref()
        .map(|raw| decode_event_cursor(raw, &auth.request_id))
        .transpose()?;
    let deprecated_offset = if cursor.is_some() {
        None
    } else {
        deprecated_offset(page, limit, &auth.request_id)?
    };

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

    let (events, next_cursor) = fetch_ip_event_page(
        db.pool(),
        &ip,
        from_dt,
        to_dt,
        limit,
        deprecated_offset,
        cursor.as_ref(),
    )
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
    let transition_limit = auxiliary_limit(limit, MAX_USER_CHANGES);

    let transitions_rows = apply_binds(
        sqlx::query(
            "SELECT id, user, source, timestamp
             FROM events
             WHERE ip = ? AND timestamp >= ? AND timestamp <= ?
             ORDER BY timestamp ASC
             LIMIT ?",
        ),
        &[
            BindParam::Text(ip.clone()),
            BindParam::DateTime(from_dt),
            BindParam::DateTime(to_dt),
            BindParam::I64(transition_limit),
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
            next_cursor,
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
    let db = helpers::require_db(&state, &auth.request_id)?;

    let (from_dt, to_dt) = resolve_time_range(&q, &auth.request_id)?;
    let (page, limit) = resolve_pagination(&q);
    let cursor = q
        .cursor
        .as_deref()
        .map(|raw| decode_event_cursor(raw, &auth.request_id))
        .transpose()?;
    let deprecated_offset = if cursor.is_some() {
        None
    } else {
        deprecated_offset(page, limit, &auth.request_id)?
    };
    let active_limit = auxiliary_limit(limit, MAX_ACTIVE_USER_MAPPINGS);

    let active_rows = sqlx::query(
        "SELECT ip, mac, source, last_seen, vendor
         FROM mappings
         WHERE user = ? AND is_active = true
         ORDER BY last_seen DESC
         LIMIT ?",
    )
    .bind(&user)
    .bind(active_limit)
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

    let (events, next_cursor) = fetch_user_event_page(
        db.pool(),
        &user,
        from_dt,
        to_dt,
        limit,
        deprecated_offset,
        cursor.as_ref(),
    )
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
    let ip_history_limit = auxiliary_limit(limit, MAX_USER_IP_HISTORY);

    let distinct_rows = apply_binds(
        sqlx::query(
            "SELECT ip
             FROM events
             WHERE user = ? AND timestamp >= ? AND timestamp <= ?
             GROUP BY ip
             ORDER BY MAX(timestamp) DESC, ip ASC
             LIMIT ?",
        ),
        &[
            BindParam::Text(user.clone()),
            BindParam::DateTime(from_dt),
            BindParam::DateTime(to_dt),
            BindParam::I64(ip_history_limit),
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
            next_cursor,
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
    Query(q): Query<TimelineQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let (page, limit) = resolve_pagination(&q);
    let cursor = q
        .cursor
        .as_deref()
        .map(|raw| decode_mac_mapping_cursor(raw, &auth.request_id))
        .transpose()?;
    let deprecated_offset = if cursor.is_some() {
        None
    } else {
        deprecated_offset(page, limit, &auth.request_id)?
    };

    let total_row = sqlx::query(
        "SELECT COUNT(*) as c
         FROM mappings
         WHERE mac = ?",
    )
    .bind(&mac)
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, mac = %mac, "Failed to count MAC current mappings");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query timeline",
        )
        .with_request_id(&auth.request_id)
    })?;
    let current_mappings_total: i64 = total_row.try_get("c").unwrap_or(0);

    let rows = if let Some(cursor) = cursor.as_ref() {
        sqlx::query(
            "SELECT ip, user, source, last_seen, is_active
             FROM mappings
             WHERE mac = ?
               AND (
                    last_seen < ?
                    OR (last_seen = ? AND ip < ?)
                    OR (last_seen = ? AND ip = ? AND user < ?)
               )
             ORDER BY last_seen DESC, ip DESC, user DESC
             LIMIT ?",
        )
        .bind(&mac)
        .bind(cursor.last_seen)
        .bind(cursor.last_seen)
        .bind(&cursor.ip)
        .bind(cursor.last_seen)
        .bind(&cursor.ip)
        .bind(&cursor.user)
        .bind(i64::from(limit) + 1)
        .fetch_all(db.pool())
        .await
    } else if let Some(offset) = deprecated_offset {
        sqlx::query(
            "SELECT ip, user, source, last_seen, is_active
             FROM mappings
             WHERE mac = ?
             ORDER BY last_seen DESC, ip DESC, user DESC
             LIMIT ? OFFSET ?",
        )
        .bind(&mac)
        .bind(i64::from(limit) + 1)
        .bind(offset)
        .fetch_all(db.pool())
        .await
    } else {
        sqlx::query(
            "SELECT ip, user, source, last_seen, is_active
             FROM mappings
             WHERE mac = ?
             ORDER BY last_seen DESC, ip DESC, user DESC
             LIMIT ?",
        )
        .bind(&mac)
        .bind(i64::from(limit) + 1)
        .fetch_all(db.pool())
        .await
    }
    .map_err(|e| {
        warn!(error = %e, mac = %mac, "Failed to fetch MAC current mappings");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query timeline",
        )
        .with_request_id(&auth.request_id)
    })?;

    let mut current_mappings = Vec::with_capacity(rows.len().min(limit as usize));
    for row in rows {
        current_mappings.push(MacCurrentMapping {
            ip: row.try_get("ip").unwrap_or_default(),
            user: row.try_get("user").unwrap_or_default(),
            source: row.try_get("source").unwrap_or_default(),
            last_seen: row.try_get("last_seen").unwrap_or_else(|_| Utc::now()),
            is_active: row.try_get("is_active").unwrap_or(false),
        });
    }
    let current_mappings_next_cursor = if current_mappings.len() > limit as usize {
        current_mappings.truncate(limit as usize);
        current_mappings
            .last()
            .map(|last| encode_mac_mapping_cursor(last.last_seen, &last.ip, &last.user))
    } else {
        None
    };
    let ip_history_limit = auxiliary_limit(limit, MAX_MAC_IP_HISTORY);

    let ip_rows = sqlx::query(
        "SELECT ip
         FROM mappings
         WHERE mac = ?
         GROUP BY ip
         ORDER BY MAX(last_seen) DESC, ip ASC
         LIMIT ?",
    )
    .bind(&mac)
    .bind(ip_history_limit + 1)
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

    let mut ip_history = Vec::with_capacity(ip_rows.len().min(ip_history_limit as usize));
    for row in ip_rows {
        ip_history.push(row.try_get("ip").unwrap_or_default());
    }
    let ip_history_truncated = ip_history.len() > ip_history_limit as usize;
    if ip_history_truncated {
        ip_history.truncate(ip_history_limit as usize);
    }

    Ok(Json(MacTimelineResponse {
        mac,
        current_mappings,
        current_mappings_total,
        current_mappings_page: page,
        current_mappings_limit: limit,
        current_mappings_next_cursor,
        ip_history,
        ip_history_truncated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_event_cursor_round_trips() {
        let ts = Utc::now();
        let raw = encode_event_cursor(ts, 42);
        let parsed =
            decode_event_cursor(&raw, "req-1").unwrap_or_else(|_| panic!("cursor parse failed"));
        assert_eq!(parsed.id, 42);
        assert_eq!(parsed.timestamp.timestamp(), ts.timestamp());
    }

    #[test]
    fn decode_event_cursor_rejects_invalid_shape() {
        let err = decode_event_cursor("broken", "req-1").expect_err("cursor must fail");
        assert_eq!(err.code, error::INVALID_INPUT);
    }

    #[test]
    fn auxiliary_limit_scales_with_requested_page_size() {
        assert_eq!(auxiliary_limit(50, 1_000), 250);
        assert_eq!(auxiliary_limit(500, 1_000), 1_000);
    }

    #[test]
    fn decode_mac_mapping_cursor_round_trips() {
        let ts = Utc::now();
        let raw = encode_mac_mapping_cursor(ts, "10.1.2.3", "jkowalski");
        let parsed = decode_mac_mapping_cursor(&raw, "req-1")
            .unwrap_or_else(|_| panic!("mac cursor parse failed"));
        assert_eq!(parsed.ip, "10.1.2.3");
        assert_eq!(parsed.user, "jkowalski");
        assert_eq!(parsed.last_seen.timestamp(), ts.timestamp());
    }
}
