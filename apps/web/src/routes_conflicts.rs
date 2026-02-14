//! Conflict viewing and resolution endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use std::collections::HashMap;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;
use trueid_common::pagination::{PaginatedResponse, PaginationParams};

/// Conflict row representation used by v2 API endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct ConflictRecord {
    pub id: i64,
    pub conflict_type: String,
    pub severity: String,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub user_old: Option<String>,
    pub user_new: Option<String>,
    pub source: String,
    pub details: Option<String>,
    pub detected_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
}

/// Query parameters for conflicts listing.
#[derive(Debug, Deserialize)]
pub struct ListConflictsQuery {
    #[serde(rename = "type")]
    pub conflict_type: Option<String>,
    pub severity: Option<String>,
    pub ip: Option<String>,
    pub resolved: Option<bool>,
    #[serde(rename = "from")]
    pub from_ts: Option<String>,
    #[serde(rename = "to")]
    pub to_ts: Option<String>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// Request payload for resolve endpoint.
#[derive(Debug, Deserialize)]
pub struct ResolveConflictRequest {
    pub note: Option<String>,
}

/// Conflict stats response.
#[derive(Debug, Serialize)]
struct ConflictStatsResponse {
    total_unresolved: i64,
    by_type: HashMap<String, i64>,
    by_severity: HashMap<String, i64>,
}

/// Generic bind parameter for dynamic SQL.
#[derive(Debug, Clone)]
enum BindParam {
    Text(String),
    DateTime(DateTime<Utc>),
    I64(i64),
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

/// Applies dynamic bind list to a SQLx query.
///
/// Parameters: `query` - SQLx query object, `binds` - parameters in placeholder order.
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

/// Lists conflicts with filters and pagination.
///
/// Parameters: `auth` - authenticated principal, `q` - query filters, `state` - app state.
/// Returns: paginated conflicts list.
pub async fn list_conflicts(
    auth: AuthUser,
    Query(q): Query<ListConflictsQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let from_dt = parse_datetime_param(&q.from_ts, "from", &auth.request_id)?;
    let to_dt = parse_datetime_param(&q.to_ts, "to", &auth.request_id)?;
    let pagination = PaginationParams {
        page: q.page,
        limit: q.limit,
    };
    let page = pagination.page_or(1);
    let limit = pagination.limit_or(50, 200);
    let offset = pagination.offset(50, 200);

    let mut conditions = Vec::<String>::new();
    let mut binds = Vec::<BindParam>::new();

    if let Some(conflict_type) = &q.conflict_type {
        conditions.push("conflict_type = ?".to_string());
        binds.push(BindParam::Text(conflict_type.clone()));
    }
    if let Some(severity) = &q.severity {
        conditions.push("severity = ?".to_string());
        binds.push(BindParam::Text(severity.clone()));
    }
    if let Some(ip) = &q.ip {
        conditions.push("ip = ?".to_string());
        binds.push(BindParam::Text(ip.clone()));
    }
    if q.resolved.unwrap_or(false) {
        conditions.push("resolved_at IS NOT NULL".to_string());
    } else {
        conditions.push("resolved_at IS NULL".to_string());
    }
    if let Some(from) = from_dt {
        conditions.push("detected_at >= ?".to_string());
        binds.push(BindParam::DateTime(from));
    }
    if let Some(to) = to_dt {
        conditions.push("detected_at <= ?".to_string());
        binds.push(BindParam::DateTime(to));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) as c FROM conflicts {where_clause}");
    let total_row = apply_binds(sqlx::query(&count_sql), &binds)
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Conflicts count query failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to count conflicts",
            )
            .with_request_id(&auth.request_id)
        })?;
    let total: i64 = total_row.try_get("c").unwrap_or(0);

    let mut data_binds = binds.clone();
    data_binds.push(BindParam::I64(i64::from(limit)));
    data_binds.push(BindParam::I64(offset));

    let data_sql = format!(
        "SELECT id, conflict_type, severity, ip, mac, user_old, user_new, source, details, \
                detected_at, resolved_at, resolved_by
         FROM conflicts
         {where_clause}
         ORDER BY detected_at DESC
         LIMIT ? OFFSET ?"
    );
    let rows = apply_binds(sqlx::query(&data_sql), &data_binds)
        .fetch_all(db.pool())
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Conflicts list query failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to query conflicts",
            )
            .with_request_id(&auth.request_id)
        })?;

    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        data.push(ConflictRecord {
            id: row.try_get("id").unwrap_or(0),
            conflict_type: row.try_get("conflict_type").unwrap_or_default(),
            severity: row.try_get("severity").unwrap_or_default(),
            ip: row.try_get("ip").ok(),
            mac: row.try_get("mac").ok(),
            user_old: row.try_get("user_old").ok(),
            user_new: row.try_get("user_new").ok(),
            source: row.try_get("source").unwrap_or_default(),
            details: row.try_get("details").ok(),
            detected_at: row.try_get("detected_at").unwrap_or_else(|_| Utc::now()),
            resolved_at: row.try_get("resolved_at").ok(),
            resolved_by: row.try_get("resolved_by").ok(),
        });
    }

    Ok(Json(PaginatedResponse::new(data, total, page, limit)))
}

/// Returns unresolved conflict summary statistics.
///
/// Parameters: `auth` - authenticated principal, `state` - app state.
/// Returns: unresolved totals grouped by type and severity.
pub async fn conflict_stats(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let total_row = sqlx::query("SELECT COUNT(*) as c FROM conflicts WHERE resolved_at IS NULL")
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Conflict stats total query failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to compute conflict stats",
            )
            .with_request_id(&auth.request_id)
        })?;
    let total_unresolved: i64 = total_row.try_get("c").unwrap_or(0);

    let type_rows = sqlx::query(
        "SELECT conflict_type, COUNT(*) as c
         FROM conflicts
         WHERE resolved_at IS NULL
         GROUP BY conflict_type",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, "Conflict stats by_type query failed");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to compute conflict stats",
        )
        .with_request_id(&auth.request_id)
    })?;
    let mut by_type = HashMap::new();
    for row in type_rows {
        let key: String = row.try_get("conflict_type").unwrap_or_default();
        let count: i64 = row.try_get("c").unwrap_or(0);
        by_type.insert(key, count);
    }

    let severity_rows = sqlx::query(
        "SELECT severity, COUNT(*) as c
         FROM conflicts
         WHERE resolved_at IS NULL
         GROUP BY severity",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, "Conflict stats by_severity query failed");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to compute conflict stats",
        )
        .with_request_id(&auth.request_id)
    })?;
    let mut by_severity = HashMap::new();
    for row in severity_rows {
        let key: String = row.try_get("severity").unwrap_or_default();
        let count: i64 = row.try_get("c").unwrap_or(0);
        by_severity.insert(key, count);
    }

    Ok(Json(ConflictStatsResponse {
        total_unresolved,
        by_type,
        by_severity,
    }))
}

/// Resolves a conflict by ID and optionally appends a note into details JSON.
///
/// Parameters: `auth` - authenticated principal, `id` - conflict ID, `state` - app state, `body` - optional resolution note.
/// Returns: JSON response with updated resolution metadata.
pub async fn resolve_conflict(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(body): Json<ResolveConflictRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let existing = sqlx::query("SELECT details, resolved_at FROM conflicts WHERE id = ?")
        .bind(id)
        .fetch_optional(db.pool())
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, conflict_id = id, "Conflict lookup failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to resolve conflict",
            )
            .with_request_id(&auth.request_id)
        })?;

    let Some(existing_row) = existing else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "Conflict not found",
        )
        .with_request_id(&auth.request_id));
    };

    let already_resolved: Option<DateTime<Utc>> = existing_row.try_get("resolved_at").ok();
    if already_resolved.is_some() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            error::CONFLICT,
            "Conflict already resolved",
        )
        .with_request_id(&auth.request_id));
    }

    let current_details: Option<String> = existing_row.try_get("details").ok();
    let updated_details = if let Some(note) = body.note.as_ref() {
        let mut details_json = current_details
            .as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            .unwrap_or_else(|| json!({}));
        if !details_json.is_object() {
            details_json = json!({ "previous_details": details_json });
        }
        if let Some(obj) = details_json.as_object_mut() {
            obj.insert("resolution_note".to_string(), json!(note));
        }
        Some(details_json.to_string())
    } else {
        current_details
    };

    let resolved_at = Utc::now();
    sqlx::query("UPDATE conflicts SET resolved_at = ?, resolved_by = ?, details = ? WHERE id = ?")
        .bind(resolved_at)
        .bind(&auth.username)
        .bind(updated_details.clone())
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, conflict_id = id, "Conflict resolve update failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to resolve conflict",
            )
            .with_request_id(&auth.request_id)
        })?;

    let target_id = id.to_string();
    let details = format!("note={:?}", body.note);
    helpers::audit(
        db,
        &auth,
        "resolve_conflict",
        Some(&target_id),
        Some(&details),
    )
    .await;

    Ok(Json(json!({
        "id": id,
        "resolved_at": resolved_at.to_rfc3339(),
        "resolved_by": auth.username,
        "details": updated_details,
    })))
}
