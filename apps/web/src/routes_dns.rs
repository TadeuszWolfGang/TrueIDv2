//! DNS cache browsing and maintenance endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tracing::warn;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;

/// DNS cache record returned by API.
#[derive(Serialize)]
struct DnsCacheResponse {
    ip: String,
    hostname: Option<String>,
    previous_hostname: Option<String>,
    resolved_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    first_seen: DateTime<Utc>,
    last_error: Option<String>,
    resolve_count: i64,
}

/// DNS cache aggregate statistics.
#[derive(Serialize)]
struct DnsStatsResponse {
    total_cached: i64,
    resolved_ok: i64,
    unresolved: i64,
    expired: i64,
    recent_changes: i64,
}

/// DNS list filters.
#[derive(Deserialize)]
pub(crate) struct DnsQuery {
    q: Option<String>,
    status: Option<String>,
    page: Option<i64>,
    limit: Option<i64>,
}

/// Paginated DNS list response.
#[derive(Serialize)]
struct DnsListResponse {
    data: Vec<DnsCacheResponse>,
    total: i64,
    page: i64,
    limit: i64,
}

/// Flush response payload.
#[derive(Serialize)]
struct FlushResponse {
    deleted: u64,
}

/// Maps SQL row into DNS response struct.
///
/// Parameters: `row` - database row.
/// Returns: serialized DNS cache record.
fn map_dns_row(row: &sqlx::sqlite::SqliteRow) -> DnsCacheResponse {
    DnsCacheResponse {
        ip: row.try_get("ip").unwrap_or_default(),
        hostname: row.try_get("hostname").ok(),
        previous_hostname: row.try_get("previous_hostname").ok(),
        resolved_at: row.try_get("resolved_at").ok(),
        expires_at: row.try_get("expires_at").ok(),
        first_seen: row.try_get("first_seen").unwrap_or_else(|_| Utc::now()),
        last_error: row.try_get("last_error").ok(),
        resolve_count: row.try_get("resolve_count").unwrap_or(0),
    }
}

/// Lists DNS cache entries with filtering and pagination.
///
/// Parameters: `auth` - authenticated principal, `q` - query filters, `state` - app state.
/// Returns: paginated list response.
pub(crate) async fn list_dns(
    auth: AuthUser,
    Query(q): Query<DnsQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * limit;

    let mut conditions = Vec::<String>::new();
    let mut binds = Vec::<String>::new();

    if let Some(search) = q.q {
        conditions.push("(ip LIKE ? OR hostname LIKE ?)".to_string());
        let like = format!("%{search}%");
        binds.push(like.clone());
        binds.push(like);
    }

    if let Some(status) = q.status.as_deref() {
        match status {
            "resolved" => conditions.push("hostname IS NOT NULL".to_string()),
            "unresolved" => conditions.push("hostname IS NULL".to_string()),
            "expired" => conditions.push("expires_at < datetime('now')".to_string()),
            "changed" => conditions.push("previous_hostname IS NOT NULL".to_string()),
            _ => {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    error::INVALID_INPUT,
                    "Invalid status. Use: resolved, unresolved, expired, changed",
                )
                .with_request_id(&auth.request_id));
            }
        }
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) as c FROM dns_cache {where_clause}");
    let mut count_q = sqlx::query(&count_sql);
    for bind in &binds {
        count_q = count_q.bind(bind);
    }
    let total: i64 = count_q
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to count DNS cache entries");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to list DNS cache",
            )
            .with_request_id(&auth.request_id)
        })?
        .try_get("c")
        .unwrap_or(0);

    let data_sql = format!(
        "SELECT ip, hostname, previous_hostname, resolved_at, expires_at, first_seen, last_error, resolve_count
         FROM dns_cache
         {where_clause}
         ORDER BY COALESCE(resolved_at, first_seen) DESC
         LIMIT ? OFFSET ?"
    );
    let mut data_q = sqlx::query(&data_sql);
    for bind in &binds {
        data_q = data_q.bind(bind);
    }
    let rows = data_q
        .bind(limit)
        .bind(offset)
        .fetch_all(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to fetch DNS cache entries");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to list DNS cache",
            )
            .with_request_id(&auth.request_id)
        })?;

    let data = rows.iter().map(map_dns_row).collect::<Vec<_>>();
    Ok(Json(DnsListResponse {
        data,
        total,
        page,
        limit,
    }))
}

/// Returns DNS cache statistics.
///
/// Parameters: `auth` - authenticated principal, `state` - app state.
/// Returns: aggregate DNS stats response.
pub(crate) async fn dns_stats(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let total_cached: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dns_cache")
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to query dns total_cached");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to query DNS stats",
            )
            .with_request_id(&auth.request_id)
        })?;
    let resolved_ok: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dns_cache WHERE hostname IS NOT NULL")
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to query dns resolved_ok");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to query DNS stats",
                )
                .with_request_id(&auth.request_id)
            })?;
    let unresolved: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dns_cache WHERE hostname IS NULL")
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to query dns unresolved");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to query DNS stats",
                )
                .with_request_id(&auth.request_id)
            })?;
    let expired: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dns_cache WHERE expires_at < datetime('now')")
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to query dns expired");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to query DNS stats",
                )
                .with_request_id(&auth.request_id)
            })?;
    let recent_changes: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dns_cache WHERE previous_hostname IS NOT NULL")
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to query dns recent_changes");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to query DNS stats",
                )
                .with_request_id(&auth.request_id)
            })?;

    Ok(Json(DnsStatsResponse {
        total_cached,
        resolved_ok,
        unresolved,
        expired,
        recent_changes,
    }))
}

/// Returns DNS cache details for a single IP.
///
/// Parameters: `auth` - authenticated principal, `ip` - target IP, `state` - app state.
/// Returns: DNS cache entry for the IP.
pub(crate) async fn dns_by_ip(
    auth: AuthUser,
    Path(ip): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let row = sqlx::query(
        "SELECT ip, hostname, previous_hostname, resolved_at, expires_at, first_seen, last_error, resolve_count
         FROM dns_cache
         WHERE ip = ?",
    )
    .bind(&ip)
    .fetch_optional(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, ip = %ip, "Failed to fetch DNS cache row");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to fetch DNS cache entry",
        )
        .with_request_id(&auth.request_id)
    })?;

    match row {
        Some(row) => Ok(Json(map_dns_row(&row)).into_response()),
        None => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "DNS cache entry not found",
        )
        .with_request_id(&auth.request_id)),
    }
}

/// Deletes DNS cache entry for one IP to force re-resolve on next cycle.
///
/// Parameters: `auth` - authenticated admin, `ip` - target IP, `state` - app state.
/// Returns: HTTP 204 when deleted.
pub(crate) async fn delete_dns_ip(
    auth: AuthUser,
    Path(ip): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let result = sqlx::query("DELETE FROM dns_cache WHERE ip = ?")
        .bind(&ip)
        .execute(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, ip = %ip, "Failed to delete DNS cache entry");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to delete DNS cache entry",
            )
            .with_request_id(&auth.request_id)
        })?;
    if result.rows_affected() == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "DNS cache entry not found",
        )
        .with_request_id(&auth.request_id));
    }

    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "dns_cache_delete_ip",
            Some(&ip),
            None,
            None,
            Some(&auth.request_id),
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Flushes whole DNS cache table.
///
/// Parameters: `auth` - authenticated admin, `state` - app state.
/// Returns: number of deleted rows.
pub(crate) async fn flush_dns_cache(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let result = sqlx::query("DELETE FROM dns_cache")
        .execute(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to flush DNS cache");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to flush DNS cache",
            )
            .with_request_id(&auth.request_id)
        })?;

    let deleted = result.rows_affected();
    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "dns_cache_flush",
            None,
            Some(&format!("deleted={deleted}")),
            None,
            Some(&auth.request_id),
        )
        .await;

    Ok((StatusCode::OK, Json(FlushResponse { deleted })))
}
