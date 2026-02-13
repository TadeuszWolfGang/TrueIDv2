//! DHCP fingerprint definition and observation endpoints.

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

/// Fingerprint definition response payload.
#[derive(Serialize)]
struct FingerprintResponse {
    id: i64,
    fingerprint: String,
    device_type: String,
    os_family: Option<String>,
    description: Option<String>,
    source: String,
    created_at: DateTime<Utc>,
}

/// Create fingerprint request payload.
#[derive(Deserialize)]
pub(crate) struct CreateFingerprintRequest {
    fingerprint: String,
    device_type: String,
    os_family: Option<String>,
    description: Option<String>,
}

/// DHCP observation response payload.
#[derive(Serialize)]
struct ObservationResponse {
    mac: String,
    fingerprint: String,
    device_type: Option<String>,
    hostname: Option<String>,
    ip: Option<String>,
    observed_at: DateTime<Utc>,
    match_source: Option<String>,
}

/// Device type aggregate row.
#[derive(Serialize)]
struct DeviceTypeCount {
    device_type: String,
    count: i64,
}

/// Fingerprint statistics response.
#[derive(Serialize)]
struct FingerprintStatsResponse {
    total_fingerprints: i64,
    builtin_fingerprints: i64,
    user_fingerprints: i64,
    total_observations: i64,
    matched_observations: i64,
    unmatched_observations: i64,
    device_type_breakdown: Vec<DeviceTypeCount>,
}

/// Observation list query params.
#[derive(Deserialize)]
pub(crate) struct ObservationQuery {
    device_type: Option<String>,
    unmatched: Option<bool>,
    q: Option<String>,
    page: Option<i64>,
    limit: Option<i64>,
}

/// Paginated observation list response.
#[derive(Serialize)]
struct PaginatedObservations {
    data: Vec<ObservationResponse>,
    total: i64,
    page: i64,
    limit: i64,
}

/// Backfill response payload.
#[derive(Serialize)]
struct BackfillResponse {
    updated: u64,
}

/// Normalizes DHCP Option 55 string to sorted and deduplicated form.
///
/// Parameters: `raw` - raw option codes list.
/// Returns: normalized fingerprint string or `None` for invalid/empty input.
fn normalize_fingerprint(raw: &str) -> Option<String> {
    let mut codes: Vec<u16> = raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .filter(|&n| n > 0 && n <= 255)
        .collect();
    if codes.is_empty() {
        return None;
    }
    codes.sort_unstable();
    codes.dedup();
    Some(
        codes
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(","),
    )
}

/// Backfills mapping device types using DHCP observations by MAC.
///
/// Parameters: `pool` - SQLite connection pool.
/// Returns: number of updated mapping rows.
async fn backfill_device_types(pool: &sqlx::SqlitePool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE mappings SET device_type = (
            SELECT o.device_type FROM dhcp_observations o
            WHERE o.mac = mappings.mac AND o.device_type IS NOT NULL
         )
         WHERE mappings.mac IS NOT NULL
           AND EXISTS (
               SELECT 1 FROM dhcp_observations o
               WHERE o.mac = mappings.mac AND o.device_type IS NOT NULL
           )",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Lists all DHCP fingerprint definitions.
///
/// Parameters: `auth` - authenticated user, `state` - app state.
/// Returns: list of fingerprints.
pub(crate) async fn list_fingerprints(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let rows = sqlx::query(
        "SELECT id, fingerprint, device_type, os_family, description, source, created_at
         FROM dhcp_fingerprints
         ORDER BY source ASC, device_type ASC, fingerprint ASC",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to list fingerprints");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list fingerprints",
        )
        .with_request_id(&auth.request_id)
    })?;

    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        data.push(FingerprintResponse {
            id: row.try_get("id").unwrap_or_default(),
            fingerprint: row.try_get("fingerprint").unwrap_or_default(),
            device_type: row.try_get("device_type").unwrap_or_default(),
            os_family: row.try_get("os_family").ok(),
            description: row.try_get("description").ok(),
            source: row
                .try_get("source")
                .unwrap_or_else(|_| "builtin".to_string()),
            created_at: row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        });
    }
    Ok(Json(data))
}

/// Creates a custom fingerprint definition.
///
/// Parameters: `auth` - authenticated admin, `state` - app state, `req` - create payload.
/// Returns: created fingerprint.
pub(crate) async fn create_fingerprint(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateFingerprintRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let normalized = normalize_fingerprint(&req.fingerprint).ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Invalid fingerprint format",
        )
        .with_request_id(&auth.request_id)
    })?;
    if req.device_type.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "device_type is required",
        )
        .with_request_id(&auth.request_id));
    }

    let insert = sqlx::query(
        "INSERT INTO dhcp_fingerprints
         (fingerprint, device_type, os_family, description, source)
         VALUES (?, ?, ?, ?, 'user')",
    )
    .bind(&normalized)
    .bind(req.device_type.trim())
    .bind(req.os_family.as_deref().map(str::trim))
    .bind(req.description.as_deref().map(str::trim))
    .execute(db.pool())
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint failed") {
            ApiError::new(
                StatusCode::CONFLICT,
                error::CONFLICT,
                "Fingerprint already exists",
            )
            .with_request_id(&auth.request_id)
        } else {
            warn!(error = %e, "Failed to create fingerprint");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to create fingerprint",
            )
            .with_request_id(&auth.request_id)
        }
    })?;

    let id = insert.last_insert_rowid();
    let row = sqlx::query(
        "SELECT id, fingerprint, device_type, os_family, description, source, created_at
         FROM dhcp_fingerprints WHERE id = ?",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, id, "Failed to fetch created fingerprint");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to create fingerprint",
        )
        .with_request_id(&auth.request_id)
    })?;

    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "fingerprint_create",
            Some(&id.to_string()),
            Some(&normalized),
            None,
            Some(&auth.request_id),
        )
        .await;

    Ok((
        StatusCode::CREATED,
        Json(FingerprintResponse {
            id: row.try_get("id").unwrap_or_default(),
            fingerprint: row.try_get("fingerprint").unwrap_or_default(),
            device_type: row.try_get("device_type").unwrap_or_default(),
            os_family: row.try_get("os_family").ok(),
            description: row.try_get("description").ok(),
            source: row.try_get("source").unwrap_or_else(|_| "user".to_string()),
            created_at: row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        }),
    ))
}

/// Deletes user-defined fingerprint by ID.
///
/// Parameters: `auth` - authenticated admin, `id` - fingerprint id, `state` - app state.
/// Returns: HTTP 204 on success.
pub(crate) async fn delete_fingerprint(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let row = sqlx::query("SELECT source, fingerprint FROM dhcp_fingerprints WHERE id = ?")
        .bind(id)
        .fetch_optional(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, id, "Failed to load fingerprint for delete");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to delete fingerprint",
            )
            .with_request_id(&auth.request_id)
        })?;
    let Some(row) = row else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "Fingerprint not found",
        )
        .with_request_id(&auth.request_id));
    };
    let source: String = row
        .try_get("source")
        .unwrap_or_else(|_| "builtin".to_string());
    let fp_value: String = row.try_get("fingerprint").unwrap_or_default();
    if source != "user" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            error::FORBIDDEN,
            "Cannot delete built-in fingerprint",
        )
        .with_request_id(&auth.request_id));
    }

    sqlx::query("DELETE FROM dhcp_fingerprints WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, id, "Failed to delete fingerprint");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to delete fingerprint",
            )
            .with_request_id(&auth.request_id)
        })?;

    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "fingerprint_delete",
            Some(&id.to_string()),
            Some(&fp_value),
            None,
            Some(&auth.request_id),
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Returns fingerprint and observation statistics.
///
/// Parameters: `auth` - authenticated user, `state` - app state.
/// Returns: aggregate statistics payload.
pub(crate) async fn fingerprint_stats(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let pool = db.pool();

    let total_fingerprints: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dhcp_fingerprints")
        .fetch_one(pool)
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to load fingerprint stats");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to load fingerprint stats",
            )
            .with_request_id(&auth.request_id)
        })?;
    let builtin_fingerprints: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dhcp_fingerprints WHERE source = 'builtin'")
            .fetch_one(pool)
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to load fingerprint stats");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to load fingerprint stats",
                )
                .with_request_id(&auth.request_id)
            })?;
    let user_fingerprints: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dhcp_fingerprints WHERE source = 'user'")
            .fetch_one(pool)
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to load fingerprint stats");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to load fingerprint stats",
                )
                .with_request_id(&auth.request_id)
            })?;
    let total_observations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dhcp_observations")
        .fetch_one(pool)
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to load fingerprint stats");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to load fingerprint stats",
            )
            .with_request_id(&auth.request_id)
        })?;
    let matched_observations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dhcp_observations WHERE device_type IS NOT NULL")
            .fetch_one(pool)
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to load fingerprint stats");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to load fingerprint stats",
                )
                .with_request_id(&auth.request_id)
            })?;
    let unmatched_observations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dhcp_observations WHERE device_type IS NULL")
            .fetch_one(pool)
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to load fingerprint stats");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to load fingerprint stats",
                )
                .with_request_id(&auth.request_id)
            })?;

    let breakdown_rows = sqlx::query(
        "SELECT device_type, COUNT(*) as c
         FROM dhcp_observations
         WHERE device_type IS NOT NULL
         GROUP BY device_type
         ORDER BY c DESC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to load fingerprint breakdown");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to load fingerprint stats",
        )
        .with_request_id(&auth.request_id)
    })?;
    let device_type_breakdown = breakdown_rows
        .into_iter()
        .map(|row| DeviceTypeCount {
            device_type: row.try_get("device_type").unwrap_or_default(),
            count: row.try_get("c").unwrap_or(0),
        })
        .collect::<Vec<_>>();

    Ok(Json(FingerprintStatsResponse {
        total_fingerprints,
        builtin_fingerprints,
        user_fingerprints,
        total_observations,
        matched_observations,
        unmatched_observations,
        device_type_breakdown,
    }))
}

/// Lists DHCP observations with filters.
///
/// Parameters: `auth` - authenticated user, `q` - query filters, `state` - app state.
/// Returns: paginated observations.
pub(crate) async fn list_observations(
    auth: AuthUser,
    Query(q): Query<ObservationQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * limit;

    let mut where_parts = Vec::<String>::new();
    let mut binds = Vec::<String>::new();
    if let Some(device_type) = q.device_type.as_deref() {
        where_parts.push("device_type = ?".to_string());
        binds.push(device_type.to_string());
    }
    if q.unmatched.unwrap_or(false) {
        where_parts.push("device_type IS NULL".to_string());
    }
    if let Some(search) = q.q.as_deref() {
        where_parts.push("(mac LIKE ? OR hostname LIKE ?)".to_string());
        let like = format!("%{}%", search.trim());
        binds.push(like.clone());
        binds.push(like);
    }
    let where_clause = if where_parts.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_parts.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) as c FROM dhcp_observations {where_clause}");
    let mut count_q = sqlx::query(&count_sql);
    for bind in &binds {
        count_q = count_q.bind(bind);
    }
    let total: i64 = count_q
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to count observations");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to list observations",
            )
            .with_request_id(&auth.request_id)
        })?
        .try_get("c")
        .unwrap_or(0);

    let data_sql = format!(
        "SELECT mac, fingerprint, device_type, hostname, ip, observed_at, match_source
         FROM dhcp_observations
         {where_clause}
         ORDER BY observed_at DESC
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
            warn!(error = %e, "Failed to list observations");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to list observations",
            )
            .with_request_id(&auth.request_id)
        })?;

    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        data.push(ObservationResponse {
            mac: row.try_get("mac").unwrap_or_default(),
            fingerprint: row.try_get("fingerprint").unwrap_or_default(),
            device_type: row.try_get("device_type").ok(),
            hostname: row.try_get("hostname").ok(),
            ip: row.try_get("ip").ok(),
            observed_at: row.try_get("observed_at").unwrap_or_else(|_| Utc::now()),
            match_source: row.try_get("match_source").ok(),
        });
    }

    Ok(Json(PaginatedObservations {
        data,
        total,
        page,
        limit,
    }))
}

/// Re-runs mappings backfill from DHCP observations.
///
/// Parameters: `auth` - authenticated admin, `state` - app state.
/// Returns: number of updated mapping rows.
pub(crate) async fn backfill(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let updated = backfill_device_types(db.pool()).await.map_err(|e| {
        warn!(error = %e, "Failed to backfill device types");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to backfill device types",
        )
        .with_request_id(&auth.request_id)
    })?;

    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "fingerprint_backfill",
            None,
            Some(&format!("updated={updated}")),
            None,
            Some(&auth.request_id),
        )
        .await;

    Ok((StatusCode::OK, Json(BackfillResponse { updated })))
}
