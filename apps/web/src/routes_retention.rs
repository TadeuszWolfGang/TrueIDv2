//! Data retention policy API for admins.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tracing::warn;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::routes_proxy;
use crate::AppState;

/// Retention policy response row.
#[derive(Debug, Serialize)]
struct RetentionPolicyDto {
    table_name: String,
    retention_days: i64,
    enabled: bool,
    last_run_at: Option<String>,
    last_deleted_count: i64,
}

/// List response for retention policies.
#[derive(Debug, Serialize)]
struct RetentionPoliciesResponse {
    policies: Vec<RetentionPolicyDto>,
}

/// Retention policy update payload.
#[derive(Debug, Deserialize)]
pub(crate) struct UpdateRetentionPolicyRequest {
    retention_days: i64,
    enabled: bool,
}

/// One table stats row.
#[derive(Debug, Serialize)]
struct RetentionTableStats {
    table_name: String,
    row_count: i64,
    retention_days: i64,
    oldest_row: Option<String>,
}

/// Stats response payload.
#[derive(Debug, Serialize)]
struct RetentionStatsResponse {
    tables: Vec<RetentionTableStats>,
    database_size_bytes: i64,
}

/// Returns canonical timestamp column for each supported retention table.
///
/// Parameters: `table_name` - target table name.
/// Returns: timestamp column name if supported.
fn retention_timestamp_col(table_name: &str) -> Option<&'static str> {
    match table_name {
        "events" => Some("timestamp"),
        "conflicts" => Some("detected_at"),
        "alert_history" => Some("fired_at"),
        "audit_log" => Some("timestamp"),
        "notification_deliveries" => Some("delivered_at"),
        "firewall_push_history" => Some("pushed_at"),
        "report_snapshots" => Some("generated_at"),
        "dns_cache" => Some("resolved_at"),
        _ => None,
    }
}

/// Lists all retention policies.
///
/// Parameters: `auth` - authenticated admin, `state` - app state.
/// Returns: retention policy list.
pub(crate) async fn list_policies(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = sqlx::query(
        "SELECT table_name, retention_days, enabled, last_run_at, COALESCE(last_deleted_count, 0) as last_deleted_count
         FROM retention_policies
         ORDER BY table_name ASC",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to list retention policies");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list retention policies",
        )
        .with_request_id(&auth.request_id)
    })?;

    let mut policies = Vec::with_capacity(rows.len());
    for row in rows {
        policies.push(RetentionPolicyDto {
            table_name: row.try_get("table_name").unwrap_or_default(),
            retention_days: row.try_get("retention_days").unwrap_or(90),
            enabled: row.try_get("enabled").unwrap_or(true),
            last_run_at: row.try_get("last_run_at").ok(),
            last_deleted_count: row.try_get("last_deleted_count").unwrap_or(0),
        });
    }
    Ok(Json(RetentionPoliciesResponse { policies }))
}

/// Updates one retention policy.
///
/// Parameters: `auth` - authenticated admin, `table_name` - policy table key, `state` - app state, `body` - update payload.
/// Returns: updated policy.
pub(crate) async fn update_policy(
    auth: AuthUser,
    Path(table_name): Path<String>,
    State(state): State<AppState>,
    Json(body): Json<UpdateRetentionPolicyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    if retention_timestamp_col(&table_name).is_none() {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "Unknown retention policy table",
        )
        .with_request_id(&auth.request_id));
    }
    if body.retention_days < 1 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "retention_days must be >= 1",
        )
        .with_request_id(&auth.request_id));
    }
    if table_name == "audit_log" && body.retention_days < 30 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "audit_log retention_days must be >= 30",
        )
        .with_request_id(&auth.request_id));
    }
    if table_name == "audit_log" && !body.enabled {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "audit_log retention cannot be disabled",
        )
        .with_request_id(&auth.request_id));
    }

    let result = sqlx::query(
        "UPDATE retention_policies
         SET retention_days = ?, enabled = ?, updated_at = datetime('now')
         WHERE table_name = ?",
    )
    .bind(body.retention_days)
    .bind(body.enabled)
    .bind(&table_name)
    .execute(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, table = %table_name, "Failed to update retention policy");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to update retention policy",
        )
        .with_request_id(&auth.request_id)
    })?;
    if result.rows_affected() == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "Retention policy not found",
        )
        .with_request_id(&auth.request_id));
    }
    helpers::audit(
        db,
        &auth,
        "update_retention_policy",
        Some(&table_name),
        Some(&format!(
            "retention_days={}, enabled={}",
            body.retention_days, body.enabled
        )),
    )
    .await;

    let row = sqlx::query(
        "SELECT table_name, retention_days, enabled, last_run_at, COALESCE(last_deleted_count, 0) as last_deleted_count
         FROM retention_policies
         WHERE table_name = ?",
    )
    .bind(&table_name)
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, table = %table_name, "Failed to fetch updated retention policy");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to update retention policy",
        )
        .with_request_id(&auth.request_id)
    })?;
    Ok(Json(RetentionPolicyDto {
        table_name: row.try_get("table_name").unwrap_or_default(),
        retention_days: row.try_get("retention_days").unwrap_or(90),
        enabled: row.try_get("enabled").unwrap_or(true),
        last_run_at: row.try_get("last_run_at").ok(),
        last_deleted_count: row.try_get("last_deleted_count").unwrap_or(0),
    }))
}

/// Forces retention run immediately using engine executor.
///
/// Parameters: `auth` - authenticated admin, `state` - app state.
/// Returns: engine retention run result payload.
pub(crate) async fn run_now(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let response =
        routes_proxy::proxy_to_engine(&state, reqwest::Method::POST, "/engine/retention/run", None)
            .await
            .map_err(|_| {
                ApiError::new(
                    StatusCode::BAD_GATEWAY,
                    error::SERVICE_UNAVAILABLE,
                    "Engine retention executor unavailable",
                )
                .with_request_id(&auth.request_id)
            })?;
    helpers::audit(db, &auth, "run_retention_now", None, None).await;
    Ok(response)
}

/// Returns row counts, oldest timestamps, and DB size for retention-managed tables.
///
/// Parameters: `auth` - authenticated admin, `state` - app state.
/// Returns: retention stats payload.
pub(crate) async fn stats(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = sqlx::query(
        "SELECT table_name, retention_days
         FROM retention_policies
         ORDER BY table_name ASC",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to read retention policies for stats");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to load retention stats",
        )
        .with_request_id(&auth.request_id)
    })?;
    let mut tables = Vec::with_capacity(rows.len());
    for row in rows {
        let table_name: String = row.try_get("table_name").unwrap_or_default();
        let retention_days: i64 = row.try_get("retention_days").unwrap_or(90);
        let Some(ts_col) = retention_timestamp_col(&table_name) else {
            continue;
        };
        let count_sql = format!("SELECT COUNT(*) as c FROM {table_name}");
        let count_row = sqlx::query(&count_sql)
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, table = %table_name, "Failed to count retention table rows");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to load retention stats",
                )
                .with_request_id(&auth.request_id)
            })?;
        let oldest_sql = format!("SELECT MIN({ts_col}) as oldest FROM {table_name}");
        let oldest_row = sqlx::query(&oldest_sql)
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, table = %table_name, "Failed to read oldest row timestamp");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to load retention stats",
                )
                .with_request_id(&auth.request_id)
            })?;
        tables.push(RetentionTableStats {
            table_name,
            row_count: count_row.try_get("c").unwrap_or(0),
            retention_days,
            oldest_row: oldest_row.try_get("oldest").ok(),
        });
    }

    let page_count: i64 = sqlx::query_scalar("SELECT page_count FROM pragma_page_count")
        .fetch_one(db.pool())
        .await
        .unwrap_or(0);
    let page_size: i64 = sqlx::query_scalar("SELECT page_size FROM pragma_page_size")
        .fetch_one(db.pool())
        .await
        .unwrap_or(0);
    Ok(Json(RetentionStatsResponse {
        tables,
        database_size_bytes: page_count.saturating_mul(page_size),
    }))
}
