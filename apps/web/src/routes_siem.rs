//! SIEM targets API (CRUD + stats).

use axum::{
    extract::{Path, State},
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

/// SIEM target response payload.
#[derive(Serialize)]
pub(crate) struct SiemTargetResponse {
    id: i64,
    name: String,
    format: String,
    transport: String,
    host: String,
    port: i64,
    enabled: bool,
    forward_mappings: bool,
    forward_conflicts: bool,
    forward_alerts: bool,
    last_forward_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    events_forwarded: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// SIEM target create payload.
#[derive(Deserialize)]
pub(crate) struct CreateSiemTargetRequest {
    name: String,
    format: String,
    transport: String,
    host: String,
    port: i64,
    enabled: Option<bool>,
    forward_mappings: Option<bool>,
    forward_conflicts: Option<bool>,
    forward_alerts: Option<bool>,
}

/// SIEM target update payload.
#[derive(Deserialize)]
pub(crate) struct UpdateSiemTargetRequest {
    name: Option<String>,
    format: Option<String>,
    transport: Option<String>,
    host: Option<String>,
    port: Option<i64>,
    enabled: Option<bool>,
    forward_mappings: Option<bool>,
    forward_conflicts: Option<bool>,
    forward_alerts: Option<bool>,
}

/// SIEM aggregate stats payload.
#[derive(Serialize)]
pub(crate) struct SiemStatsResponse {
    total_targets: i64,
    enabled_targets: i64,
    total_events_forwarded: i64,
    targets_with_error: i64,
}

/// Validates SIEM target format.
///
/// Parameters: `value` - requested format, `request_id` - correlation id.
/// Returns: validation result.
fn validate_format(value: &str, request_id: &str) -> Result<(), ApiError> {
    if matches!(value, "cef" | "leef" | "json") {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "format must be one of: cef, leef, json",
        )
        .with_request_id(request_id))
    }
}

/// Validates SIEM target transport.
///
/// Parameters: `value` - requested transport, `request_id` - correlation id.
/// Returns: validation result.
fn validate_transport(value: &str, request_id: &str) -> Result<(), ApiError> {
    if matches!(value, "udp" | "tcp") {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "transport must be one of: udp, tcp",
        )
        .with_request_id(request_id))
    }
}

/// Validates host and port.
///
/// Parameters: `host` - destination host, `port` - destination port, `request_id` - correlation id.
/// Returns: validation result.
fn validate_host_port(host: &str, port: i64, request_id: &str) -> Result<(), ApiError> {
    if host.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "host cannot be empty",
        )
        .with_request_id(request_id));
    }
    if !(1..=65535).contains(&port) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "port must be in range 1..65535",
        )
        .with_request_id(request_id));
    }
    Ok(())
}

/// Maps DB row to API target response.
///
/// Parameters: `row` - sqlite row.
/// Returns: mapped response DTO.
fn map_row(row: &sqlx::sqlite::SqliteRow) -> SiemTargetResponse {
    SiemTargetResponse {
        id: row.try_get("id").unwrap_or_default(),
        name: row.try_get("name").unwrap_or_default(),
        format: row.try_get("format").unwrap_or_default(),
        transport: row.try_get("transport").unwrap_or_default(),
        host: row.try_get("host").unwrap_or_default(),
        port: row.try_get("port").unwrap_or(514),
        enabled: row.try_get("enabled").unwrap_or(true),
        forward_mappings: row.try_get("forward_mappings").unwrap_or(true),
        forward_conflicts: row.try_get("forward_conflicts").unwrap_or(true),
        forward_alerts: row.try_get("forward_alerts").unwrap_or(true),
        last_forward_at: row.try_get("last_forward_at").ok(),
        last_error: row.try_get("last_error").ok(),
        events_forwarded: row.try_get("events_forwarded").unwrap_or_default(),
        created_at: row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        updated_at: row.try_get("updated_at").unwrap_or_else(|_| Utc::now()),
    }
}

/// Lists all SIEM targets.
///
/// Parameters: `auth` - authenticated user, `state` - app state.
/// Returns: SIEM target list.
pub(crate) async fn list_targets(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = sqlx::query(
        "SELECT id, name, format, transport, host, port, enabled,
                forward_mappings, forward_conflicts, forward_alerts,
                last_forward_at, last_error, events_forwarded, created_at, updated_at
         FROM siem_targets
         ORDER BY name ASC",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to list SIEM targets");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list SIEM targets",
        )
        .with_request_id(&auth.request_id)
    })?;
    Ok(Json(rows.iter().map(map_row).collect::<Vec<_>>()))
}

/// Gets one SIEM target by id.
///
/// Parameters: `auth` - authenticated user, `id` - target id, `state` - app state.
/// Returns: SIEM target details.
pub(crate) async fn get_target(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let row = sqlx::query(
        "SELECT id, name, format, transport, host, port, enabled,
                forward_mappings, forward_conflicts, forward_alerts,
                last_forward_at, last_error, events_forwarded, created_at, updated_at
         FROM siem_targets
         WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, target_id = id, "Failed to fetch SIEM target");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to fetch SIEM target",
        )
        .with_request_id(&auth.request_id)
    })?;
    match row {
        Some(row) => Ok(Json(map_row(&row)).into_response()),
        None => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "SIEM target not found",
        )
        .with_request_id(&auth.request_id)),
    }
}

/// Creates a SIEM target.
///
/// Parameters: `auth` - authenticated admin, `state` - app state, `req` - create payload.
/// Returns: created SIEM target.
pub(crate) async fn create_target(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateSiemTargetRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_format(req.format.trim(), &auth.request_id)?;
    validate_transport(req.transport.trim(), &auth.request_id)?;
    validate_host_port(req.host.trim(), req.port, &auth.request_id)?;
    if req.name.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "name cannot be empty",
        )
        .with_request_id(&auth.request_id));
    }

    let db = helpers::require_db(&state, &auth.request_id)?;
    let result = sqlx::query(
        "INSERT INTO siem_targets
         (name, format, transport, host, port, enabled, forward_mappings, forward_conflicts, forward_alerts)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(req.name.trim())
    .bind(req.format.trim())
    .bind(req.transport.trim())
    .bind(req.host.trim())
    .bind(req.port)
    .bind(req.enabled.unwrap_or(true))
    .bind(req.forward_mappings.unwrap_or(true))
    .bind(req.forward_conflicts.unwrap_or(true))
    .bind(req.forward_alerts.unwrap_or(true))
    .execute(db.pool())
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("UNIQUE constraint failed") {
            ApiError::new(
                StatusCode::CONFLICT,
                error::CONFLICT,
                "Target with this host and port already exists",
            )
            .with_request_id(&auth.request_id)
        } else {
            warn!(error = %e, "Failed to create SIEM target");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to create SIEM target",
            )
            .with_request_id(&auth.request_id)
        }
    })?;

    let id = result.last_insert_rowid();
    helpers::audit(
        db,
        &auth,
        "siem_target_create",
        Some(&id.to_string()),
        Some(req.name.trim()),
    )
    .await;

    get_target(auth, Path(id), State(state)).await
}

/// Updates SIEM target fields.
///
/// Parameters: `auth` - authenticated admin, `id` - target id, `state` - app state, `req` - update payload.
/// Returns: updated SIEM target.
pub(crate) async fn update_target(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(req): Json<UpdateSiemTargetRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let existing =
        sqlx::query("SELECT format, transport, host, port, name FROM siem_targets WHERE id = ?")
            .bind(id)
            .fetch_optional(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, target_id = id, "Failed to load SIEM target for update");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to update SIEM target",
                )
                .with_request_id(&auth.request_id)
            })?;
    let Some(existing) = existing else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "SIEM target not found",
        )
        .with_request_id(&auth.request_id));
    };

    let existing_format: String = existing
        .try_get("format")
        .unwrap_or_else(|_| "cef".to_string());
    let existing_transport: String = existing
        .try_get("transport")
        .unwrap_or_else(|_| "udp".to_string());
    let existing_host: String = existing.try_get("host").unwrap_or_default();
    let existing_port: i64 = existing.try_get("port").unwrap_or(514);
    let existing_name: String = existing.try_get("name").unwrap_or_default();

    let format = req.format.clone().unwrap_or(existing_format);
    let transport = req.transport.clone().unwrap_or(existing_transport);
    let host = req.host.clone().unwrap_or(existing_host);
    let port = req.port.unwrap_or(existing_port);
    let name = req.name.clone().unwrap_or(existing_name);

    validate_format(&format, &auth.request_id)?;
    validate_transport(&transport, &auth.request_id)?;
    validate_host_port(&host, port, &auth.request_id)?;
    if name.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "name cannot be empty",
        )
        .with_request_id(&auth.request_id));
    }

    sqlx::query(
        "UPDATE siem_targets
         SET name = COALESCE(?, name),
             format = COALESCE(?, format),
             transport = COALESCE(?, transport),
             host = COALESCE(?, host),
             port = COALESCE(?, port),
             enabled = COALESCE(?, enabled),
             forward_mappings = COALESCE(?, forward_mappings),
             forward_conflicts = COALESCE(?, forward_conflicts),
             forward_alerts = COALESCE(?, forward_alerts),
             updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(req.name.as_deref().map(str::trim))
    .bind(req.format.as_deref().map(str::trim))
    .bind(req.transport.as_deref().map(str::trim))
    .bind(req.host.as_deref().map(str::trim))
    .bind(req.port)
    .bind(req.enabled)
    .bind(req.forward_mappings)
    .bind(req.forward_conflicts)
    .bind(req.forward_alerts)
    .bind(id)
    .execute(db.pool())
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("UNIQUE constraint failed") {
            ApiError::new(
                StatusCode::CONFLICT,
                error::CONFLICT,
                "Target with this host and port already exists",
            )
            .with_request_id(&auth.request_id)
        } else {
            warn!(error = %e, target_id = id, "Failed to update SIEM target");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to update SIEM target",
            )
            .with_request_id(&auth.request_id)
        }
    })?;

    helpers::audit(db, &auth, "siem_target_update", Some(&id.to_string()), None).await;

    get_target(auth, Path(id), State(state)).await
}

/// Deletes SIEM target.
///
/// Parameters: `auth` - authenticated admin, `id` - target id, `state` - app state.
/// Returns: HTTP 204 on success.
pub(crate) async fn delete_target(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let result = sqlx::query("DELETE FROM siem_targets WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, target_id = id, "Failed to delete SIEM target");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to delete SIEM target",
            )
            .with_request_id(&auth.request_id)
        })?;
    if result.rows_affected() == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "SIEM target not found",
        )
        .with_request_id(&auth.request_id));
    }

    helpers::audit(db, &auth, "siem_target_delete", Some(&id.to_string()), None).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Returns SIEM forwarding statistics.
///
/// Parameters: `auth` - authenticated user, `state` - app state.
/// Returns: SIEM stats.
pub(crate) async fn siem_stats(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let total_targets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM siem_targets")
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to count SIEM targets");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to read SIEM stats",
            )
            .with_request_id(&auth.request_id)
        })?;
    let enabled_targets: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM siem_targets WHERE enabled = 1")
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to count enabled SIEM targets");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to read SIEM stats",
                )
                .with_request_id(&auth.request_id)
            })?;
    let total_events_forwarded: i64 =
        sqlx::query_scalar("SELECT COALESCE(SUM(events_forwarded), 0) FROM siem_targets")
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to sum forwarded SIEM events");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to read SIEM stats",
                )
                .with_request_id(&auth.request_id)
            })?;
    let targets_with_error: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM siem_targets WHERE last_error IS NOT NULL AND last_error != ''",
    )
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to count SIEM targets with errors");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to read SIEM stats",
        )
        .with_request_id(&auth.request_id)
    })?;

    Ok(Json(SiemStatsResponse {
        total_targets,
        enabled_targets,
        total_events_forwarded,
        targets_with_error,
    }))
}
