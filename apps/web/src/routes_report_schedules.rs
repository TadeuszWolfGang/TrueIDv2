//! Scheduled report configuration API.

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
use crate::AppState;

/// DTO returned by schedule list/detail endpoints.
#[derive(Debug, Serialize)]
pub struct ReportScheduleDto {
    id: i64,
    name: String,
    report_type: String,
    schedule_cron: String,
    enabled: bool,
    channel_ids: Vec<i64>,
    include_sections: Vec<String>,
    last_sent_at: Option<String>,
    created_by: Option<i64>,
    created_at: String,
    updated_at: String,
}

/// Create/update payload for report schedule.
#[derive(Debug, Deserialize)]
pub struct UpsertReportScheduleRequest {
    name: String,
    report_type: String,
    schedule_cron: String,
    enabled: Option<bool>,
    channel_ids: Option<Vec<i64>>,
    include_sections: Option<Vec<String>>,
}

/// Validates simple cron format `min hour * * dow`.
///
/// Parameters: `cron` - cron string.
/// Returns: true when valid.
fn is_valid_simple_cron(cron: &str) -> bool {
    let parts = cron.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 5 {
        return false;
    }
    let Ok(minute) = parts[0].parse::<u32>() else {
        return false;
    };
    let Ok(hour) = parts[1].parse::<u32>() else {
        return false;
    };
    let Ok(dow) = parts[4].parse::<u32>() else {
        return false;
    };
    minute <= 59 && hour <= 23 && dow <= 6 && parts[2] == "*" && parts[3] == "*"
}

/// Validates report sections set.
///
/// Parameters: `sections` - section names.
/// Returns: true when all values are supported.
fn valid_sections(sections: &[String]) -> bool {
    sections.iter().all(|s| {
        matches!(
            s.as_str(),
            "summary" | "conflicts" | "alerts" | "compliance" | "top_users" | "top_ips"
        )
    })
}

/// Maps DB row to schedule DTO.
///
/// Parameters: `row` - sql row.
/// Returns: parsed schedule.
fn map_schedule_row(row: &sqlx::sqlite::SqliteRow) -> ReportScheduleDto {
    let channel_ids_raw: String = row.try_get("channel_ids").unwrap_or_else(|_| "[]".into());
    let include_sections_raw: String = row
        .try_get("include_sections")
        .unwrap_or_else(|_| "[\"summary\",\"conflicts\",\"alerts\"]".into());
    ReportScheduleDto {
        id: row.try_get("id").unwrap_or_default(),
        name: row.try_get("name").unwrap_or_default(),
        report_type: row
            .try_get("report_type")
            .unwrap_or_else(|_| "daily".to_string()),
        schedule_cron: row
            .try_get("schedule_cron")
            .unwrap_or_else(|_| "0 8 * * 1".to_string()),
        enabled: row.try_get("enabled").unwrap_or(true),
        channel_ids: serde_json::from_str(&channel_ids_raw).unwrap_or_default(),
        include_sections: serde_json::from_str(&include_sections_raw).unwrap_or_else(|_| {
            vec![
                "summary".to_string(),
                "conflicts".to_string(),
                "alerts".to_string(),
            ]
        }),
        last_sent_at: row.try_get("last_sent_at").ok(),
        created_by: row.try_get("created_by").ok(),
        created_at: row.try_get("created_at").unwrap_or_default(),
        updated_at: row.try_get("updated_at").unwrap_or_default(),
    }
}

/// Lists report schedules.
///
/// Parameters: `auth` - authenticated admin, `state` - app state.
/// Returns: schedule list.
pub(crate) async fn list_schedules(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = sqlx::query(
        "SELECT id, name, report_type, schedule_cron, enabled, channel_ids, include_sections,
                last_sent_at, created_by, created_at, updated_at
         FROM report_schedules
         ORDER BY id DESC",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to list report schedules");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list report schedules",
        )
        .with_request_id(&auth.request_id)
    })?;
    let schedules = rows.iter().map(map_schedule_row).collect::<Vec<_>>();
    Ok(Json(serde_json::json!({ "schedules": schedules })))
}

/// Creates report schedule.
///
/// Parameters: `auth` - authenticated admin, `state` - app state, `body` - create payload.
/// Returns: created schedule.
pub(crate) async fn create_schedule(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<UpsertReportScheduleRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "name cannot be empty",
        )
        .with_request_id(&auth.request_id));
    }
    if !matches!(body.report_type.as_str(), "daily" | "weekly" | "compliance") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "report_type must be one of: daily, weekly, compliance",
        )
        .with_request_id(&auth.request_id));
    }
    if !is_valid_simple_cron(body.schedule_cron.trim()) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "schedule_cron must follow: 'min hour * * dow'",
        )
        .with_request_id(&auth.request_id));
    }
    let channel_ids = body.channel_ids.unwrap_or_default();
    let include_sections = body.include_sections.unwrap_or_else(|| {
        vec![
            "summary".to_string(),
            "conflicts".to_string(),
            "alerts".to_string(),
        ]
    });
    if !valid_sections(&include_sections) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "include_sections contains unsupported section",
        )
        .with_request_id(&auth.request_id));
    }
    let channel_ids_json = serde_json::to_string(&channel_ids).unwrap_or_else(|_| "[]".to_string());
    let include_sections_json =
        serde_json::to_string(&include_sections).unwrap_or_else(|_| "[]".to_string());

    let created = sqlx::query(
        "INSERT INTO report_schedules
         (name, report_type, schedule_cron, enabled, channel_ids, include_sections, created_by, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))",
    )
    .bind(name)
    .bind(&body.report_type)
    .bind(body.schedule_cron.trim())
    .bind(body.enabled.unwrap_or(true))
    .bind(channel_ids_json)
    .bind(include_sections_json)
    .bind(auth.user_id)
    .execute(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to create report schedule");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to create report schedule",
        )
        .with_request_id(&auth.request_id)
    })?;
    let id = created.last_insert_rowid();
    helpers::audit(
        db,
        &auth,
        "create_report_schedule",
        Some(&id.to_string()),
        Some(name),
    )
    .await;

    let row = sqlx::query(
        "SELECT id, name, report_type, schedule_cron, enabled, channel_ids, include_sections,
                last_sent_at, created_by, created_at, updated_at
         FROM report_schedules
         WHERE id = ?",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, schedule_id = id, "Failed to load created report schedule");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to create report schedule",
        )
        .with_request_id(&auth.request_id)
    })?;
    Ok((StatusCode::CREATED, Json(map_schedule_row(&row))))
}

/// Updates report schedule.
///
/// Parameters: `auth` - authenticated admin, `id` - schedule id, `state` - app state, `body` - update payload.
/// Returns: updated schedule.
pub(crate) async fn update_schedule(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(body): Json<UpsertReportScheduleRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let name = body.name.trim();
    if name.is_empty()
        || !matches!(body.report_type.as_str(), "daily" | "weekly" | "compliance")
        || !is_valid_simple_cron(body.schedule_cron.trim())
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Invalid schedule payload",
        )
        .with_request_id(&auth.request_id));
    }
    let channel_ids = body.channel_ids.unwrap_or_default();
    let include_sections = body.include_sections.unwrap_or_else(|| {
        vec![
            "summary".to_string(),
            "conflicts".to_string(),
            "alerts".to_string(),
        ]
    });
    if !valid_sections(&include_sections) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "include_sections contains unsupported section",
        )
        .with_request_id(&auth.request_id));
    }

    let updated = sqlx::query(
        "UPDATE report_schedules
         SET name = ?, report_type = ?, schedule_cron = ?, enabled = ?, channel_ids = ?, include_sections = ?, updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(name)
    .bind(&body.report_type)
    .bind(body.schedule_cron.trim())
    .bind(body.enabled.unwrap_or(true))
    .bind(serde_json::to_string(&channel_ids).unwrap_or_else(|_| "[]".to_string()))
    .bind(serde_json::to_string(&include_sections).unwrap_or_else(|_| "[]".to_string()))
    .bind(id)
    .execute(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, schedule_id = id, "Failed to update report schedule");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to update report schedule",
        )
        .with_request_id(&auth.request_id)
    })?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "Report schedule not found",
        )
        .with_request_id(&auth.request_id));
    }

    helpers::audit(
        db,
        &auth,
        "update_report_schedule",
        Some(&id.to_string()),
        Some(name),
    )
    .await;

    let row = sqlx::query(
        "SELECT id, name, report_type, schedule_cron, enabled, channel_ids, include_sections,
                last_sent_at, created_by, created_at, updated_at
         FROM report_schedules
         WHERE id = ?",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, schedule_id = id, "Failed to load updated report schedule");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to update report schedule",
        )
        .with_request_id(&auth.request_id)
    })?;
    Ok(Json(map_schedule_row(&row)))
}

/// Deletes report schedule.
///
/// Parameters: `auth` - authenticated admin, `id` - schedule id, `state` - app state.
/// Returns: no-content.
pub(crate) async fn delete_schedule(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let deleted = sqlx::query("DELETE FROM report_schedules WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, schedule_id = id, "Failed to delete report schedule");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to delete report schedule",
            )
            .with_request_id(&auth.request_id)
        })?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "Report schedule not found",
        )
        .with_request_id(&auth.request_id));
    }
    helpers::audit(
        db,
        &auth,
        "delete_report_schedule",
        Some(&id.to_string()),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Triggers immediate schedule delivery through engine API.
///
/// Parameters: `auth` - authenticated admin, `id` - schedule id, `state` - app state.
/// Returns: send status payload.
pub(crate) async fn send_now(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<axum::response::Response, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let schedule_row = sqlx::query("SELECT channel_ids FROM report_schedules WHERE id = ?")
        .bind(id)
        .fetch_optional(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, schedule_id = id, "Failed to load schedule before send-now");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to send report schedule",
            )
            .with_request_id(&auth.request_id)
        })?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                error::NOT_FOUND,
                "Report schedule not found",
            )
            .with_request_id(&auth.request_id)
        })?;
    let channel_ids_raw: String = schedule_row.try_get("channel_ids").unwrap_or_default();
    let channel_ids = serde_json::from_str::<Vec<i64>>(&channel_ids_raw).unwrap_or_default();

    if channel_ids.is_empty() {
        let payload = serde_json::json!({
            "success": true,
            "delivered": 0,
            "attempted": 0
        });
        helpers::audit(
            db,
            &auth,
            "send_now_report_schedule",
            Some(&id.to_string()),
            Some("no channels configured"),
        )
        .await;
        return Ok(Json(payload).into_response());
    }

    let path = format!("/engine/reports/schedules/{id}/send-now");
    let response = crate::routes_proxy::proxy_to_engine(&state, reqwest::Method::POST, &path, None)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                error::SERVICE_UNAVAILABLE,
                "Engine report send-now endpoint unavailable",
            )
            .with_request_id(&auth.request_id)
        })?;
    helpers::audit(
        db,
        &auth,
        "send_now_report_schedule",
        Some(&id.to_string()),
        None,
    )
    .await;
    Ok(response.into_response())
}
