//! Audit log viewing endpoints (Admin only, read-only).
//!
//! The audit_log table is append-only by design — no DELETE/UPDATE endpoints.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;
use trueid_common::pagination::PaginationParams;

// ── Query / Response types ──────────────────────────────────

#[derive(Deserialize)]
pub struct AuditLogsQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub action: Option<String>,
    pub username: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
}

#[derive(Serialize)]
struct AuditLogsResponse {
    entries: Vec<AuditEntryDto>,
    total: i64,
    page: u32,
    per_page: u32,
}

#[derive(Serialize)]
struct AuditEntryDto {
    id: i64,
    timestamp: String,
    user_id: Option<i64>,
    username: String,
    principal_type: String,
    action: String,
    target: Option<String>,
    details: Option<String>,
    ip_address: Option<String>,
    request_id: Option<String>,
}

#[derive(Serialize)]
struct ActionCount {
    action: String,
    count: i64,
}

#[derive(Serialize)]
struct AuditStatsResponse {
    total: i64,
    last_24h: i64,
    last_7d: i64,
    top_actions: Vec<ActionCount>,
}

// ── GET /api/v1/audit-logs ──────────────────────────────────

/// Returns paginated audit log entries with optional filters.
///
/// Query params: page, per_page (max 200), action, username, since, until.
/// Returns: paginated list with total count.
pub async fn list_audit_logs(
    auth: AuthUser,
    State(state): State<AppState>,
    Query(params): Query<AuditLogsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let pagination = PaginationParams {
        page: params.page,
        limit: params.per_page,
    };
    let page = pagination.page_or(1);
    let per_page = pagination.limit_or(50, 200);
    let offset = pagination.offset(50, 200);
    let limit = i64::from(per_page);

    let total = db
        .count_audit_logs_filtered(
            params.action.as_deref(),
            params.username.as_deref(),
            params.since.as_deref(),
            params.until.as_deref(),
        )
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Audit log count failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to count audit logs",
            )
            .with_request_id(&auth.request_id)
        })?;

    let entries = db
        .query_audit_logs(
            limit,
            offset,
            params.action.as_deref(),
            params.username.as_deref(),
            params.since.as_deref(),
            params.until.as_deref(),
        )
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Audit log query failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to query audit logs",
            )
            .with_request_id(&auth.request_id)
        })?;

    let dtos: Vec<AuditEntryDto> = entries
        .into_iter()
        .map(|e| AuditEntryDto {
            id: e.id,
            timestamp: e.timestamp.to_rfc3339(),
            user_id: e.user_id,
            username: e.username,
            principal_type: e.principal_type,
            action: e.action,
            target: e.target,
            details: e.details,
            ip_address: e.ip_address,
            request_id: e.request_id,
        })
        .collect();

    Ok(Json(AuditLogsResponse {
        entries: dtos,
        total,
        page,
        per_page,
    }))
}

// ── GET /api/v1/audit-logs/stats ────────────────────────────

/// Returns audit log statistics: totals and top actions.
pub async fn audit_stats(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let (total, last_24h, last_7d, top) = db.audit_stats().await.map_err(|e| {
        tracing::warn!(error = %e, "Audit stats query failed");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to get audit stats",
        )
        .with_request_id(&auth.request_id)
    })?;

    Ok(Json(AuditStatsResponse {
        total,
        last_24h,
        last_7d,
        top_actions: top
            .into_iter()
            .map(|(action, count)| ActionCount { action, count })
            .collect(),
    }))
}
