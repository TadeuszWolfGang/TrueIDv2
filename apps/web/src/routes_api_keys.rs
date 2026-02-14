//! API key management endpoints (Admin only — enforced by router-level middleware).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;
use trueid_common::model::{ApiKeyRecord, UserRole};

// ── Request / response types ───────────────────────────────

#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    #[serde(alias = "name")]
    pub description: String,
    pub role: UserRole,
    pub expires_in_days: Option<i64>,
    pub rate_limit_rpm: Option<i64>,
    pub rate_limit_burst: Option<i64>,
}

#[derive(Serialize)]
struct CreateApiKeyResponse {
    key: String,
    notice: &'static str,
    record: ApiKeyRecord,
}

#[derive(Deserialize)]
pub struct UsageQuery {
    pub days: Option<i64>,
}

#[derive(Deserialize)]
pub struct UpdateLimitsRequest {
    pub rate_limit_rpm: i64,
    pub rate_limit_burst: i64,
}

#[derive(Serialize)]
struct UsageRow {
    hour: String,
    requests: i64,
    errors: i64,
}

#[derive(Serialize)]
struct ApiKeyUsageResponse {
    key_id: i64,
    key_name: String,
    rate_limit_rpm: i64,
    usage: Vec<UsageRow>,
    total_requests_7d: i64,
    total_errors_7d: i64,
}

// ── GET /api/v1/api-keys ───────────────────────────────────

/// Lists all API keys (hash never exposed).
pub async fn list_keys(
    _auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &_auth.request_id)?;

    let keys = db.list_api_keys().await.map_err(|e| {
        warn!(error = %e, "Failed to list API keys");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list API keys",
        )
    })?;

    Ok(Json(keys))
}

// ── POST /api/v1/api-keys ──────────────────────────────────

/// Creates a new API key. Returns the raw key (only time visible).
pub async fn create_key(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<CreateApiKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if body.description.is_empty() || body.description.len() > 200 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Description must be 1-200 characters",
        )
        .with_request_id(&auth.request_id));
    }
    let rpm = body.rate_limit_rpm.unwrap_or(100);
    let burst = body.rate_limit_burst.unwrap_or(20);
    if !(1..=10_000).contains(&rpm) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "rate_limit_rpm must be in range 1..=10000",
        )
        .with_request_id(&auth.request_id));
    }
    if !(1..=1_000).contains(&burst) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "rate_limit_burst must be in range 1..=1000",
        )
        .with_request_id(&auth.request_id));
    }

    let db = helpers::require_db(&state, &auth.request_id)?;

    let expires_at = body
        .expires_in_days
        .map(|days| chrono::Utc::now() + chrono::Duration::days(days));

    let (raw_key, record) = db
        .create_api_key(
            &body.description,
            body.role,
            auth.user_id,
            expires_at,
            rpm,
            burst,
        )
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to create API key");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to create API key",
            )
        })?;

    let target_id = format!("api_key:{}", record.id);
    let details =
        serde_json::json!({"role": body.role.to_string(), "description": body.description})
            .to_string();
    helpers::audit(
        db,
        &auth,
        "api_key_created",
        Some(&target_id),
        Some(&details),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            key: raw_key,
            notice: "Store this key securely — it will not be shown again.",
            record,
        }),
    ))
}

// ── DELETE /api/v1/api-keys/{id} ───────────────────────────

/// Revokes an API key (soft delete: is_active = false).
pub async fn revoke_key(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let revoked = db.revoke_api_key(id).await.map_err(|e| {
        warn!(error = %e, "Failed to revoke API key");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to revoke API key",
        )
    })?;

    if !revoked {
        return Err(
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "API key not found")
                .with_request_id(&auth.request_id),
        );
    }

    let target_id = format!("api_key:{id}");
    helpers::audit(db, &auth, "api_key_revoked", Some(&target_id), None).await;

    Ok(StatusCode::OK)
}

/// Returns hourly API usage for one key.
pub async fn get_usage(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(query): Query<UsageQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let days = query.days.unwrap_or(7).clamp(1, 30);
    let key = db
        .get_api_key_by_id(id)
        .await
        .map_err(|e| {
            warn!(error = %e, key_id = id, "Failed to load API key usage");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to load API key",
            )
        })?
        .ok_or_else(|| {
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "API key not found")
                .with_request_id(&auth.request_id)
        })?;
    let usage = db.list_api_key_usage_hourly(id, days).await.map_err(|e| {
        warn!(error = %e, key_id = id, "Failed to query API key usage rows");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query API usage",
        )
    })?;
    let (total_requests, total_errors) = db.sum_api_key_usage(id, days).await.map_err(|e| {
        warn!(error = %e, key_id = id, "Failed to summarize API key usage");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to summarize API usage",
        )
    })?;

    let response = ApiKeyUsageResponse {
        key_id: id,
        key_name: key.description,
        rate_limit_rpm: key.rate_limit_rpm,
        usage: usage
            .into_iter()
            .map(|row| UsageRow {
                hour: row.hour,
                requests: row.requests,
                errors: row.errors,
            })
            .collect(),
        total_requests_7d: total_requests,
        total_errors_7d: total_errors,
    };
    Ok(Json(response))
}

/// Updates RPM and burst limits for one API key.
pub async fn update_limits(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateLimitsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if !(1..=10_000).contains(&body.rate_limit_rpm) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "rate_limit_rpm must be in range 1..=10000",
        )
        .with_request_id(&auth.request_id));
    }
    if !(1..=1_000).contains(&body.rate_limit_burst) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "rate_limit_burst must be in range 1..=1000",
        )
        .with_request_id(&auth.request_id));
    }
    let db = helpers::require_db(&state, &auth.request_id)?;
    let updated = db
        .update_api_key_limits(id, body.rate_limit_rpm, body.rate_limit_burst)
        .await
        .map_err(|e| {
            warn!(error = %e, key_id = id, "Failed to update API key limits");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to update API key limits",
            )
        })?;
    if !updated {
        return Err(
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "API key not found")
                .with_request_id(&auth.request_id),
        );
    }
    let target_id = format!("api_key:{id}");
    let details = serde_json::json!({
        "rate_limit_rpm": body.rate_limit_rpm,
        "rate_limit_burst": body.rate_limit_burst,
    })
    .to_string();
    helpers::audit(
        db,
        &auth,
        "api_key_limits_updated",
        Some(&target_id),
        Some(&details),
    )
    .await;
    Ok(StatusCode::OK)
}
