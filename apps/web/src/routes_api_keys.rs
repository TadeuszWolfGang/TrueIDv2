//! API key management endpoints (Admin only — enforced by router-level middleware).

use axum::{
    extract::{Path, State},
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
    pub description: String,
    pub role: UserRole,
    pub expires_in_days: Option<i64>,
}

#[derive(Serialize)]
struct CreateApiKeyResponse {
    key: String,
    notice: &'static str,
    record: ApiKeyRecord,
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

    let db = helpers::require_db(&state, &auth.request_id)?;

    let expires_at = body
        .expires_in_days
        .map(|days| chrono::Utc::now() + chrono::Duration::days(days));

    let (raw_key, record) = db
        .create_api_key(&body.description, body.role, auth.user_id, expires_at)
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
    helpers::audit(db, &auth, "api_key_created", Some(&target_id), Some(&details)).await;

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
