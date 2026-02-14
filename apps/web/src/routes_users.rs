//! User management endpoints (Admin only — enforced by router-level middleware).

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
use crate::password_policy::PasswordPolicy;
use crate::AppState;
use trueid_common::model::{UserPublic, UserRole};

// ── Request / response types ───────────────────────────────

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: UserRole,
}

#[derive(Deserialize)]
pub struct ChangeRoleRequest {
    pub role: UserRole,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct UsersQuery {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Serialize)]
struct PaginatedUsers {
    data: Vec<UserPublic>,
    total: i64,
    page: i64,
    per_page: i64,
}

// ── Validation helper ──────────────────────────────────────

/// Username regex: 3-50 chars, alphanumeric + underscore + dash.
fn validate_username(username: &str) -> bool {
    username.len() >= 3
        && username.len() <= 50
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

// ── GET /api/v1/users ──────────────────────────────────────

/// Lists all users with pagination.
pub async fn list_users(
    auth: AuthUser,
    Query(q): Query<UsersQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(50).clamp(1, 200);

    let all = db.list_users().await.map_err(|e| {
        warn!(error = %e, "Failed to list users");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list users",
        )
    })?;

    let total = all.len() as i64;
    let offset = ((page - 1) * per_page) as usize;
    let data: Vec<UserPublic> = all
        .into_iter()
        .skip(offset)
        .take(per_page as usize)
        .collect();

    Ok(Json(PaginatedUsers {
        data,
        total,
        page,
        per_page,
    }))
}

// ── POST /api/v1/users ─────────────────────────────────────

/// Creates a new user. Sets force_password_change = true.
pub async fn create_user(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if !validate_username(&body.username) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Username must be 3-50 chars, alphanumeric/underscore/dash only",
        )
        .with_request_id(&auth.request_id));
    }
    let db = helpers::require_db(&state, &auth.request_id)?;
    let policy = PasswordPolicy::load(db).await;
    if let Err(msg) = policy.validate(&body.password) {
        return Err(
            ApiError::new(StatusCode::BAD_REQUEST, error::INVALID_INPUT, &msg)
                .with_request_id(&auth.request_id),
        );
    }

    let user = db
        .create_user(&body.username, &body.password, body.role)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("UNIQUE constraint") {
                ApiError::new(
                    StatusCode::CONFLICT,
                    error::CONFLICT,
                    "Username already exists",
                )
                .with_request_id(&auth.request_id)
            } else {
                warn!(error = %e, "Failed to create user");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to create user",
                )
                .with_request_id(&auth.request_id)
            }
        })?;

    let _ = db.set_force_password_change(user.id, true).await;

    let details = serde_json::json!({"role": body.role.to_string()}).to_string();
    let target_id = format!("user:{}", user.id);
    helpers::audit(db, &auth, "user_created", Some(&target_id), Some(&details)).await;

    Ok((StatusCode::CREATED, Json(UserPublic::from(user))))
}

// ── GET /api/v1/users/{id} ─────────────────────────────────

/// Returns a single user.
pub async fn get_user(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let user = db.get_user_by_id(id).await.ok().flatten().ok_or_else(|| {
        ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "User not found")
            .with_request_id(&auth.request_id)
    })?;

    Ok(Json(UserPublic::from(user)))
}

// ── PUT /api/v1/users/{id}/role ────────────────────────────

/// Changes a user's role. Cannot change own role.
pub async fn change_role(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<ChangeRoleRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if auth.user_id == id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Cannot change your own role",
        )
        .with_request_id(&auth.request_id));
    }

    let db = helpers::require_db(&state, &auth.request_id)?;

    let user = db.get_user_by_id(id).await.ok().flatten().ok_or_else(|| {
        ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "User not found")
            .with_request_id(&auth.request_id)
    })?;

    let old_role = user.role.to_string();
    db.update_user_role(id, body.role).await.map_err(|e| {
        warn!(error = %e, "Failed to change role");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to change role",
        )
    })?;

    let details =
        serde_json::json!({"old_role": old_role, "new_role": body.role.to_string()}).to_string();
    let target_id = format!("user:{id}");
    helpers::audit(db, &auth, "role_changed", Some(&target_id), Some(&details)).await;

    let updated = db.get_user_by_id(id).await.ok().flatten().ok_or_else(|| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "User refetch failed",
        )
    })?;

    Ok(Json(UserPublic::from(updated)))
}

// ── POST /api/v1/users/{id}/reset-password ─────────────────

/// Admin resets a user's password. Sets force_password_change = true.
pub async fn reset_password(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<ResetPasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let policy = PasswordPolicy::load(db).await;
    if let Err(msg) = policy.validate(&body.new_password) {
        return Err(
            ApiError::new(StatusCode::BAD_REQUEST, error::INVALID_INPUT, &msg)
                .with_request_id(&auth.request_id),
        );
    }

    let user = db.get_user_by_id(id).await.ok().flatten().ok_or_else(|| {
        ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "User not found")
            .with_request_id(&auth.request_id)
    })?;
    if let Err(msg) = policy.check_history(db, id, &body.new_password).await {
        return Err(
            ApiError::new(StatusCode::BAD_REQUEST, error::INVALID_INPUT, &msg)
                .with_request_id(&auth.request_id),
        );
    }
    let old_hash = user.password_hash.clone();

    db.change_password(id, &body.new_password)
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to reset password");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to reset password",
            )
        })?;
    let _ = db.set_force_password_change(id, true).await;
    let _ = db.insert_password_history(id, &old_hash).await;

    let target_id = format!("user:{id}");
    helpers::audit(db, &auth, "password_reset_by_admin", Some(&target_id), None).await;

    Ok(StatusCode::OK)
}

// ── POST /api/v1/users/{id}/unlock ─────────────────────────

/// Clears account lockout (failed_attempts and locked_until).
pub async fn unlock_account(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let _user = db.get_user_by_id(id).await.ok().flatten().ok_or_else(|| {
        ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "User not found")
            .with_request_id(&auth.request_id)
    })?;

    db.reset_failed_attempts(id).await.map_err(|e| {
        warn!(error = %e, "Failed to unlock account");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to unlock account",
        )
    })?;

    let target_id = format!("user:{id}");
    helpers::audit(db, &auth, "account_unlocked", Some(&target_id), None).await;

    Ok(StatusCode::OK)
}

/// Disables TOTP for a specific user (admin override).
pub async fn disable_user_totp(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let _user = db.get_user_by_id(id).await.ok().flatten().ok_or_else(|| {
        ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "User not found")
            .with_request_id(&auth.request_id)
    })?;
    db.disable_user_totp(id).await.map_err(|e| {
        warn!(error = %e, user_id = id, "Failed to disable user TOTP");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to disable user TOTP",
        )
    })?;
    helpers::audit(
        db,
        &auth,
        "admin_disable_user_totp",
        Some(&format!("user:{id}")),
        None,
    )
    .await;
    Ok(StatusCode::OK)
}

// ── DELETE /api/v1/users/{id} ──────────────────────────────

/// Deletes a user. Cannot delete self. Must keep at least 1 Admin.
pub async fn delete_user(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, ApiError> {
    if auth.user_id == id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Cannot delete yourself",
        )
        .with_request_id(&auth.request_id));
    }

    let db = helpers::require_db(&state, &auth.request_id)?;

    let user = db.get_user_by_id(id).await.ok().flatten().ok_or_else(|| {
        ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "User not found")
            .with_request_id(&auth.request_id)
    })?;

    // Ensure at least 1 Admin remains.
    if user.role == UserRole::Admin {
        let admin_count = db.count_admins().await.unwrap_or(0);
        if admin_count <= 1 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "Cannot delete the last Admin user",
            )
            .with_request_id(&auth.request_id));
        }
    }

    // Revoke all sessions for the user.
    let _ = db.revoke_all_sessions(id).await;

    db.delete_user(id).await.map_err(|e| {
        warn!(error = %e, "Failed to delete user");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to delete user",
        )
    })?;

    let details = serde_json::json!({
        "deleted_username": user.username,
        "deleted_role": user.role.to_string()
    })
    .to_string();
    let target_id = format!("user:{id}");
    helpers::audit(db, &auth, "user_deleted", Some(&target_id), Some(&details)).await;

    Ok(StatusCode::NO_CONTENT)
}
