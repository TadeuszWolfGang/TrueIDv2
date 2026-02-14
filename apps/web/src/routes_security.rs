//! Admin security endpoints for password policy and session controls.

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
use crate::password_policy::PasswordPolicy;
use crate::AppState;

/// Password policy admin response model.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PasswordPolicyResponse {
    min_length: usize,
    require_uppercase: bool,
    require_lowercase: bool,
    require_digit: bool,
    require_special: bool,
    history_count: usize,
    max_age_days: i64,
    session_max_idle_minutes: i64,
    session_absolute_max_hours: i64,
    totp_required_for_admins: bool,
}

/// Active session row for admin session management.
#[derive(Debug, Serialize)]
struct AdminSessionInfo {
    id: i64,
    user_id: i64,
    username: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    created_at: String,
    last_active_at: String,
    expires_at: String,
}

/// Simple toggle body used by admin TOTP requirement endpoint.
#[derive(Debug, Deserialize)]
pub(crate) struct TotpRequirementRequest {
    enabled: bool,
}

/// Returns active password/security policy values.
///
/// Parameters: `auth` - admin principal, `state` - app state.
/// Returns: current password and session policy.
pub(crate) async fn get_password_policy(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let policy = PasswordPolicy::load(db).await;
    Ok(Json(PasswordPolicyResponse {
        min_length: policy.min_length,
        require_uppercase: policy.require_uppercase,
        require_lowercase: policy.require_lowercase,
        require_digit: policy.require_digit,
        require_special: policy.require_special,
        history_count: policy.history_count,
        max_age_days: policy.max_age_days,
        session_max_idle_minutes: policy.session_max_idle_minutes,
        session_absolute_max_hours: policy.session_absolute_max_hours,
        totp_required_for_admins: policy.totp_required_for_admins,
    }))
}

/// Updates password/security policy values.
///
/// Parameters: `auth` - admin principal, `state` - app state, `body` - new policy values.
/// Returns: updated policy.
pub(crate) async fn update_password_policy(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<PasswordPolicyResponse>,
) -> Result<impl IntoResponse, ApiError> {
    if body.min_length < 8 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "min_length must be >= 8",
        )
        .with_request_id(&auth.request_id));
    }
    let db = helpers::require_db(&state, &auth.request_id)?;
    db.set_config("password_min_length", &body.min_length.to_string())
        .await
        .map_err(to_internal(&auth.request_id, "Failed to update password policy"))?;
    db.set_config(
        "password_require_uppercase",
        &body.require_uppercase.to_string(),
    )
    .await
    .map_err(to_internal(&auth.request_id, "Failed to update password policy"))?;
    db.set_config(
        "password_require_lowercase",
        &body.require_lowercase.to_string(),
    )
    .await
    .map_err(to_internal(&auth.request_id, "Failed to update password policy"))?;
    db.set_config("password_require_digit", &body.require_digit.to_string())
        .await
        .map_err(to_internal(&auth.request_id, "Failed to update password policy"))?;
    db.set_config("password_require_special", &body.require_special.to_string())
        .await
        .map_err(to_internal(&auth.request_id, "Failed to update password policy"))?;
    db.set_config("password_history_count", &body.history_count.to_string())
        .await
        .map_err(to_internal(&auth.request_id, "Failed to update password policy"))?;
    db.set_config("password_max_age_days", &body.max_age_days.to_string())
        .await
        .map_err(to_internal(&auth.request_id, "Failed to update password policy"))?;
    db.set_config(
        "session_max_idle_minutes",
        &body.session_max_idle_minutes.to_string(),
    )
    .await
    .map_err(to_internal(&auth.request_id, "Failed to update password policy"))?;
    db.set_config(
        "session_absolute_max_hours",
        &body.session_absolute_max_hours.to_string(),
    )
    .await
    .map_err(to_internal(&auth.request_id, "Failed to update password policy"))?;
    db.set_config(
        "totp_required_for_admins",
        &body.totp_required_for_admins.to_string(),
    )
    .await
    .map_err(to_internal(&auth.request_id, "Failed to update password policy"))?;
    helpers::audit(db, &auth, "security_policy_updated", None, None).await;
    get_password_policy(auth, State(state)).await
}

/// Lists active sessions across all users.
///
/// Parameters: `auth` - admin principal, `state` - app state.
/// Returns: session list.
pub(crate) async fn list_all_sessions(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = db.list_all_active_sessions().await.map_err(|e| {
        warn!(error = %e, "Failed to list all active sessions");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list active sessions",
        )
        .with_request_id(&auth.request_id)
    })?;
    let out: Vec<AdminSessionInfo> = rows
        .into_iter()
        .map(|(s, username)| AdminSessionInfo {
            id: s.id,
            user_id: s.user_id,
            username,
            ip_address: s.ip_address,
            user_agent: s.user_agent,
            created_at: s.created_at.to_rfc3339(),
            last_active_at: s.last_active_at.to_rfc3339(),
            expires_at: s.expires_at.to_rfc3339(),
        })
        .collect();
    Ok(Json(out))
}

/// Revokes a session by id (admin action).
///
/// Parameters: `auth` - admin principal, `state` - app state, `id` - session id.
/// Returns: HTTP 200.
pub(crate) async fn revoke_any_session(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    db.revoke_session(id)
        .await
        .map_err(to_internal(&auth.request_id, "Failed to revoke session"))?;
    helpers::audit(
        db,
        &auth,
        "admin_session_revoked",
        Some(&format!("session:{id}")),
        None,
    )
    .await;
    Ok(StatusCode::OK)
}

/// Updates global admin TOTP requirement toggle.
///
/// Parameters: `auth` - admin principal, `state` - app state, `body` - enable/disable value.
/// Returns: stored value.
pub(crate) async fn set_totp_requirement(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<TotpRequirementRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    db.set_config("totp_required_for_admins", &body.enabled.to_string())
        .await
        .map_err(to_internal(
            &auth.request_id,
            "Failed to update TOTP requirement",
        ))?;
    helpers::audit(
        db,
        &auth,
        "totp_requirement_updated",
        None,
        Some(&format!("enabled={}", body.enabled)),
    )
    .await;
    Ok(Json(serde_json::json!({
        "totp_required_for_admins": body.enabled
    })))
}

/// Builds shared internal-error mapper closure for policy/session endpoints.
fn to_internal<'a>(
    request_id: &'a str,
    message: &'static str,
) -> impl Fn(anyhow::Error) -> ApiError + 'a {
    move |_| {
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error::INTERNAL_ERROR, message)
            .with_request_id(request_id)
    }
}
