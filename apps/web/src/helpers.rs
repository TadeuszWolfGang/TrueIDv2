//! Shared handler helpers to reduce boilerplate.

use axum::http::StatusCode;
use std::sync::Arc;
use trueid_common::db::Db;

use crate::error::ApiError;
use crate::{error, AppState};

/// Extracts database handle from AppState.
///
/// Parameters: `state` - app state, `request_id` - request correlation id.
/// Returns: database handle or SERVICE_UNAVAILABLE ApiError.
pub(crate) fn require_db<'a>(
    state: &'a AppState,
    request_id: &str,
) -> Result<&'a Arc<Db>, ApiError> {
    state.db.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            error::SERVICE_UNAVAILABLE,
            "Database unavailable",
        )
        .with_request_id(request_id)
    })
}

/// Writes audit log entry for the authenticated user's action.
///
/// Parameters: `db` - database handle, `auth` - authenticated user, `action` - audit action name, `target_id` - optional target resource id, `details` - optional additional details.
/// Returns: none.
pub async fn audit_principal(
    db: &Db,
    user_id: Option<i64>,
    username: &str,
    principal_type: &str,
    action: &str,
    target_id: Option<&str>,
    details: Option<&str>,
    ip: Option<&str>,
    request_id: Option<&str>,
) {
    let _ = db
        .write_audit_log(
            user_id,
            username,
            principal_type,
            action,
            target_id,
            details,
            ip,
            request_id,
        )
        .await;
}

/// Writes audit log entry for the authenticated user's action.
///
/// Parameters: `db` - database handle, `auth` - authenticated user, `action` - audit action name, `target_id` - optional target resource id, `details` - optional additional details.
/// Returns: none.
pub(crate) async fn audit(
    db: &Db,
    auth: &crate::middleware::AuthUser,
    action: &str,
    target_id: Option<&str>,
    details: Option<&str>,
) {
    audit_principal(
        db,
        Some(auth.user_id),
        &auth.username,
        &auth.principal_type,
        action,
        target_id,
        details,
        None,
        Some(&auth.request_id),
    )
    .await;
}

/// Audit helper for system-level actions (no authenticated user).
///
/// Parameters: `db` - database handle, `username` - actor identifier, `action` - audit action name, `target_id` - optional target resource id, `details` - optional additional details, `ip` - optional client IP, `request_id` - optional request correlation id.
/// Returns: none.
pub(crate) async fn audit_system(
    db: &Db,
    username: &str,
    action: &str,
    target_id: Option<&str>,
    details: Option<&str>,
    ip: Option<&str>,
    request_id: Option<&str>,
) {
    audit_principal(
        db, None, username, "system", action, target_id, details, ip, request_id,
    )
    .await;
}
