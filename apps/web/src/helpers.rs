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
pub(crate) async fn audit(
    db: &Db,
    auth: &crate::middleware::AuthUser,
    action: &str,
    target_id: Option<&str>,
    details: Option<&str>,
) {
    let _ = db
        .write_audit_log(
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
