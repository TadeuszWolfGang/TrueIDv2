//! Unified API error type for all TrueID web endpoints.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

// ── Standard error codes ───────────────────────────────────

pub const AUTH_REQUIRED: &str = "AUTH_REQUIRED";
pub const INVALID_CREDENTIALS: &str = "INVALID_CREDENTIALS";
pub const ACCOUNT_LOCKED: &str = "ACCOUNT_LOCKED";
pub const FORBIDDEN: &str = "FORBIDDEN";
pub const INVALID_INPUT: &str = "INVALID_INPUT";
pub const NOT_FOUND: &str = "NOT_FOUND";
pub const CONFLICT: &str = "CONFLICT";
pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
pub const SERVICE_UNAVAILABLE: &str = "SERVICE_UNAVAILABLE";
pub const CSRF_FAILED: &str = "CSRF_FAILED";
pub const RATE_LIMITED: &str = "RATE_LIMITED";

// ── ApiError ───────────────────────────────────────────────

/// Structured API error returned as JSON.
///
/// Fields: HTTP status, machine-readable code, human-readable message,
/// optional request_id for correlation.
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
}

impl ApiError {
    /// Creates a new ApiError.
    ///
    /// Parameters: `status`, `code`, `message`.
    /// Returns: `ApiError` with no request_id (set later by middleware).
    pub fn new(status: StatusCode, code: &str, message: &str) -> Self {
        Self {
            status,
            code: code.to_string(),
            message: message.to_string(),
            request_id: None,
        }
    }

    /// Attaches a request_id to this error.
    ///
    /// Parameters: `rid` — request ID string.
    /// Returns: self with request_id set.
    pub fn with_request_id(mut self, rid: &str) -> Self {
        self.request_id = Some(rid.to_string());
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({
            "error": self.message,
            "code": self.code,
            "request_id": self.request_id.unwrap_or_default(),
        });
        (self.status, Json(body)).into_response()
    }
}

impl From<(StatusCode, &str, &str)> for ApiError {
    /// Convenience conversion from (StatusCode, code, message).
    fn from((status, code, message): (StatusCode, &str, &str)) -> Self {
        Self::new(status, code, message)
    }
}
