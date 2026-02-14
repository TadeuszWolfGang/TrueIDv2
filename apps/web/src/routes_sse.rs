//! SSE proxy endpoint for live engine events.

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use tracing::warn;

use crate::error::{self, ApiError};
use crate::{middleware::AuthUser, AppState};

/// Proxies the engine SSE feed for authenticated dashboard users.
///
/// Parameters: `state` - shared application state, `_auth` - authenticated principal.
/// Returns: streamed SSE HTTP response or `BAD_GATEWAY` on upstream failure.
pub(crate) async fn event_stream(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Response, ApiError> {
    let url = format!("{}/engine/events/stream", state.engine_url);
    let mut req = state.http_client.get(&url);
    if let Some(ref token) = state.engine_service_token {
        req = req.header("X-Service-Token", token);
    }

    let upstream = req.send().await.map_err(|err| {
        warn!(error = %err, url = %url, "SSE proxy request failed");
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            error::SERVICE_UNAVAILABLE,
            "Failed to connect to engine SSE stream",
        )
        .with_request_id(&auth.request_id)
    })?;
    if !upstream.status().is_success() {
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            error::SERVICE_UNAVAILABLE,
            "Engine SSE stream returned non-success status",
        )
        .with_request_id(&auth.request_id));
    }

    let mut response = Body::from_stream(upstream.bytes_stream()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok(response)
}
