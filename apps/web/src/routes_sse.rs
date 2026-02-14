//! SSE proxy endpoint for live engine events.

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use tracing::warn;

use crate::{middleware::AuthUser, AppState};

/// Proxies the engine SSE feed for authenticated dashboard users.
///
/// Parameters: `state` - shared application state, `_auth` - authenticated principal.
/// Returns: streamed SSE HTTP response or `BAD_GATEWAY` on upstream failure.
pub(crate) async fn event_stream(
    State(state): State<AppState>,
    _auth: AuthUser,
) -> Result<Response, StatusCode> {
    let url = format!("{}/engine/events/stream", state.engine_url);
    let mut req = state.http_client.get(&url);
    if let Some(ref token) = state.engine_service_token {
        req = req.header("X-Service-Token", token);
    }

    let upstream = req.send().await.map_err(|err| {
        warn!(error = %err, url = %url, "SSE proxy request failed");
        StatusCode::BAD_GATEWAY
    })?;
    if !upstream.status().is_success() {
        return Err(StatusCode::BAD_GATEWAY);
    }

    let mut response = Body::from_stream(upstream.bytes_stream()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok(response)
}
