//! SSE proxy endpoint for live engine events.
//!
//! Enforces global and per-user concurrent stream caps so authenticated
//! clients cannot exhaust file descriptors / heap with endless streams.

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use futures_core::stream::Stream;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex, OnceLock,
};
use std::task::{Context, Poll};
use tracing::warn;

use crate::error::{self, ApiError};
use crate::{middleware::AuthUser, AppState};

/// Global concurrent SSE stream cap (resource-exhaustion guard).
const MAX_GLOBAL_SSE_STREAMS: usize = 64;
/// Per-user concurrent SSE stream cap.
const MAX_SSE_STREAMS_PER_USER: usize = 5;

static GLOBAL_SSE_STREAMS: AtomicUsize = AtomicUsize::new(0);
static PER_USER_SSE: OnceLock<Mutex<HashMap<i64, usize>>> = OnceLock::new();

fn per_user_map() -> &'static Mutex<HashMap<i64, usize>> {
    PER_USER_SSE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Tries to reserve one SSE slot (global + per-user).
///
/// Parameters: `user_id` - authenticated principal id.
/// Returns: true when the slot was reserved.
fn try_acquire_stream(user_id: i64) -> bool {
    if GLOBAL_SSE_STREAMS.fetch_add(1, Ordering::AcqRel) >= MAX_GLOBAL_SSE_STREAMS {
        GLOBAL_SSE_STREAMS.fetch_sub(1, Ordering::AcqRel);
        return false;
    }
    let mut map = per_user_map().lock().unwrap_or_else(|e| e.into_inner());
    let count = map.entry(user_id).or_insert(0);
    if *count >= MAX_SSE_STREAMS_PER_USER {
        GLOBAL_SSE_STREAMS.fetch_sub(1, Ordering::AcqRel);
        return false;
    }
    *count += 1;
    true
}

/// Releases one SSE slot.
fn release_stream(user_id: i64) {
    GLOBAL_SSE_STREAMS.fetch_sub(1, Ordering::AcqRel);
    let mut map = per_user_map().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(count) = map.get_mut(&user_id) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            map.remove(&user_id);
        }
    }
}

/// Passthrough stream wrapper that releases the SSE slot when dropped
/// (i.e. when the client disconnects or the response body completes).
struct CountedStream<S> {
    inner: S,
    user_id: i64,
}

impl<S> Stream for CountedStream<S>
where
    S: Stream + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

impl<S> Drop for CountedStream<S> {
    fn drop(&mut self) {
        release_stream(self.user_id);
    }
}

/// Proxies the engine SSE feed for authenticated dashboard users.
///
/// Parameters: `state` - shared application state, `auth` - authenticated principal.
/// Returns: streamed SSE HTTP response, `TOO_MANY_REQUESTS` when stream caps
/// are exceeded, or `BAD_GATEWAY` on upstream failure.
pub(crate) async fn event_stream(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Response, ApiError> {
    if !try_acquire_stream(auth.user_id) {
        warn!(
            user_id = auth.user_id,
            "SSE stream refused: concurrent stream limit reached"
        );
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            error::RATE_LIMITED,
            "Too many concurrent event streams",
        )
        .with_request_id(&auth.request_id));
    }
    let user_id = auth.user_id;
    let url = format!("{}/engine/events/stream", state.engine_url);
    let mut req = state.http_client.get(&url);
    if let Some(ref token) = state.engine_service_token {
        req = req.header("X-Service-Token", token);
    }

    let upstream = match req.send().await {
        Ok(upstream) => upstream,
        Err(err) => {
            release_stream(user_id);
            warn!(error = %err, url = %url, "SSE proxy request failed");
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                error::SERVICE_UNAVAILABLE,
                "Failed to connect to engine SSE stream",
            )
            .with_request_id(&auth.request_id));
        }
    };
    if !upstream.status().is_success() {
        release_stream(user_id);
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            error::SERVICE_UNAVAILABLE,
            "Engine SSE stream returned non-success status",
        )
        .with_request_id(&auth.request_id));
    }

    let counted = CountedStream {
        inner: upstream.bytes_stream(),
        user_id,
    };
    let mut response = Body::from_stream(counted).into_response();
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
