//! Engine proxy handlers for admin/config write paths.

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use tracing::warn;

use crate::AppState;

/// Proxies a request to the engine admin API and returns its JSON response.
///
/// Parameters: `state` - shared app state, `method` - HTTP method, `path` - engine path,
/// `body` - optional JSON payload.
/// Returns: proxied `(status, json)` response or `BAD_GATEWAY` on transport/parse errors.
pub(crate) async fn proxy_to_engine(
    state: &AppState,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    let url = format!("{}{}", state.engine_url, path);
    let mut req = state.http_client.request(method, &url);
    if let Some(ref token) = state.engine_service_token {
        req = req.header("X-Service-Token", token);
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await.map_err(|e| {
        warn!(error = %e, url = %url, "Engine proxy request failed");
        StatusCode::BAD_GATEWAY
    })?;
    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let json_body = resp
        .json::<serde_json::Value>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok((status, Json(json_body)))
}

/// Proxies adapters status endpoint.
///
/// Parameters: `s` - shared app state.
/// Returns: proxied adapters status response.
pub(crate) async fn proxy_admin_adapters(
    State(s): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/status/adapters", None).await
}

/// Proxies agents status endpoint.
///
/// Parameters: `s` - shared app state.
/// Returns: proxied agents status response.
pub(crate) async fn proxy_admin_agents(
    State(s): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/status/agents", None).await
}

/// Proxies runtime config status endpoint.
///
/// Parameters: `s` - shared app state.
/// Returns: proxied runtime config response.
pub(crate) async fn proxy_admin_runtime_config(
    State(s): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/status/runtime-config", None).await
}

/// Proxies TTL config read endpoint.
///
/// Parameters: `s` - shared app state.
/// Returns: proxied TTL config payload.
pub(crate) async fn proxy_get_ttl(
    State(s): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/config/ttl", None).await
}

/// Proxies TTL config update endpoint.
///
/// Parameters: `s` - shared app state, `body` - JSON payload.
/// Returns: proxied update response.
pub(crate) async fn proxy_put_ttl(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::PUT, "/engine/config/ttl", Some(body)).await
}

/// Proxies source-priority config read endpoint.
///
/// Parameters: `s` - shared app state.
/// Returns: proxied source-priority payload.
pub(crate) async fn proxy_get_source_priority(
    State(s): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(
        &s,
        reqwest::Method::GET,
        "/engine/config/source-priority",
        None,
    )
    .await
}

/// Proxies source-priority config update endpoint.
///
/// Parameters: `s` - shared app state, `body` - JSON payload.
/// Returns: proxied update response.
pub(crate) async fn proxy_put_source_priority(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(
        &s,
        reqwest::Method::PUT,
        "/engine/config/source-priority",
        Some(body),
    )
    .await
}

/// Proxies Sycope config read endpoint.
///
/// Parameters: `s` - shared app state.
/// Returns: proxied Sycope config payload.
pub(crate) async fn proxy_get_sycope(
    State(s): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::GET, "/engine/config/sycope", None).await
}

/// Proxies Sycope config update endpoint.
///
/// Parameters: `s` - shared app state, `body` - JSON payload.
/// Returns: proxied update response.
pub(crate) async fn proxy_put_sycope(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::PUT, "/engine/config/sycope", Some(body)).await
}

/// Proxies mapping create endpoint.
///
/// Parameters: `s` - shared app state, `body` - JSON payload.
/// Returns: proxied create response.
pub(crate) async fn proxy_post_mapping(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(&s, reqwest::Method::POST, "/engine/mappings", Some(body)).await
}

/// Proxies mapping delete endpoint.
///
/// Parameters: `s` - shared app state, `ip` - mapping key.
/// Returns: proxied delete response.
pub(crate) async fn proxy_delete_mapping(
    State(s): State<AppState>,
    Path(ip): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    proxy_to_engine(
        &s,
        reqwest::Method::DELETE,
        &format!("/engine/mappings/{}", ip),
        None,
    )
    .await
}
