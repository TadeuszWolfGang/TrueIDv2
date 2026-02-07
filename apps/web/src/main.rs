//! TrueID Web — read-only HTTP dashboard.
//!
//! Serves the API (`/api/recent`, `/lookup/:ip`) and static assets.
//! Reads from the same SQLite database that the engine writes to.

use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use trueid_common::db::Db;
use trueid_common::{env_or_default, parse_socket_addr};

const DEFAULT_DB_URL: &str = "sqlite://trueid.db?mode=rwc";
const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:3000";
const DEFAULT_ASSETS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");

#[derive(Clone)]
struct AppState {
    db: Arc<Db>,
}

#[derive(Serialize)]
struct LookupResponse {
    user: Option<String>,
}

#[derive(Deserialize)]
struct RecentQuery {
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct EventsQuery {
    since: Option<i64>,
}

/// Returns 200 OK for health checks.
///
/// Parameters: none.
/// Returns: HTTP status code.
async fn health() -> StatusCode {
    StatusCode::OK
}

/// Looks up the current user by IP address.
///
/// Parameters: `ip` - IP address path param, `state` - shared app state.
/// Returns: JSON with optional user or 500 on error.
async fn lookup(
    Path(ip): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    match state.db.get_mapping(&ip).await {
        Ok(Some(mapping)) => Ok(Json(LookupResponse {
            user: mapping.current_users.into_iter().next(),
        })),
        Ok(None) => Ok(Json(LookupResponse { user: None })),
        Err(err) => {
            warn!(error = %err, %ip, "Lookup failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Returns recent mappings ordered by last_seen.
///
/// Parameters: `query` - optional limit, `state` - shared app state.
/// Returns: JSON list of mappings or 500 on error.
async fn recent(
    Query(query): Query<RecentQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = query.limit.unwrap_or(50);
    let limit = if limit <= 0 { 50 } else { limit };
    match state.db.get_recent_mappings(limit).await {
        Ok(mappings) => Ok(Json(mappings)),
        Err(err) => {
            warn!(error = %err, "Recent mappings query failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Returns all currently active identity mappings (is_active = true).
///
/// Parameters: `state` - shared app state.
/// Returns: JSON list of active mappings or 500 on error.
async fn api_v1_mappings(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    match state.db.get_active_mappings().await {
        Ok(mappings) => Ok(Json(mappings)),
        Err(err) => {
            warn!(error = %err, "Active mappings query failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Returns events since a given Unix timestamp (seconds).
///
/// Parameters: `query` - optional `since` param (Unix seconds, default 0),
/// `state` - shared app state.
/// Returns: JSON list of events or 500 on error.
async fn api_v1_events(
    Query(query): Query<EventsQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let since_ts = query.since.unwrap_or(0);
    let since_dt = Utc.timestamp_opt(since_ts, 0).single().unwrap_or_else(Utc::now);
    match state.db.get_events_since(since_dt).await {
        Ok(events) => Ok(Json(events)),
        Err(err) => {
            warn!(error = %err, "Events query failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Starts the Axum HTTP server with graceful shutdown.
///
/// Parameters: none.
/// Returns: `Ok(())` on clean shutdown or an error.
#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let db_url = env_or_default("DATABASE_URL", DEFAULT_DB_URL);
    let http_addr = parse_socket_addr(
        &env_or_default("HTTP_BIND", DEFAULT_HTTP_ADDR),
        DEFAULT_HTTP_ADDR,
    )?;

    info!(db_url = %db_url, "Initializing database (read-only dashboard)");
    let db = Arc::new(trueid_common::db::init_db(&db_url).await?);

    let app = Router::new()
        .route("/health", get(health))
        .route("/lookup/{ip}", get(lookup))
        .route("/api/recent", get(recent))
        .route("/api/v1/mappings", get(api_v1_mappings))
        .route("/api/v1/events", get(api_v1_events))
        .with_state(AppState { db })
        .fallback_service(ServeDir::new(env_or_default("ASSETS_DIR", DEFAULT_ASSETS_DIR)));

    info!(%http_addr, "Starting HTTP server");
    let listener = tokio::net::TcpListener::bind(http_addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async { tokio::signal::ctrl_c().await.ok(); })
        .await?;

    info!("Web server stopped");
    Ok(())
}
