//! Axum server entrypoint for net-identity.

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use net_identity_adapter_ad_logs::AdLogsAdapter;
use net_identity_adapter_radius::RadiusAdapter;
use net_identity_db::Db;
use net_identity_core::model::IdentityEvent;
use serde::Serialize;
use sqlx::SqlitePool;
use std::{env, net::SocketAddr, sync::Arc};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const DEFAULT_DB_URL: &str = "sqlite://net-identity.db";
const DEFAULT_RADIUS_ADDR: &str = "0.0.0.0:1813";
const DEFAULT_AD_SYSLOG_ADDR: &str = "0.0.0.0:514";
const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:3000";
const CHANNEL_CAPACITY: usize = 1024;

#[derive(Clone)]
struct AppState {
    db: Arc<Db>,
}

#[derive(Serialize)]
struct LookupResponse {
    user: Option<String>,
}

/// Returns 200 OK for health checks.
///
/// Parameters: none.
/// Returns: HTTP status code.
async fn health() -> StatusCode {
    StatusCode::OK
}

/// Looks up the current user by IP.
///
/// Parameters: `ip` - IP address string, `state` - app state.
/// Returns: JSON response with optional user.
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

/// Runs the event processing loop.
///
/// Parameters: `receiver` - incoming event channel, `db` - database handle.
/// Returns: `Ok(())` when the channel closes.
async fn run_event_loop(mut receiver: Receiver<IdentityEvent>, db: Arc<Db>) -> Result<()> {
    while let Some(event) = receiver.recv().await {
        if let Err(err) = db.upsert_mapping(event).await {
            warn!(error = %err, "Failed to upsert mapping");
        }
    }
    Ok(())
}

/// Reads an environment variable or returns the default.
///
/// Parameters: `key` - environment variable name, `default_value` - fallback.
/// Returns: resolved string value.
fn env_or_default(key: &str, default_value: &str) -> String {
    env::var(key).unwrap_or_else(|_| default_value.to_string())
}

/// Parses a socket address from string, using a default value.
///
/// Parameters: `value` - value to parse, `default_value` - fallback string.
/// Returns: parsed `SocketAddr` or an error.
fn parse_socket_addr(value: &str, default_value: &str) -> Result<SocketAddr> {
    let resolved = if value.is_empty() { default_value } else { value };
    Ok(resolved.parse()?)
}

/// Starts the Axum HTTP server and background workers.
///
/// Parameters: none.
/// Returns: `Ok(())` on clean shutdown or an error.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let db_url = env_or_default("DATABASE_URL", DEFAULT_DB_URL);
    let radius_addr =
        parse_socket_addr(&env_or_default("RADIUS_BIND", DEFAULT_RADIUS_ADDR), DEFAULT_RADIUS_ADDR)?;
    let ad_syslog_addr =
        parse_socket_addr(&env_or_default("AD_SYSLOG_BIND", DEFAULT_AD_SYSLOG_ADDR), DEFAULT_AD_SYSLOG_ADDR)?;
    let http_addr =
        parse_socket_addr(&env_or_default("HTTP_BIND", DEFAULT_HTTP_ADDR), DEFAULT_HTTP_ADDR)?;
    let radius_secret = env_or_default("RADIUS_SECRET", "secret");

    info!(db_url = %db_url, "Initializing database");
    let pool = SqlitePool::connect(&db_url).await?;
    sqlx::migrate!("../../crates/db/migrations").run(&pool).await?;
    let db = Arc::new(Db::new(pool));

    let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
    let event_db = db.clone();
    tokio::spawn(async move {
        if let Err(err) = run_event_loop(receiver, event_db).await {
            warn!(error = %err, "Event loop stopped");
        }
    });

    spawn_radius_adapter(radius_addr, radius_secret.as_bytes(), sender.clone());
    spawn_ad_logs_adapter(ad_syslog_addr, sender.clone());

    info!(%http_addr, "Starting HTTP server");
    let app = Router::new()
        .route("/health", get(health))
        .route("/lookup/:ip", get(lookup))
        .with_state(AppState { db });
    let listener = tokio::net::TcpListener::bind(http_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Spawns the RADIUS adapter task.
///
/// Parameters: `bind_addr` - UDP bind address, `secret` - shared secret,
/// `sender` - event channel.
/// Returns: none.
fn spawn_radius_adapter(bind_addr: SocketAddr, secret: &[u8], sender: Sender<IdentityEvent>) {
    let adapter = RadiusAdapter::new(bind_addr, secret, sender);
    info!(%bind_addr, "Starting RADIUS adapter");
    tokio::spawn(async move {
        if let Err(err) = adapter.run().await {
            warn!(error = %err, "RADIUS adapter stopped");
        }
    });
}

/// Spawns the AD syslog adapter task.
///
/// Parameters: `bind_addr` - TCP/UDP bind address, `sender` - event channel.
/// Returns: none.
fn spawn_ad_logs_adapter(bind_addr: SocketAddr, sender: Sender<IdentityEvent>) {
    let adapter = AdLogsAdapter::new(bind_addr, sender);
    info!(%bind_addr, "Starting AD syslog adapter");
    tokio::spawn(async move {
        if let Err(err) = adapter.run().await {
            warn!(error = %err, "AD syslog adapter stopped");
        }
    });
}
