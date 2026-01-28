//! Axum server entrypoint for net-identity.

use anyhow::Result;
use axum::{routing::get, Router};
use tracing_subscriber::EnvFilter;

/// HTTP handler for the root endpoint.
///
/// Parameters: none.
/// Returns: static health string.
async fn root() -> &'static str {
    "net-identity ok"
}

/// Starts the Axum HTTP server.
///
/// Parameters: none.
/// Returns: `Ok(())` on clean shutdown or an error.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let app = Router::new().route("/", get(root));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
