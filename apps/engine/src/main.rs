//! TrueID Engine — ingestion-only process (no HTTP).
//!
//! Starts RADIUS, AD syslog and DHCP syslog adapters, processes
//! incoming identity events and persists them to SQLite.

use anyhow::Result;
use net_identity_adapter_ad_logs::AdLogsAdapter;
use net_identity_adapter_dhcp_logs::DhcpLogsAdapter;
use net_identity_adapter_radius::RadiusAdapter;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use trueid_common::db::Db;
use trueid_common::model::IdentityEvent;
use trueid_common::{env_or_default, parse_socket_addr};

const DEFAULT_DB_URL: &str = "sqlite://trueid.db?mode=rwc";
const DEFAULT_RADIUS_ADDR: &str = "0.0.0.0:1813";
const DEFAULT_AD_SYSLOG_ADDR: &str = "0.0.0.0:5514";
const DEFAULT_DHCP_SYSLOG_ADDR: &str = "0.0.0.0:5516";
const CHANNEL_CAPACITY: usize = 1024;

/// Runs the event processing loop, persisting each event to the database.
///
/// Parameters: `receiver` - incoming event channel, `db` - database handle.
/// Returns: `Ok(())` when the channel closes.
async fn run_event_loop(mut receiver: Receiver<IdentityEvent>, db: Arc<Db>) -> Result<()> {
    while let Some(event) = receiver.recv().await {
        info!(?event, "Processing event");
        if let Err(err) = db.upsert_mapping(event).await {
            warn!(error = %err, "Failed to upsert mapping");
        }
    }
    Ok(())
}

/// Spawns the RADIUS adapter task.
///
/// Parameters: `bind_addr` - UDP bind address, `secret` - shared secret,
/// `sender` - event channel.
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
/// Parameters: `bind_addr` - UDP/TCP bind address, `sender` - event channel.
fn spawn_ad_logs_adapter(bind_addr: SocketAddr, sender: Sender<IdentityEvent>) {
    let adapter = AdLogsAdapter::new(bind_addr, sender);
    info!(%bind_addr, "Starting AD syslog adapter");
    tokio::spawn(async move {
        if let Err(err) = adapter.run().await {
            warn!(error = %err, "AD syslog adapter stopped");
        }
    });
}

/// Spawns the DHCP syslog adapter task.
///
/// Parameters: `bind_addr` - UDP bind address, `sender` - event channel.
fn spawn_dhcp_logs_adapter(bind_addr: SocketAddr, sender: Sender<IdentityEvent>) {
    let adapter = DhcpLogsAdapter::new(bind_addr, sender);
    info!(%bind_addr, "Starting DHCP syslog adapter");
    tokio::spawn(async move {
        if let Err(err) = adapter.run().await {
            warn!(error = %err, "DHCP adapter stopped");
        }
    });
}

/// Starts all adapters, processes events and waits for Ctrl+C.
///
/// Parameters: none.
/// Returns: `Ok(())` on clean shutdown or an error.
#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let db_url = env_or_default("DATABASE_URL", DEFAULT_DB_URL);
    let radius_addr = parse_socket_addr(
        &env_or_default("RADIUS_BIND", DEFAULT_RADIUS_ADDR),
        DEFAULT_RADIUS_ADDR,
    )?;
    let ad_syslog_addr = parse_socket_addr(
        &env_or_default("AD_SYSLOG_BIND", DEFAULT_AD_SYSLOG_ADDR),
        DEFAULT_AD_SYSLOG_ADDR,
    )?;
    let dhcp_syslog_addr = parse_socket_addr(
        &env_or_default("DHCP_SYSLOG_BIND", DEFAULT_DHCP_SYSLOG_ADDR),
        DEFAULT_DHCP_SYSLOG_ADDR,
    )?;
    let radius_secret = env_or_default("RADIUS_SECRET", "secret");

    info!(db_url = %db_url, "Initializing database");
    let db = Arc::new(trueid_common::db::init_db(&db_url).await?);

    let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
    let event_db = db.clone();
    tokio::spawn(async move {
        if let Err(err) = run_event_loop(receiver, event_db).await {
            warn!(error = %err, "Event loop stopped");
        }
    });

    spawn_radius_adapter(radius_addr, radius_secret.as_bytes(), sender.clone());
    spawn_ad_logs_adapter(ad_syslog_addr, sender.clone());
    spawn_dhcp_logs_adapter(dhcp_syslog_addr, sender);

    info!("Engine running — press Ctrl+C to stop");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    db.close().await;

    Ok(())
}
