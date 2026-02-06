//! TrueID Engine — ingestion-only process (no HTTP).
//!
//! Starts RADIUS, AD syslog and DHCP syslog adapters, processes
//! incoming identity events and persists them to SQLite.

use anyhow::Result;
use net_identity_adapter_ad_logs::AdLogsAdapter;
use net_identity_adapter_dhcp_logs::DhcpLogsAdapter;
use net_identity_adapter_radius::RadiusAdapter;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
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
const JANITOR_INTERVAL_SECS: u64 = 60;
const STALE_TTL_MINUTES: i64 = 5;
const DEFAULT_OUI_PATH: &str = "./data/oui.csv";

/// OUI-to-vendor lookup table (key: uppercase 6-char hex prefix).
type VendorMap = HashMap<String, String>;

/// Loads the IEEE OUI database from a CSV file into a `VendorMap`.
///
/// CSV format: Registry, Assignment, Organization Name, Organization Address.
/// Uses index-based field access for robustness with quoted fields.
///
/// Parameters: `path` - filesystem path to oui.csv.
/// Returns: populated `VendorMap` or an error.
fn load_oui_csv(path: &Path) -> Result<VendorMap> {
    let mut reader = csv::Reader::from_path(path)?;
    let mut map = HashMap::with_capacity(40_000);
    let mut sample_count = 0_u32;

    for result in reader.records() {
        let record = result?;
        let oui = record.get(1).unwrap_or("").trim().to_ascii_uppercase();
        let vendor = record.get(2).unwrap_or("").trim().to_string();

        if sample_count < 5 {
            info!(oui = %oui, vendor = %vendor, "Sample parsed");
            sample_count += 1;
        }

        if !oui.is_empty() && !vendor.is_empty() {
            map.insert(oui, vendor);
        }
    }
    Ok(map)
}

/// Resolves a MAC address to a vendor name using the OUI map.
///
/// Strips separators (`:`, `-`, `.`), takes the first 6 hex chars,
/// uppercases them, and queries the map.
///
/// Parameters: `mac` - raw MAC string (any separator), `vendors` - OUI lookup table.
/// Returns: vendor name if found.
fn resolve_vendor(mac: &str, vendors: &VendorMap) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .flat_map(|c| c.to_uppercase())
        .collect();
    if hex.len() < 6 {
        return None;
    }
    vendors.get(&hex[..6]).cloned()
}

/// Runs the event processing loop, persisting each event to the database.
///
/// Parameters: `receiver` - incoming event channel, `db` - database handle,
/// `vendors` - OUI vendor lookup table.
/// Returns: `Ok(())` when the channel closes.
async fn run_event_loop(
    mut receiver: Receiver<IdentityEvent>,
    db: Arc<Db>,
    vendors: Arc<VendorMap>,
) -> Result<()> {
    while let Some(event) = receiver.recv().await {
        let vendor = event
            .mac
            .as_deref()
            .and_then(|mac| resolve_vendor(mac, &vendors));
        info!(?event, ?vendor, "Processing event");
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

/// Periodically deactivates mappings that have not been seen within the TTL.
///
/// Parameters: `db` - shared database handle.
fn start_janitor(db: Arc<Db>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(JANITOR_INTERVAL_SECS));
        loop {
            interval.tick().await;
            match db.deactivate_stale(STALE_TTL_MINUTES).await {
                Ok(count) if count > 0 => {
                    info!(deactivated = count, "Janitor: marked stale mappings as inactive");
                }
                Ok(_) => {}
                Err(err) => {
                    warn!(error = %err, "Janitor: failed to deactivate stale mappings");
                }
            }
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

    let oui_path = env_or_default("OUI_CSV_PATH", DEFAULT_OUI_PATH);
    let vendors: Arc<VendorMap> = match load_oui_csv(Path::new(&oui_path)) {
        Ok(map) => {
            info!(count = map.len(), path = %oui_path, "Loaded OUI vendor database");
            Arc::new(map)
        }
        Err(err) => {
            warn!(error = %err, path = %oui_path, "Failed to load OUI CSV — vendor lookup disabled");
            Arc::new(HashMap::new())
        }
    };

    info!(db_url = %db_url, "Initializing database");
    let db = Arc::new(trueid_common::db::init_db(&db_url).await?);

    let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
    let event_db = db.clone();
    let event_vendors = vendors.clone();
    tokio::spawn(async move {
        if let Err(err) = run_event_loop(receiver, event_db, event_vendors).await {
            warn!(error = %err, "Event loop stopped");
        }
    });

    spawn_radius_adapter(radius_addr, radius_secret.as_bytes(), sender.clone());
    spawn_ad_logs_adapter(ad_syslog_addr, sender.clone());
    spawn_dhcp_logs_adapter(dhcp_syslog_addr, sender);
    start_janitor(db.clone());

    info!("Engine running — press Ctrl+C to stop");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    db.close().await;

    Ok(())
}
