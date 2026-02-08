//! TrueID Engine — ingestion + admin API process.
//!
//! Starts RADIUS, AD syslog and DHCP syslog adapters (UDP, legacy),
//! optional TLS syslog listeners (secure), processes incoming identity
//! events and persists them to SQLite. Exposes an internal Admin HTTP
//! API on a separate port for configuration and monitoring.

mod admin_api;
mod tls_listener;

use anyhow::Result;
use axum::Router;
use chrono::Utc;
use net_identity_adapter_ad_logs::AdLogsAdapter;
use net_identity_adapter_dhcp_logs::DhcpLogsAdapter;
use net_identity_adapter_radius::RadiusAdapter;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::RwLock;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use trueid_common::db::Db;
use trueid_common::model::{AdapterStatus, IdentityEvent};
use trueid_common::{env_or_default, parse_socket_addr};

use crate::admin_api::{EngineAdminState, RuntimeEnv};

const DEFAULT_DB_URL: &str = "sqlite://net-identity.db?mode=rwc";
const DEFAULT_RADIUS_ADDR: &str = "0.0.0.0:1813";
const DEFAULT_AD_SYSLOG_ADDR: &str = "0.0.0.0:5514";
const DEFAULT_DHCP_SYSLOG_ADDR: &str = "0.0.0.0:5516";
const CHANNEL_CAPACITY: usize = 1024;
const DEFAULT_OUI_PATH: &str = "./data/oui.csv";
const DEFAULT_AD_TLS_ADDR: &str = "0.0.0.0:5615";
const DEFAULT_DHCP_TLS_ADDR: &str = "0.0.0.0:5617";
const DEFAULT_TLS_CA: &str = "./certs/ca.pem";
const DEFAULT_TLS_CERT: &str = "./certs/server.pem";
const DEFAULT_TLS_KEY: &str = "./certs/server-key.pem";
const DEFAULT_ADMIN_HTTP_ADDR: &str = "127.0.0.1:8080";

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
pub fn resolve_vendor(mac: &str, vendors: &VendorMap) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();
    if hex.len() < 6 {
        return None;
    }
    let oui_key = &hex[..6];
    info!(oui_key = %oui_key, mac = %mac, "Looking up OUI");
    vendors.get(oui_key).cloned()
}

/// Runs the event processing loop, persisting each event to the database.
///
/// Also updates adapter stats counters for live monitoring.
///
/// Parameters: `receiver` - incoming event channel, `db` - database handle,
/// `vendors` - OUI vendor lookup table, `adapter_stats` - shared adapter stats.
/// Returns: `Ok(())` when the channel closes.
async fn run_event_loop(
    mut receiver: Receiver<IdentityEvent>,
    db: Arc<Db>,
    vendors: Arc<VendorMap>,
    adapter_stats: Arc<RwLock<Vec<AdapterStatus>>>,
) -> Result<()> {
    while let Some(event) = receiver.recv().await {
        let vendor = event
            .mac
            .as_deref()
            .and_then(|mac| resolve_vendor(mac, &vendors));
        info!(
            mac = ?event.mac,
            vendor = ?vendor,
            ip = %event.ip,
            "Vendor lookup result"
        );

        // Update adapter stats counter.
        let source_name = match event.source {
            trueid_common::model::SourceType::Radius => "RADIUS",
            trueid_common::model::SourceType::AdLog => "AD Syslog",
            trueid_common::model::SourceType::DhcpLease => "DHCP Syslog",
            trueid_common::model::SourceType::Manual => "Manual",
        };
        {
            let mut stats = adapter_stats.write().await;
            if let Some(a) = stats.iter_mut().find(|a| a.name == source_name) {
                a.events_total += 1;
                a.last_event_at = Some(Utc::now());
            }
        }

        if let Err(err) = db.upsert_mapping(event, vendor.as_deref()).await {
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

/// Periodically deactivates mappings not seen within the TTL.
///
/// Reads interval and TTL dynamically from the config table each iteration,
/// so changes via the admin API take effect without restart.
///
/// Parameters: `db` - shared database handle.
fn start_janitor(db: Arc<Db>) {
    tokio::spawn(async move {
        loop {
            let interval_secs = db.get_config_i64("janitor_interval_secs", 60).await;
            tokio::time::sleep(Duration::from_secs(interval_secs as u64)).await;

            let ttl = db.get_config_i64("stale_ttl_minutes", 5).await;
            match db.deactivate_stale(ttl).await {
                Ok(count) if count > 0 => {
                    info!(deactivated = count, ttl_minutes = ttl, "Janitor: marked stale mappings");
                }
                Ok(_) => {}
                Err(err) => {
                    warn!(error = %err, "Janitor: failed to deactivate stale mappings");
                }
            }
        }
    });
}

/// Parses a TLS heartbeat message and upserts agent info.
///
/// Expected: `... TrueID-Agent: HEARTBEAT hostname=X uptime=X events_sent=X events_dropped=X`
///
/// Parameters: `msg` - raw syslog payload, `db` - database handle.
pub async fn handle_heartbeat(msg: &str, db: &Db) {
    let payload = match msg.split("TrueID-Agent: ").nth(1) {
        Some(p) if p.starts_with("HEARTBEAT") => p,
        _ => return,
    };
    let get = |key: &str| -> Option<String> {
        payload
            .split_whitespace()
            .find(|s| s.starts_with(&format!("{}=", key)))
            .and_then(|s| s.split_once('='))
            .map(|(_, v)| v.to_string())
    };
    let hostname = match get("hostname") {
        Some(h) if !h.is_empty() => h,
        _ => return,
    };
    let uptime = get("uptime").and_then(|v| v.parse().ok()).unwrap_or(0);
    let sent = get("events_sent").and_then(|v| v.parse().ok()).unwrap_or(0);
    let dropped = get("events_dropped").and_then(|v| v.parse().ok()).unwrap_or(0);

    if let Err(err) = db.upsert_agent(&hostname, uptime, sent, dropped, "tls").await {
        warn!(error = %err, hostname = %hostname, "Failed to upsert agent heartbeat");
    }
}

/// Builds the initial adapter stats list for monitoring.
fn build_initial_adapter_stats(
    radius_addr: &str, ad_addr: &str, dhcp_addr: &str,
    ad_tls_addr: &str, dhcp_tls_addr: &str, tls_enabled: bool,
) -> Vec<AdapterStatus> {
    let tls_status = if tls_enabled { "idle" } else { "disabled" };
    vec![
        AdapterStatus { name: "RADIUS".into(), protocol: "UDP".into(), bind: radius_addr.into(), status: "idle".into(), last_event_at: None, events_total: 0 },
        AdapterStatus { name: "AD Syslog".into(), protocol: "UDP".into(), bind: ad_addr.into(), status: "idle".into(), last_event_at: None, events_total: 0 },
        AdapterStatus { name: "DHCP Syslog".into(), protocol: "UDP".into(), bind: dhcp_addr.into(), status: "idle".into(), last_event_at: None, events_total: 0 },
        AdapterStatus { name: "AD TLS".into(), protocol: "TCP+TLS".into(), bind: ad_tls_addr.into(), status: tls_status.into(), last_event_at: None, events_total: 0 },
        AdapterStatus { name: "DHCP TLS".into(), protocol: "TCP+TLS".into(), bind: dhcp_tls_addr.into(), status: tls_status.into(), last_event_at: None, events_total: 0 },
    ]
}

/// Periodically recomputes adapter status strings based on last_event_at.
fn start_adapter_status_updater(adapter_stats: Arc<RwLock<Vec<AdapterStatus>>>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let now = Utc::now();
            let mut stats = adapter_stats.write().await;
            for a in stats.iter_mut() {
                if a.status == "disabled" { continue; }
                a.status = match a.last_event_at {
                    Some(t) if (now - t).num_minutes() < 5 => "active".into(),
                    Some(_) => "idle".into(),
                    None => "idle".into(),
                };
            }
        }
    });
}

/// Starts all adapters, admin HTTP, processes events and waits for Ctrl+C.
#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let db_url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => {
            warn!("DATABASE_URL not set — using default: {}", DEFAULT_DB_URL);
            DEFAULT_DB_URL.to_string()
        }
    };
    let radius_bind_str = env_or_default("RADIUS_BIND", DEFAULT_RADIUS_ADDR);
    let ad_syslog_bind_str = env_or_default("AD_SYSLOG_BIND", DEFAULT_AD_SYSLOG_ADDR);
    let dhcp_syslog_bind_str = env_or_default("DHCP_SYSLOG_BIND", DEFAULT_DHCP_SYSLOG_ADDR);
    let radius_addr = parse_socket_addr(&radius_bind_str, DEFAULT_RADIUS_ADDR)?;
    let ad_syslog_addr = parse_socket_addr(&ad_syslog_bind_str, DEFAULT_AD_SYSLOG_ADDR)?;
    let dhcp_syslog_addr = parse_socket_addr(&dhcp_syslog_bind_str, DEFAULT_DHCP_SYSLOG_ADDR)?;
    let radius_secret = env_or_default("RADIUS_SECRET", "secret");
    let admin_bind_str = env_or_default("ADMIN_HTTP_BIND", DEFAULT_ADMIN_HTTP_ADDR);
    let admin_addr = parse_socket_addr(&admin_bind_str, DEFAULT_ADMIN_HTTP_ADDR)?;

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

    // TLS paths.
    let tls_ca = env_or_default("TLS_CA_CERT", DEFAULT_TLS_CA);
    let tls_cert = env_or_default("TLS_SERVER_CERT", DEFAULT_TLS_CERT);
    let tls_key = env_or_default("TLS_SERVER_KEY", DEFAULT_TLS_KEY);
    let ad_tls_bind_str = env_or_default("AD_TLS_BIND", DEFAULT_AD_TLS_ADDR);
    let dhcp_tls_bind_str = env_or_default("DHCP_TLS_BIND", DEFAULT_DHCP_TLS_ADDR);
    let tls_files_exist = Path::new(&tls_ca).exists()
        && Path::new(&tls_cert).exists()
        && Path::new(&tls_key).exists();

    // Adapter stats (shared with admin API).
    let adapter_stats = Arc::new(RwLock::new(build_initial_adapter_stats(
        &radius_bind_str, &ad_syslog_bind_str, &dhcp_syslog_bind_str,
        &ad_tls_bind_str, &dhcp_tls_bind_str, tls_files_exist,
    )));
    start_adapter_status_updater(adapter_stats.clone());

    // Runtime env snapshot for E4.
    let runtime_env = Arc::new(RuntimeEnv {
        database_url: db_url.clone(),
        radius_bind: radius_bind_str.clone(),
        radius_secret_set: radius_secret != "secret",
        ad_syslog_bind: ad_syslog_bind_str.clone(),
        dhcp_syslog_bind: dhcp_syslog_bind_str.clone(),
        ad_tls_bind: ad_tls_bind_str.clone(),
        dhcp_tls_bind: dhcp_tls_bind_str.clone(),
        tls_enabled: tls_files_exist,
        tls_ca_exists: Path::new(&tls_ca).exists(),
        tls_cert_exists: Path::new(&tls_cert).exists(),
        tls_key_exists: Path::new(&tls_key).exists(),
        oui_csv_path: oui_path.clone(),
        admin_http_bind: admin_bind_str.clone(),
    });

    // Admin HTTP API (:8080).
    let service_token = std::env::var("ENGINE_SERVICE_TOKEN").ok().filter(|s| !s.is_empty());
    if service_token.is_none() {
        warn!("ENGINE_SERVICE_TOKEN not set — admin API is unprotected.");
    }

    let admin_state = EngineAdminState {
        db: db.clone(),
        vendors: vendors.clone(),
        adapter_stats: adapter_stats.clone(),
        runtime_env,
        service_token,
    };
    let admin_router: Router = admin_api::admin_router(admin_state);
    info!(%admin_addr, "Starting admin HTTP API");
    let admin_listener = tokio::net::TcpListener::bind(admin_addr).await?;
    tokio::spawn(async move {
        if let Err(err) = axum::serve(admin_listener, admin_router).await {
            warn!(error = %err, "Admin HTTP server stopped");
        }
    });

    let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
    let event_db = db.clone();
    let event_vendors = vendors.clone();
    let event_adapter_stats = adapter_stats.clone();
    tokio::spawn(async move {
        if let Err(err) = run_event_loop(receiver, event_db, event_vendors, event_adapter_stats).await {
            warn!(error = %err, "Event loop stopped");
        }
    });

    spawn_radius_adapter(radius_addr, radius_secret.as_bytes(), sender.clone());
    spawn_ad_logs_adapter(ad_syslog_addr, sender.clone());
    spawn_dhcp_logs_adapter(dhcp_syslog_addr, sender.clone());
    start_janitor(db.clone());

    // Optional TLS listeners (only started if cert files exist).
    if tls_files_exist {
        match tls_listener::build_tls_acceptor(
            Path::new(&tls_ca),
            Path::new(&tls_cert),
            Path::new(&tls_key),
        ) {
            Ok(acceptor) => {
                let ad_tls_addr = parse_socket_addr(&ad_tls_bind_str, DEFAULT_AD_TLS_ADDR)?;
                let dhcp_tls_addr = parse_socket_addr(&dhcp_tls_bind_str, DEFAULT_DHCP_TLS_ADDR)?;

                // AD TLS listener — feeds into the same sender as UDP AD adapter.
                let ad_sender = sender.clone();
                let ad_db = db.clone();
                let ad_acceptor = acceptor.clone();
                let ad_handler: tls_listener::MessageHandler =
                    Arc::new(move |msg: &str, _peer: SocketAddr| {
                        // Check for heartbeat first.
                        let hb_db = ad_db.clone();
                        let hb_msg = msg.to_string();
                        tokio::spawn(async move { handle_heartbeat(&hb_msg, &hb_db).await });

                        if let Ok(Some(event)) = parse_tls_syslog_ad(msg) {
                            let s = ad_sender.clone();
                            tokio::spawn(async move {
                                if let Err(err) = s.send(event).await {
                                    warn!(error = %err, "Failed to send TLS AD event");
                                }
                            });
                        }
                    });
                tokio::spawn(async move {
                    if let Err(err) =
                        tls_listener::run_tls_listener(ad_tls_addr, ad_acceptor, ad_handler, "AD-TLS")
                            .await
                    {
                        warn!(error = %err, "AD TLS listener stopped");
                    }
                });

                // DHCP TLS listener.
                let dhcp_sender = sender.clone();
                let dhcp_db = db.clone();
                let dhcp_handler: tls_listener::MessageHandler =
                    Arc::new(move |msg: &str, _peer: SocketAddr| {
                        let hb_db = dhcp_db.clone();
                        let hb_msg = msg.to_string();
                        tokio::spawn(async move { handle_heartbeat(&hb_msg, &hb_db).await });

                        if let Ok(Some(event)) = parse_tls_syslog_dhcp(msg) {
                            let s = dhcp_sender.clone();
                            tokio::spawn(async move {
                                if let Err(err) = s.send(event).await {
                                    warn!(error = %err, "Failed to send TLS DHCP event");
                                }
                            });
                        }
                    });
                tokio::spawn(async move {
                    if let Err(err) =
                        tls_listener::run_tls_listener(dhcp_tls_addr, acceptor, dhcp_handler, "DHCP-TLS")
                            .await
                    {
                        warn!(error = %err, "DHCP TLS listener stopped");
                    }
                });

                info!("TLS listeners started (AD: {}, DHCP: {})", ad_tls_addr, dhcp_tls_addr);
            }
            Err(err) => {
                warn!(error = %err, "Failed to build TLS acceptor — TLS listeners disabled");
            }
        }
    } else {
        info!("TLS cert files not found — TLS listeners disabled (UDP-only mode)");
    }

    info!("Engine running — press Ctrl+C to stop");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    db.close().await;

    Ok(())
}

/// Parses a TLS-transported AD syslog message into an IdentityEvent.
///
/// Expected format: `<PRI>... TrueID-Agent: AD_LOGON user=X ip=X port=X event_id=X status=X`
///
/// Parameters: `msg` - raw syslog payload.
/// Returns: optional IdentityEvent if the message matches.
fn parse_tls_syslog_ad(msg: &str) -> anyhow::Result<Option<IdentityEvent>> {
    let payload = msg.split("TrueID-Agent: ").nth(1).unwrap_or("");
    if !payload.starts_with("AD_LOGON") {
        return Ok(None);
    }
    let get = |key: &str| -> Option<String> {
        payload
            .split_whitespace()
            .find(|s| s.starts_with(&format!("{}=", key)))
            .and_then(|s| s.split_once('='))
            .map(|(_, v)| v.to_string())
    };
    let user = get("user").unwrap_or_default();
    let ip_str = get("ip").unwrap_or_default();
    let ip: std::net::IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return Ok(None),
    };
    Ok(Some(IdentityEvent {
        source: trueid_common::model::SourceType::AdLog,
        ip,
        user,
        timestamp: chrono::Utc::now(),
        raw_data: msg.to_string(),
        mac: None,
        confidence_score: 90,
    }))
}

/// Parses a TLS-transported DHCP syslog message into an IdentityEvent.
///
/// Expected format: `<PRI>... TrueID-Agent: DHCP_LEASE ip=X mac=X hostname=X lease=X`
///
/// Parameters: `msg` - raw syslog payload.
/// Returns: optional IdentityEvent if the message matches.
fn parse_tls_syslog_dhcp(msg: &str) -> anyhow::Result<Option<IdentityEvent>> {
    let payload = msg.split("TrueID-Agent: ").nth(1).unwrap_or("");
    if !payload.starts_with("DHCP_LEASE") {
        return Ok(None);
    }
    let get = |key: &str| -> Option<String> {
        payload
            .split_whitespace()
            .find(|s| s.starts_with(&format!("{}=", key)))
            .and_then(|s| s.split_once('='))
            .map(|(_, v)| v.to_string())
    };
    let ip_str = get("ip").unwrap_or_default();
    let ip: std::net::IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return Ok(None),
    };
    let mac = get("mac");
    let hostname = get("hostname").unwrap_or_default();
    Ok(Some(IdentityEvent {
        source: trueid_common::model::SourceType::DhcpLease,
        ip,
        user: hostname,
        timestamp: chrono::Utc::now(),
        raw_data: msg.to_string(),
        mac,
        confidence_score: 60,
    }))
}
