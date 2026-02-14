//! TrueID Engine — ingestion + admin API process.
//!
//! Starts RADIUS, AD syslog and DHCP syslog adapters (UDP, legacy),
//! optional TLS syslog listeners (secure), processes incoming identity
//! events and persists them to SQLite. Exposes an internal Admin HTTP
//! API on a separate port for configuration and monitoring.

mod adapter_status;
mod admin_api;
mod alerts;
mod conflicts;
mod dns_resolver;
mod fingerprints;
mod firewall_push;
mod ldap_sync;
mod live_bus;
mod metrics;
mod notifications;
mod report_generator;
mod retention;
mod scheduler;
mod siem_forwarder;
mod snmp_poller;
mod subnets;
mod tls_listener;
mod tls_parsers;
mod vendor;
mod vpn_adapters;

use anyhow::Result;
use axum::Router;
use chrono::Utc;
use net_identity_adapter_ad_logs::AdLogsAdapter;
use net_identity_adapter_dhcp_logs::DhcpLogsAdapter;
use net_identity_adapter_radius::RadiusAdapter;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use trueid_common::db::Db;
use trueid_common::live_event::LiveEvent;
use trueid_common::model::{AdapterStatus, IdentityEvent, SourceType};
use trueid_common::{env_or_default, parse_socket_addr};

use crate::admin_api::{EngineAdminState, RuntimeEnv};
pub(crate) use crate::vendor::resolve_vendor;
use crate::vendor::{load_oui_csv, VendorMap};

const DEFAULT_DB_URL: &str = "sqlite://net-identity.db?mode=rwc";
const DEFAULT_RADIUS_ADDR: &str = "0.0.0.0:1813";
const DEFAULT_AD_SYSLOG_ADDR: &str = "0.0.0.0:5514";
const DEFAULT_DHCP_SYSLOG_ADDR: &str = "0.0.0.0:5516";
const DEFAULT_VPN_SYSLOG_ADDR: &str = "0.0.0.0:5518";
const CHANNEL_CAPACITY: usize = 1024;
const DEFAULT_OUI_PATH: &str = "./data/oui.csv";
const DEFAULT_AD_TLS_ADDR: &str = "0.0.0.0:5615";
const DEFAULT_DHCP_TLS_ADDR: &str = "0.0.0.0:5617";
const DEFAULT_TLS_CA: &str = "./certs/ca.pem";
const DEFAULT_TLS_CERT: &str = "./certs/server.pem";
const DEFAULT_TLS_KEY: &str = "./certs/server-key.pem";
const DEFAULT_ADMIN_HTTP_ADDR: &str = "127.0.0.1:8080";
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Shared context for the event processing loop.
struct EventLoopCtx {
    db: Arc<Db>,
    vendors: Arc<VendorMap>,
    adapter_stats: Arc<RwLock<Vec<AdapterStatus>>>,
    subnet_cache: Arc<RwLock<Vec<subnets::SubnetEntry>>>,
    fingerprint_db: Arc<RwLock<fingerprints::FingerprintDb>>,
    alert_rules: Arc<RwLock<Vec<alerts::AlertRule>>>,
    http_client: reqwest::Client,
    siem_sender: Sender<siem_forwarder::SiemEvent>,
    notification_dispatcher: Arc<notifications::NotificationDispatcher>,
}

/// Runs the event processing loop, persisting each event to the database.
///
/// Also updates adapter stats counters for live monitoring.
///
/// Parameters: `receiver` - incoming event channel, `ctx` - shared loop context.
/// Returns: `Ok(())` when the channel closes.
async fn run_event_loop(mut receiver: Receiver<IdentityEvent>, ctx: EventLoopCtx) -> Result<()> {
    let EventLoopCtx {
        db,
        vendors,
        adapter_stats,
        subnet_cache,
        fingerprint_db,
        alert_rules,
        http_client,
        siem_sender,
        notification_dispatcher,
    } = ctx;
    while let Some(event) = receiver.recv().await {
        let ip_str = event.ip.to_string();
        let dhcp_options55 = if matches!(event.source, SourceType::DhcpLease) {
            tls_parsers::extract_field_value(&event.raw_data, "options55")
        } else {
            None
        };
        let event_mac = event.mac.clone();
        let dhcp_hostname =
            if matches!(event.source, SourceType::DhcpLease) && !event.user.is_empty() {
                Some(event.user.clone())
            } else {
                None
            };
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
            trueid_common::model::SourceType::VpnAnyConnect
            | trueid_common::model::SourceType::VpnGlobalProtect
            | trueid_common::model::SourceType::VpnFortinet => "VPN Syslog",
            trueid_common::model::SourceType::Manual => "Manual",
        };
        {
            let mut stats = adapter_stats.write().await;
            if let Some(a) = stats.iter_mut().find(|a| a.name == source_name) {
                a.events_total += 1;
                a.last_event_at = Some(Utc::now());
            }
        }

        let detected_conflicts = match conflicts::detect_conflicts(db.pool(), &event).await {
            Ok(detected) => {
                for c in &detected {
                    warn!(
                        conflict_type = %c.conflict_type,
                        severity = %c.severity,
                        ip = ?c.ip,
                        user_old = ?c.user_old,
                        user_new = ?c.user_new,
                        "Conflict detected"
                    );
                    let _ = siem_sender.try_send(siem_forwarder::SiemEvent::Conflict {
                        ip: c.ip.clone(),
                        user_old: c.user_old.clone(),
                        user_new: c.user_new.clone(),
                        conflict_type: c.conflict_type.clone(),
                        severity: c.severity.clone(),
                        timestamp: Utc::now(),
                    });
                    live_bus::send(LiveEvent::ConflictDetected {
                        id: c.id,
                        conflict_type: c.conflict_type.clone(),
                        severity: c.severity.clone(),
                        ip: c.ip.clone(),
                        user_old: c.user_old.clone(),
                        user_new: c.user_new.clone(),
                        detected_at: c.detected_at,
                    });
                }
                detected
            }
            Err(err) => {
                warn!(
                    error = %err,
                    ip = %ip_str,
                    "Conflict detection failed — continuing with upsert"
                );
                Vec::new()
            }
        };

        {
            let rules = alert_rules.read().await;
            let firings =
                alerts::evaluate_event(db.pool(), &event, &detected_conflicts, &rules).await;
            for firing in firings {
                let _ = siem_sender.try_send(siem_forwarder::SiemEvent::Alert {
                    rule_name: firing.rule_name.clone(),
                    severity: firing.severity.clone(),
                    ip: firing.ip.clone(),
                    user: firing.user_name.clone(),
                    message: firing.details.clone(),
                    timestamp: Utc::now(),
                });
                let db_for_alert = db.clone();
                let client = http_client.clone();
                let dispatcher = notification_dispatcher.clone();
                live_bus::send(LiveEvent::AlertFired {
                    rule_name: firing.rule_name.clone(),
                    rule_type: firing.rule_type.clone(),
                    severity: firing.severity.clone(),
                    ip: firing.ip.clone(),
                    user: firing.user_name.clone(),
                    fired_at: Utc::now(),
                });
                tokio::spawn(async move {
                    alerts::fire_alert(
                        db_for_alert.as_ref(),
                        &client,
                        dispatcher.as_ref(),
                        &firing,
                    )
                    .await;
                });
            }
        }

        let siem_mapping_event = siem_forwarder::SiemEvent::Mapping {
            ip: ip_str.clone(),
            user: event.user.clone(),
            mac: event.mac.clone(),
            source: source_name.to_string(),
            vendor: vendor.clone(),
            device_type: None,
            confidence: event.confidence_score,
            timestamp: event.timestamp,
        };
        let mapping_user = event.user.clone();
        let mapping_mac = event.mac.clone();
        let mapping_timestamp = event.timestamp;
        let mapping_source = source_name.to_string();
        if let Err(err) = db.upsert_mapping(event, vendor.as_deref()).await {
            warn!(error = %err, "Failed to upsert mapping");
            continue;
        }
        live_bus::send(LiveEvent::MappingUpdate {
            ip: ip_str.clone(),
            user: mapping_user,
            mac: mapping_mac,
            source: mapping_source,
            timestamp: mapping_timestamp,
        });
        let _ = siem_sender.try_send(siem_mapping_event);

        {
            let subnets = subnet_cache.read().await;
            if let Err(e) = subnets::tag_subnet(db.pool(), &ip_str, &subnets).await {
                warn!(error = %e, ip = %ip_str, "Subnet tagging failed");
            }
        }

        if let (Some(options55), Some(mac)) = (dhcp_options55.as_deref(), event_mac.as_deref()) {
            if let Some(normalized) = fingerprints::normalize_fingerprint(options55) {
                let device_type = {
                    let fp_db = fingerprint_db.read().await;
                    fingerprints::match_fingerprint(&normalized, &fp_db)
                };
                if let Err(e) = fingerprints::record_observation(
                    db.pool(),
                    mac,
                    &ip_str,
                    &normalized,
                    dhcp_hostname.as_deref(),
                    device_type.as_deref(),
                )
                .await
                {
                    warn!(error = %e, mac = %mac, "Fingerprint observation failed");
                }
            }
        }
    }
    Ok(())
}

/// Spawns the RADIUS adapter task.
///
/// Parameters: `bind_addr` - UDP bind address, `secret` - shared secret,
/// `sender` - event channel.
fn spawn_radius_adapter(
    bind_addr: SocketAddr,
    secret: &[u8],
    sender: Sender<IdentityEvent>,
) -> JoinHandle<()> {
    let adapter = RadiusAdapter::new(bind_addr, secret, sender);
    info!(%bind_addr, "Starting RADIUS adapter");
    tokio::spawn(async move {
        if let Err(err) = adapter.run().await {
            warn!(error = %err, "RADIUS adapter stopped");
        }
    })
}

/// Spawns the AD syslog adapter task.
///
/// Parameters: `bind_addr` - UDP/TCP bind address, `sender` - event channel.
fn spawn_ad_logs_adapter(bind_addr: SocketAddr, sender: Sender<IdentityEvent>) -> JoinHandle<()> {
    let adapter = AdLogsAdapter::new(bind_addr, sender);
    info!(%bind_addr, "Starting AD syslog adapter");
    tokio::spawn(async move {
        if let Err(err) = adapter.run().await {
            warn!(error = %err, "AD syslog adapter stopped");
        }
    })
}

/// Spawns the DHCP syslog adapter task.
///
/// Parameters: `bind_addr` - UDP bind address, `sender` - event channel.
fn spawn_dhcp_logs_adapter(bind_addr: SocketAddr, sender: Sender<IdentityEvent>) -> JoinHandle<()> {
    let adapter = DhcpLogsAdapter::new(bind_addr, sender);
    info!(%bind_addr, "Starting DHCP syslog adapter");
    tokio::spawn(async move {
        if let Err(err) = adapter.run().await {
            warn!(error = %err, "DHCP adapter stopped");
        }
    })
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
                    info!(
                        deactivated = count,
                        ttl_minutes = ttl,
                        "Janitor: marked stale mappings"
                    );
                }
                Ok(_) => {}
                Err(err) => {
                    warn!(error = %err, "Janitor: failed to deactivate stale mappings");
                }
            }
        }
    });
}

/// Starts all adapters, admin HTTP, processes events and waits for Ctrl+C.
#[tokio::main]
async fn main() -> Result<()> {
    let start_time = std::time::Instant::now();
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
    let vpn_syslog_bind_str = env_or_default("VPN_SYSLOG_BIND", DEFAULT_VPN_SYSLOG_ADDR);
    let radius_addr = parse_socket_addr(&radius_bind_str, DEFAULT_RADIUS_ADDR)?;
    let ad_syslog_addr = parse_socket_addr(&ad_syslog_bind_str, DEFAULT_AD_SYSLOG_ADDR)?;
    let dhcp_syslog_addr = parse_socket_addr(&dhcp_syslog_bind_str, DEFAULT_DHCP_SYSLOG_ADDR)?;
    let vpn_syslog_addr = parse_socket_addr(&vpn_syslog_bind_str, DEFAULT_VPN_SYSLOG_ADDR)?;
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
            Arc::new(VendorMap::new())
        }
    };

    info!(db_url = %db_url, "Initializing database");
    let db = Arc::new(trueid_common::db::init_db(&db_url).await?);
    let (live_tx, _) = tokio::sync::broadcast::channel::<LiveEvent>(1024);
    live_bus::set_sender(live_tx.clone());

    // DHCP fingerprint DB loaded at startup and refreshed in background.
    let fingerprint_db: Arc<RwLock<fingerprints::FingerprintDb>> = Arc::new(RwLock::new(
        fingerprints::load_fingerprints(db.pool())
            .await
            .unwrap_or_default(),
    ));
    {
        let reload_fp_db = fingerprint_db.clone();
        let reload_fp_pool = db.pool().clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                match fingerprints::load_fingerprints(&reload_fp_pool).await {
                    Ok(new_db) => *reload_fp_db.write().await = new_db,
                    Err(e) => warn!(error = %e, "Failed to reload fingerprint DB"),
                }
            }
        });
    }
    if let Err(e) = fingerprints::backfill_device_types(db.pool()).await {
        warn!(error = %e, "Failed to backfill mapping device types");
    }

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
    let adapter_stats = Arc::new(RwLock::new(adapter_status::build_initial_adapter_stats(
        &radius_bind_str,
        &ad_syslog_bind_str,
        &dhcp_syslog_bind_str,
        &vpn_syslog_bind_str,
        &ad_tls_bind_str,
        &dhcp_tls_bind_str,
        tls_files_exist,
    )));
    adapter_status::start_adapter_status_updater(adapter_stats.clone());

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
    let service_token = std::env::var("ENGINE_SERVICE_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    if service_token.is_none() {
        warn!("ENGINE_SERVICE_TOKEN not set — admin API is unprotected.");
    }

    let admin_state = EngineAdminState {
        db: db.clone(),
        vendors: vendors.clone(),
        adapter_stats: adapter_stats.clone(),
        runtime_env,
        service_token,
        start_time,
        live_tx: live_tx.clone(),
    };
    let admin_router: Router = admin_api::admin_router(admin_state);
    info!(%admin_addr, "Starting admin HTTP API");
    let admin_listener = tokio::net::TcpListener::bind(admin_addr).await?;
    tokio::spawn(async move {
        if let Err(err) = axum::serve(admin_listener, admin_router).await {
            warn!(error = %err, "Admin HTTP server stopped");
        }
    });

    // Alert rule cache loaded at startup and refreshed in background.
    let alert_rules: Arc<RwLock<Vec<alerts::AlertRule>>> = Arc::new(RwLock::new(
        alerts::load_rules(db.pool()).await.unwrap_or_default(),
    ));
    {
        let reload_db = db.clone();
        let reload_rules = alert_rules.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                match alerts::load_rules(reload_db.pool()).await {
                    Ok(rules) => *reload_rules.write().await = rules,
                    Err(err) => warn!(error = %err, "Failed to reload alert rules"),
                }
            }
        });
    }

    // Subnet cache loaded at startup and refreshed in background.
    let subnet_cache: Arc<RwLock<Vec<subnets::SubnetEntry>>> = Arc::new(RwLock::new(
        subnets::load_subnets(db.pool()).await.unwrap_or_default(),
    ));
    {
        let reload_db = db.clone();
        let reload_cache = subnet_cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                match subnets::load_subnets(reload_db.pool()).await {
                    Ok(loaded) => {
                        let mut cache = reload_cache.write().await;
                        *cache = loaded;
                    }
                    Err(e) => warn!(error = %e, "Failed to reload subnet cache"),
                }
            }
        });
    }

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to build HTTP client");
    let (siem_sender, siem_receiver) = siem_forwarder::create_siem_channel();
    let notification_dispatcher = Arc::new(notifications::NotificationDispatcher::new(
        db.clone(),
        http_client.clone(),
    ));
    let siem_forwarder_handle = {
        let siem_pool = db.pool().clone();
        tokio::spawn(async move {
            siem_forwarder::run_siem_forwarder(siem_receiver, siem_pool).await;
        })
    };

    let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
    let event_db = db.clone();
    let event_vendors = vendors.clone();
    let event_adapter_stats = adapter_stats.clone();
    let event_subnet_cache = subnet_cache.clone();
    let event_fingerprint_db = fingerprint_db.clone();
    let event_alert_rules = alert_rules.clone();
    let event_http_client = http_client.clone();
    let event_siem_sender = siem_sender.clone();
    let event_ctx = EventLoopCtx {
        db: event_db,
        vendors: event_vendors,
        adapter_stats: event_adapter_stats,
        subnet_cache: event_subnet_cache,
        fingerprint_db: event_fingerprint_db,
        alert_rules: event_alert_rules,
        http_client: event_http_client,
        siem_sender: event_siem_sender,
        notification_dispatcher,
    };
    let event_loop_handle = tokio::spawn(async move {
        if let Err(err) = run_event_loop(receiver, event_ctx).await {
            warn!(error = %err, "Event loop stopped");
        }
    });

    let radius_handle = spawn_radius_adapter(radius_addr, radius_secret.as_bytes(), sender.clone());
    let ad_handle = spawn_ad_logs_adapter(ad_syslog_addr, sender.clone());
    let dhcp_handle = spawn_dhcp_logs_adapter(dhcp_syslog_addr, sender.clone());
    let vpn_handle = {
        let vpn_sender = sender.clone();
        tokio::spawn(async move {
            if let Err(e) = vpn_adapters::run_vpn_listener(vpn_syslog_addr, vpn_sender).await {
                warn!(error = %e, "VPN syslog adapter stopped");
            }
        })
    };
    start_janitor(db.clone());
    dns_resolver::start_dns_resolver(db.clone());
    snmp_poller::start_snmp_poller(db.clone());
    firewall_push::start_firewall_push(db.clone());
    report_generator::start_report_generator(db.clone());
    {
        let retention_interval_hours = db
            .get_config_i64("retention_interval_hours", 6)
            .await
            .max(1);
        let mut background_scheduler = scheduler::Scheduler::new();
        let retention_db = db.clone();
        background_scheduler.add(
            "retention",
            Duration::from_secs((retention_interval_hours as u64) * 3600),
            move || {
                let retention_db = retention_db.clone();
                Box::pin(async move {
                    let executor =
                        retention::RetentionExecutor::from_db(retention_db.as_ref()).await;
                    for r in executor.run_all().await {
                        if r.deleted > 0 {
                            info!(
                                table = %r.table_name,
                                deleted = r.deleted,
                                "Retention cleanup deleted rows"
                            );
                        }
                    }
                })
            },
        );
        let heartbeat_tx = live_tx.clone();
        background_scheduler.add("heartbeat", Duration::from_secs(30), move || {
            let heartbeat_tx = heartbeat_tx.clone();
            Box::pin(async move {
                let _ = heartbeat_tx.send(LiveEvent::Heartbeat {
                    timestamp: Utc::now(),
                });
            })
        });
        tokio::spawn(background_scheduler.run());
    }
    {
        let ldap_db = db.clone();
        tokio::spawn(async move {
            ldap_sync::run_ldap_sync(ldap_db).await;
        });
    }

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
                        tokio::spawn(async move {
                            tls_parsers::handle_heartbeat(&hb_msg, &hb_db).await
                        });

                        if let Ok(Some(event)) = tls_parsers::parse_tls_syslog_ad(msg) {
                            let s = ad_sender.clone();
                            tokio::spawn(async move {
                                if let Err(err) = s.send(event).await {
                                    warn!(error = %err, "Failed to send TLS AD event");
                                }
                            });
                        }
                        if let Ok(Some(event)) = tls_parsers::parse_tls_syslog_vpn(msg) {
                            let s = ad_sender.clone();
                            tokio::spawn(async move {
                                if let Err(err) = s.send(event).await {
                                    warn!(error = %err, "Failed to send TLS VPN event");
                                }
                            });
                        }
                    });
                tokio::spawn(async move {
                    if let Err(err) = tls_listener::run_tls_listener(
                        ad_tls_addr,
                        ad_acceptor,
                        ad_handler,
                        "AD-TLS",
                    )
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
                        tokio::spawn(async move {
                            tls_parsers::handle_heartbeat(&hb_msg, &hb_db).await
                        });

                        if let Ok(Some((event, _options55))) =
                            tls_parsers::parse_tls_syslog_dhcp(msg)
                        {
                            let s = dhcp_sender.clone();
                            tokio::spawn(async move {
                                if let Err(err) = s.send(event).await {
                                    warn!(error = %err, "Failed to send TLS DHCP event");
                                }
                            });
                        }
                        if let Ok(Some(event)) = tls_parsers::parse_tls_syslog_vpn(msg) {
                            let s = dhcp_sender.clone();
                            tokio::spawn(async move {
                                if let Err(err) = s.send(event).await {
                                    warn!(error = %err, "Failed to send TLS VPN event");
                                }
                            });
                        }
                    });
                tokio::spawn(async move {
                    if let Err(err) = tls_listener::run_tls_listener(
                        dhcp_tls_addr,
                        acceptor,
                        dhcp_handler,
                        "DHCP-TLS",
                    )
                    .await
                    {
                        warn!(error = %err, "DHCP TLS listener stopped");
                    }
                });

                info!(
                    "TLS listeners started (AD: {}, DHCP: {})",
                    ad_tls_addr, dhcp_tls_addr
                );
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
    info!("Shutting down gracefully...");
    SHUTDOWN.store(true, Ordering::SeqCst);
    firewall_push::set_shutdown(true);

    // Stop listeners first to avoid ingesting new events during drain.
    radius_handle.abort();
    ad_handle.abort();
    dhcp_handle.abort();
    vpn_handle.abort();

    // Close event channel and let in-flight events drain.
    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(5), event_loop_handle).await;

    // Close SIEM sender and give forwarder loop a chance to flush counters.
    drop(siem_sender);
    let _ = tokio::time::timeout(Duration::from_secs(5), siem_forwarder_handle).await;

    db.close().await;
    info!("Shutdown complete.");

    Ok(())
}
