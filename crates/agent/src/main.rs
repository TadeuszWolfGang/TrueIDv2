//! TrueID Agent — Windows Event Log collector with TCP+TLS transport.
//!
//! Subcommands:
//!   install    Register as a Windows Service
//!   uninstall  Remove the Windows Service
//!   run        Run interactively (console / debug mode)

mod collector;
mod config;
mod heartbeat;
mod service;
mod tls;
mod transport;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::{AgentMode, resolve_hostname};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[cfg(windows)]
use crate::collector::{ad_events, dhcp_events};
use crate::transport::{syslog, tls_sender::SenderStats};

#[derive(Parser)]
#[command(name = "net-identity-agent", version, about = "TrueID Identity Agent")]
struct Cli {
    /// Path to config.toml.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register as a Windows Service.
    Install,
    /// Remove the Windows Service.
    Uninstall,
    /// Run interactively (debug / console mode).
    Run {
        /// Print parsed events to stdout instead of sending over TLS.
        #[arg(long)]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Install => service::install()?,
        Commands::Uninstall => service::uninstall()?,
        Commands::Run { dry_run } => run_agent(&cli.config, dry_run).await?,
    }

    Ok(())
}

/// Main agent loop — loads config, connects TLS, subscribes to events.
///
/// Parameters: `config_path` - path to config.toml, `dry_run` - print only.
/// Returns: `Ok(())` on clean shutdown or an error.
async fn run_agent(config_path: &PathBuf, dry_run: bool) -> Result<()> {
    let cfg = config::load_config(config_path)?;
    let hostname = resolve_hostname(cfg.agent.hostname.as_deref());
    info!(hostname = %hostname, mode = ?cfg.agent.mode, "Starting agent");

    if dry_run {
        info!("Dry-run mode — events will be printed, not sent");
        return run_dry(cfg, &hostname).await;
    }

    // Build TLS connector.
    let connector = tls::config::build_tls_connector(
        &cfg.tls.ca_cert,
        &cfg.tls.client_cert,
        &cfg.tls.client_key,
    )?;

    let stats = Arc::new(SenderStats::new());

    // Create per-mode sender channels and spawn TLS senders.
    let ad_tx = if cfg.agent.mode == AgentMode::Ad || cfg.agent.mode == AgentMode::Both {
        let (tx, rx) = mpsc::channel(cfg.agent.buffer_size);
        let c = connector.clone();
        let s = cfg.target.server.clone();
        let st = Arc::clone(&stats);
        let bs = cfg.connection.reconnect_interval_secs;
        let cap = cfg.agent.buffer_size;
        tokio::spawn(async move {
            tls_sender::run_sender(c, s, cfg.target.ad_port, rx, cap, &st, bs).await;
        });
        Some(tx)
    } else {
        None
    };

    let dhcp_tx = if cfg.agent.mode == AgentMode::Dhcp || cfg.agent.mode == AgentMode::Both {
        let (tx, rx) = mpsc::channel(cfg.agent.buffer_size);
        let c = connector.clone();
        let s = cfg.target.server.clone();
        let st = Arc::clone(&stats);
        let bs = cfg.connection.reconnect_interval_secs;
        let cap = cfg.agent.buffer_size;
        tokio::spawn(async move {
            tls_sender::run_sender(c, s, cfg.target.dhcp_port, rx, cap, &st, bs).await;
        });
        Some(tx)
    } else {
        None
    };

    // Spawn heartbeat.
    if let Some(ref tx) = ad_tx.as_ref().or(dhcp_tx.as_ref()) {
        let htx = (*tx).clone();
        let hhost = hostname.clone();
        let hstats = Arc::clone(&stats);
        tokio::spawn(async move {
            heartbeat::run_heartbeat(hhost, htx, &hstats, Duration::from_secs(60)).await;
        });
    }

    // Subscribe to event logs (Windows only).
    #[cfg(windows)]
    {
        use tokio::sync::mpsc as tokio_mpsc;

        if let Some(ref ad_sender) = ad_tx {
            let (raw_tx, mut raw_rx) = tokio_mpsc::unbounded_channel::<String>();
            let hn = hostname.clone();
            let sender = ad_sender.clone();
            tokio::spawn(async move {
                while let Some(xml) = raw_rx.recv().await {
                    match ad_events::parse_ad_xml(&xml) {
                        Ok(ev) => {
                            let payload = syslog::format_ad_event(
                                &hn, &ev.user, &ev.ip, &ev.port, ev.event_id, &ev.status,
                            );
                            let frame = syslog::frame_octet_counting(&payload);
                            let _ = sender.send(frame).await;
                        }
                        Err(err) => warn!(error = %err, "Failed to parse AD event"),
                    }
                }
            });
            let query = r#"<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4768 or EventID=4769 or EventID=4770 or EventID=4624 or EventID=4625)]]</Select></Query></QueryList>"#;
            collector::evtlog::subscribe("Security", query, raw_tx)?;
        }

        if let Some(ref dhcp_sender) = dhcp_tx {
            let (raw_tx, mut raw_rx) = tokio_mpsc::unbounded_channel::<String>();
            let hn = hostname.clone();
            let sender = dhcp_sender.clone();
            tokio::spawn(async move {
                while let Some(xml) = raw_rx.recv().await {
                    match dhcp_events::parse_dhcp_xml(&xml) {
                        Ok(ev) => {
                            let payload = syslog::format_dhcp_event(
                                &hn, &ev.ip, &ev.mac, &ev.hostname, ev.lease_duration,
                            );
                            let frame = syslog::frame_octet_counting(&payload);
                            let _ = sender.send(frame).await;
                        }
                        Err(err) => warn!(error = %err, "Failed to parse DHCP event"),
                    }
                }
            });
            let query = r#"<QueryList><Query Id="0" Path="Microsoft-Windows-DHCP-Server/Operational"><Select Path="Microsoft-Windows-DHCP-Server/Operational">*[System[(EventID=10 or EventID=11 or EventID=12 or EventID=15)]]</Select></Query></QueryList>"#;
            collector::evtlog::subscribe(
                "Microsoft-Windows-DHCP-Server/Operational",
                query,
                raw_tx,
            )?;
        }
    }

    #[cfg(not(windows))]
    {
        warn!("Event Log subscription not available on this platform");
        warn!("Agent will idle — use --dry-run for testing parsers");
    }

    info!("Agent running — press Ctrl+C to stop");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    Ok(())
}

/// Dry-run mode: prints sample syslog output without TLS.
///
/// Parameters: `cfg` - agent config, `hostname` - resolved hostname.
/// Returns: `Ok(())` after Ctrl+C.
async fn run_dry(_cfg: config::AgentConfig, hostname: &str) -> Result<()> {
    let sample_ad = syslog::format_ad_event(
        hostname, "jan.kowalski", "10.0.1.50", "52431", 4768, "0x0",
    );
    let sample_dhcp = syslog::format_dhcp_event(
        hostname, "10.0.1.50", "AA:BB:CC:DD:EE:FF", "WORKSTATION01", 86400,
    );
    info!("Sample AD syslog:   {}", sample_ad);
    info!("Sample DHCP syslog: {}", sample_dhcp);
    info!("Framed AD:   {:?}", String::from_utf8_lossy(&syslog::frame_octet_counting(&sample_ad)));
    info!("Framed DHCP: {:?}", String::from_utf8_lossy(&syslog::frame_octet_counting(&sample_dhcp)));

    info!("Dry-run complete. Press Ctrl+C to exit.");
    tokio::signal::ctrl_c().await?;
    Ok(())
}

use crate::transport::tls_sender;
