//! TLS syslog parsing helpers and heartbeat handling.

use anyhow::Result;
use chrono::Utc;
use tracing::warn;
use trueid_common::db::Db;
use trueid_common::model::{IdentityEvent, SourceType};

/// Extracts a `key=value` token from agent payload.
///
/// Parameters: `msg` - full syslog message, `key` - token key name.
/// Returns: extracted value when key exists.
pub(crate) fn extract_field_value(msg: &str, key: &str) -> Option<String> {
    let payload = msg.split("TrueID-Agent: ").nth(1).unwrap_or(msg);
    payload
        .split_whitespace()
        .find(|s| s.starts_with(&format!("{key}=")))
        .and_then(|s| s.split_once('='))
        .map(|(_, v)| v.to_string())
}

/// Parses AD TLS syslog message into identity event.
///
/// Parameters: `msg` - raw syslog payload.
/// Returns: optional AD identity event.
pub(crate) fn parse_tls_syslog_ad(msg: &str) -> Result<Option<IdentityEvent>> {
    let payload = msg.split("TrueID-Agent: ").nth(1).unwrap_or("");
    if !payload.starts_with("AD_LOGON") {
        return Ok(None);
    }
    let get = |key: &str| -> Option<String> {
        payload
            .split_whitespace()
            .find(|s| s.starts_with(&format!("{key}=")))
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
        source: SourceType::AdLog,
        ip,
        user,
        timestamp: Utc::now(),
        raw_data: msg.to_string(),
        mac: None,
        confidence_score: 90,
    }))
}

/// Parses DHCP TLS syslog message into identity event and DHCP options.
///
/// Parameters: `msg` - raw syslog payload.
/// Returns: optional tuple `(event, options55)`.
pub(crate) fn parse_tls_syslog_dhcp(msg: &str) -> Result<Option<(IdentityEvent, Option<String>)>> {
    let payload = msg.split("TrueID-Agent: ").nth(1).unwrap_or("");
    if !payload.starts_with("DHCP_LEASE") {
        return Ok(None);
    }
    let get = |key: &str| -> Option<String> {
        payload
            .split_whitespace()
            .find(|s| s.starts_with(&format!("{key}=")))
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
    let options55 = get("options55");
    Ok(Some((
        IdentityEvent {
            source: SourceType::DhcpLease,
            ip,
            user: hostname,
            timestamp: Utc::now(),
            raw_data: msg.to_string(),
            mac,
            confidence_score: 60,
        },
        options55,
    )))
}

/// Parses and persists agent heartbeat from TLS payload.
///
/// Parameters: `msg` - raw syslog payload, `db` - database handle.
/// Returns: nothing.
pub(crate) async fn handle_heartbeat(msg: &str, db: &Db) {
    let payload = match msg.split("TrueID-Agent: ").nth(1) {
        Some(p) if p.starts_with("HEARTBEAT") => p,
        _ => return,
    };
    let get = |key: &str| -> Option<String> {
        payload
            .split_whitespace()
            .find(|s| s.starts_with(&format!("{key}=")))
            .and_then(|s| s.split_once('='))
            .map(|(_, v)| v.to_string())
    };
    let hostname = match get("hostname") {
        Some(h) if !h.is_empty() => h,
        _ => return,
    };
    let uptime = get("uptime").and_then(|v| v.parse().ok()).unwrap_or(0);
    let sent = get("events_sent").and_then(|v| v.parse().ok()).unwrap_or(0);
    let dropped = get("events_dropped")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    if let Err(err) = db
        .upsert_agent(&hostname, uptime, sent, dropped, "tls")
        .await
    {
        warn!(error = %err, hostname = %hostname, "Failed to upsert agent heartbeat");
    }
}
