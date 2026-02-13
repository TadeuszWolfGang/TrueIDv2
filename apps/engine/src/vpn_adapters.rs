//! VPN syslog adapters for AnyConnect, GlobalProtect, and Fortinet SSL-VPN.

use anyhow::Result;
use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};
use trueid_common::model::{IdentityEvent, SourceType};

const MAX_PACKET_SIZE: usize = 4096;
const VPN_CONFIDENCE: u8 = 80;

// ── AnyConnect patterns ──
static ANYCONNECT_USER_IP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"User\s*[<=]?\s*(?P<user>\S+)\s+IP\s*[<=]?\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    )
    .expect("invalid ANYCONNECT_USER_IP regex")
});
static ANYCONNECT_USERNAME_IP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"Username\s*=\s*(?P<user>[^,]+),\s*IP\s*=\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    )
    .expect("invalid ANYCONNECT_USERNAME_IP regex")
});

// ── GlobalProtect patterns ──
static GP_USER_IP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"GlobalProtect.*User:\s*(?P<user>\S+).*?(?:from|IP):\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    )
    .expect("invalid GP_USER_IP regex")
});
static GP_IP_USER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?:from|Login from):\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*User:\s*(?P<user>\S+)",
    )
    .expect("invalid GP_IP_USER regex")
});

// ── Fortinet patterns ──
static FORTI_VPN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"remip=(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?user="(?P<user>[^"]+)""#)
        .expect("invalid FORTI_VPN regex")
});
static FORTI_VPN_REV: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"user="(?P<user>[^"]+)".*?remip=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"#)
        .expect("invalid FORTI_VPN_REV regex")
});

/// Builds VPN identity event after validating parsed fields.
///
/// Parameters: `source` - VPN source type, `ip_raw` - parsed IP string, `user_raw` - parsed user, `text` - raw syslog payload.
/// Returns: parsed VPN identity event.
fn build_vpn_event(
    source: SourceType,
    ip_raw: &str,
    user_raw: &str,
    text: &str,
) -> Option<IdentityEvent> {
    let ip: Ipv4Addr = ip_raw.parse().ok()?;
    let user = user_raw
        .trim_matches('<')
        .trim_matches('>')
        .trim_matches('"')
        .trim()
        .to_string();
    if user.is_empty() {
        return None;
    }
    Some(IdentityEvent {
        source,
        ip: ip.into(),
        user,
        timestamp: Utc::now(),
        raw_data: text.to_string(),
        mac: None,
        confidence_score: VPN_CONFIDENCE,
    })
}

/// Tries to parse Cisco AnyConnect syslog message.
///
/// Parameters: `text` - syslog payload.
/// Returns: optional VPN identity event.
fn try_anyconnect(text: &str) -> Option<IdentityEvent> {
    if let Some(caps) = ANYCONNECT_USER_IP.captures(text) {
        return build_vpn_event(
            SourceType::VpnAnyConnect,
            caps.name("ip")?.as_str(),
            caps.name("user")?.as_str(),
            text,
        );
    }
    if let Some(caps) = ANYCONNECT_USERNAME_IP.captures(text) {
        return build_vpn_event(
            SourceType::VpnAnyConnect,
            caps.name("ip")?.as_str(),
            caps.name("user")?.as_str(),
            text,
        );
    }
    None
}

/// Tries to parse Palo Alto GlobalProtect syslog message.
///
/// Parameters: `text` - syslog payload.
/// Returns: optional VPN identity event.
fn try_globalprotect(text: &str) -> Option<IdentityEvent> {
    if text.contains("GLOBALPROTECT") && text.contains("login") {
        let fields = text.split(',').map(str::trim).collect::<Vec<_>>();
        if fields.len() > 12 {
            let user = fields.get(9).copied().unwrap_or_default();
            let ip = fields.get(12).copied().unwrap_or_default();
            if let Some(event) = build_vpn_event(SourceType::VpnGlobalProtect, ip, user, text) {
                return Some(event);
            }
        }
    }
    if let Some(caps) = GP_USER_IP.captures(text) {
        return build_vpn_event(
            SourceType::VpnGlobalProtect,
            caps.name("ip")?.as_str(),
            caps.name("user")?.as_str(),
            text,
        );
    }
    if let Some(caps) = GP_IP_USER.captures(text) {
        return build_vpn_event(
            SourceType::VpnGlobalProtect,
            caps.name("ip")?.as_str(),
            caps.name("user")?.as_str(),
            text,
        );
    }
    None
}

/// Tries to parse Fortinet SSL-VPN syslog message.
///
/// Parameters: `text` - syslog payload.
/// Returns: optional VPN identity event.
fn try_fortinet(text: &str) -> Option<IdentityEvent> {
    if let Some(caps) = FORTI_VPN.captures(text) {
        return build_vpn_event(
            SourceType::VpnFortinet,
            caps.name("ip")?.as_str(),
            caps.name("user")?.as_str(),
            text,
        );
    }
    if let Some(caps) = FORTI_VPN_REV.captures(text) {
        return build_vpn_event(
            SourceType::VpnFortinet,
            caps.name("ip")?.as_str(),
            caps.name("user")?.as_str(),
            text,
        );
    }
    None
}

/// Attempts to parse VPN syslog payload from all supported vendors.
///
/// Parameters: `text` - syslog payload text.
/// Returns: optional VPN identity event.
fn parse_vpn_syslog(text: &str) -> Option<IdentityEvent> {
    if text.contains("ASA-") || text.contains("AnyConnect") {
        if let Some(event) = try_anyconnect(text) {
            return Some(event);
        }
    }
    if text.contains("GLOBALPROTECT") || text.contains("GlobalProtect") {
        if let Some(event) = try_globalprotect(text) {
            return Some(event);
        }
    }
    if text.contains("tunnel-up")
        || text.contains("subtype=\"vpn\"")
        || text.contains("subtype=vpn")
    {
        if let Some(event) = try_fortinet(text) {
            return Some(event);
        }
    }
    None
}

/// Runs UDP listener for VPN syslog messages.
///
/// Parameters: `bind_addr` - UDP bind address, `sender` - event channel sender.
/// Returns: listener lifecycle result.
pub async fn run_vpn_listener(bind_addr: SocketAddr, sender: Sender<IdentityEvent>) -> Result<()> {
    let socket = UdpSocket::bind(bind_addr).await?;
    info!(%bind_addr, "VPN syslog listener started");
    let mut buf = vec![0u8; MAX_PACKET_SIZE];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let text = String::from_utf8_lossy(&buf[..len]);
        if let Some(event) = parse_vpn_syslog(&text) {
            if let Err(e) = sender.send(event).await {
                warn!(?peer, error = %e, "Failed to send VPN event");
            }
        }
    }
}
