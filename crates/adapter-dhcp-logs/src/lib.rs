//! DHCP syslog adapter for net-identity.

use anyhow::{anyhow, Result};
use chrono::Utc;
use trueid_common::model::{IdentityEvent, SourceType};
use once_cell::sync::Lazy;
use regex::Regex;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tracing::warn;

const MAX_PACKET_SIZE: usize = 4096;
const DEFAULT_CONFIDENCE: u8 = 60;

static DHCPACK_ON_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"DHCPACK on (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) to (?P<mac>[0-9A-Fa-f:.-]+)(?: \((?P<hostname>[^)]+)\))?",
    )
    .expect("valid DHCPACK on regex")
});
static DHCPACK_IFACE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"DHCPACK\([^)]+\)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<mac>[0-9A-Fa-f:.-]+)(?: \((?P<hostname>[^)]+)\))?",
    )
    .expect("valid DHCPACK iface regex")
});

/// DHCP syslog listener that extracts leases from DHCPACK logs.
pub struct DhcpLogsAdapter {
    bind_addr: SocketAddr,
    sender: Sender<IdentityEvent>,
}

impl DhcpLogsAdapter {
    /// Creates a new adapter instance.
    ///
    /// Parameters: `bind_addr` - UDP bind address, `sender` - event channel.
    /// Returns: configured `DhcpLogsAdapter`.
    pub fn new(bind_addr: SocketAddr, sender: Sender<IdentityEvent>) -> Self {
        Self { bind_addr, sender }
    }

    /// Runs the UDP listener loop.
    ///
    /// Parameters: none.
    /// Returns: `Ok(())` on graceful shutdown or an error.
    pub async fn run(&self) -> Result<()> {
        let socket = UdpSocket::bind(self.bind_addr).await?;
        let mut buffer = vec![0_u8; MAX_PACKET_SIZE];

        loop {
            let (len, peer) = socket.recv_from(&mut buffer).await?;
            let message = &buffer[..len];
            match parse_event(message) {
                Ok(Some(event)) => {
                    if let Err(err) = self.sender.send(event).await {
                        warn!(?peer, error = %err, "Failed to send DHCP event");
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    warn!(?peer, error = %err, "Invalid DHCP syslog message");
                }
            }
        }
    }
}

/// Parses a syslog message into a DHCP lease event if matched.
///
/// Parameters: `message` - raw syslog bytes.
/// Returns: optional `IdentityEvent` or an error.
fn parse_event(message: &[u8]) -> Result<Option<IdentityEvent>> {
    let text = String::from_utf8_lossy(message);
    let payload = text.trim();
    let captures = DHCPACK_ON_REGEX
        .captures(payload)
        .or_else(|| DHCPACK_IFACE_REGEX.captures(payload));

    let Some(captures) = captures else {
        return Ok(None);
    };

    let ip_text = captures
        .name("ip")
        .ok_or_else(|| anyhow!("Missing IP address"))?
        .as_str();
    let mac_text = captures
        .name("mac")
        .ok_or_else(|| anyhow!("Missing MAC address"))?
        .as_str();

    let ip = ip_text.parse::<IpAddr>()?;
    let mac = normalize_mac(mac_text);
    let hostname = captures.name("hostname").map(|value| value.as_str().to_string());
    let user = hostname.unwrap_or_else(|| mac.clone());

    Ok(Some(IdentityEvent {
        source: SourceType::DhcpLease,
        ip,
        user,
        timestamp: Utc::now(),
        raw_data: payload.to_string(),
        mac: Some(mac),
        confidence_score: DEFAULT_CONFIDENCE,
    }))
}

/// Normalizes a MAC address by removing separators.
///
/// Parameters: `value` - MAC address string.
/// Returns: normalized lowercase hex string.
fn normalize_mac(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}
