//! RADIUS accounting adapter for net-identity.

use anyhow::{anyhow, Result};
use chrono::Utc;
use net_identity_core::model::{IdentityEvent, SourceType};
use radius::core::code::Code;
use radius::core::packet::Packet;
use radius::core::rfc2865;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tracing::warn;

const MAX_PACKET_SIZE: usize = 4096;

/// UDP listener that converts RADIUS accounting packets to `IdentityEvent`.
pub struct RadiusAdapter {
    bind_addr: SocketAddr,
    secret: Vec<u8>,
    sender: Sender<IdentityEvent>,
}

impl RadiusAdapter {
    /// Creates a new adapter instance.
    ///
    /// Parameters: `bind_addr` - UDP bind address, `secret` - RADIUS shared secret,
    /// `sender` - channel for outgoing events.
    /// Returns: configured `RadiusAdapter`.
    pub fn new(bind_addr: SocketAddr, secret: &[u8], sender: Sender<IdentityEvent>) -> Self {
        Self {
            bind_addr,
            secret: secret.to_vec(),
            sender,
        }
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
            let packet_bytes = &buffer[..len];
            match self.parse_event(packet_bytes) {
                Ok(Some(event)) => {
                    if let Err(err) = self.sender.send(event).await {
                        warn!(?peer, error = %err, "Failed to send identity event");
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    warn!(?peer, error = %err, "Invalid RADIUS packet");
                }
            }
        }
    }

    /// Parses a raw RADIUS datagram into an identity event.
    ///
    /// Parameters: `packet_bytes` - UDP payload bytes.
    /// Returns: optional event when packet is a valid Accounting-Request.
    fn parse_event(&self, packet_bytes: &[u8]) -> Result<Option<IdentityEvent>> {
        let packet = Packet::decode(packet_bytes, &self.secret)?;
        if packet.get_code() != Code::AccountingRequest {
            return Ok(None);
        }

        let user = match rfc2865::lookup_user_name(&packet) {
            Some(Ok(value)) => value,
            Some(Err(err)) => return Err(anyhow!(err)),
            None => return Err(anyhow!("Missing User-Name attribute")),
        };

        let ip = match rfc2865::lookup_framed_ip_address(&packet) {
            Some(Ok(value)) => IpAddr::V4(value),
            Some(Err(err)) => return Err(anyhow!(err)),
            None => return Err(anyhow!("Missing Framed-IP-Address attribute")),
        };

        Ok(Some(IdentityEvent {
            source: SourceType::Radius,
            ip,
            user,
            timestamp: Utc::now(),
            raw_data: bytes_to_hex(packet_bytes),
        }))
    }
}

/// Converts bytes into lowercase hex string.
///
/// Parameters: `bytes` - input byte slice.
/// Returns: hex-encoded string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

/// Maps a 4-bit nibble to its hex char.
///
/// Parameters: `value` - nibble value (0..=15).
/// Returns: hex character.
fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => '?',
    }
}
