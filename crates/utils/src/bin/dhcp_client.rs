//! Simple DHCP syslog UDP test client.

use anyhow::{Context, Result};
use std::env;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const DEFAULT_DHCP_ADDR: &str = "127.0.0.1:5516";

/// Builds a syslog payload matching the DHCP adapter parser.
///
/// Parameters: none.
/// Returns: payload bytes.
fn build_payload() -> Vec<u8> {
    let message = "<30>Jan 28 23:00:00 dhcpd[1234]: DHCPACK on 192.168.50.50 to aa:bb:cc:11:22:33 (Printer-HP) via eth0";
    message.as_bytes().to_vec()
}

/// Sends a single DHCP syslog UDP message to the configured server.
///
/// Parameters: none.
/// Returns: `Ok(())` on success or an error.
fn main() -> Result<()> {
    let addr = env::var("DHCP_SYSLOG_SEND")
        .unwrap_or_else(|_| DEFAULT_DHCP_ADDR.to_string());
    let server_addr: SocketAddr = addr.parse().context("parse DHCP syslog addr")?;
    let payload = build_payload();
    let socket = UdpSocket::bind("0.0.0.0:0").context("bind udp socket")?;
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .context("set write timeout")?;
    let sent = socket
        .send_to(&payload, server_addr)
        .context("send DHCP syslog payload")?;
    println!("Sent {sent} bytes to {server_addr}");
    Ok(())
}
