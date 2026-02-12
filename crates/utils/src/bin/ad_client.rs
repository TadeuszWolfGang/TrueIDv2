//! Simple AD syslog UDP test client.

use anyhow::{Context, Result};
use std::env;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const DEFAULT_SYSLOG_ADDR: &str = "127.0.0.1:5140";

/// Builds a syslog payload matching the AD adapter parser.
///
/// Parameters: none.
/// Returns: payload bytes.
fn build_payload() -> Vec<u8> {
    let message = "<13>Jan 28 22:15:00 DC01 MSWinEventLog: 1, Security, 42, Wed Jan 28 22:15:00 2026, 4624, Microsoft-Windows-Security-Auditing, N/A, N/A, Success Audit, DC01.corp.local, Logon, An account was successfully logged on. EventID: 4624 TargetUserName: Director_Bob IpAddress: 10.99.99.99";
    message.as_bytes().to_vec()
}

/// Sends a single syslog UDP message to the configured server.
///
/// Parameters: none.
/// Returns: `Ok(())` on success or an error.
fn main() -> Result<()> {
    let addr = env::var("AD_SYSLOG_SEND").unwrap_or_else(|_| DEFAULT_SYSLOG_ADDR.to_string());
    let server_addr: SocketAddr = addr.parse().context("parse syslog addr")?;
    let payload = build_payload();
    let socket = UdpSocket::bind("0.0.0.0:0").context("bind udp socket")?;
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .context("set write timeout")?;
    let sent = socket
        .send_to(&payload, server_addr)
        .context("send syslog payload")?;
    println!("Sent {sent} bytes to {server_addr}");
    Ok(())
}
