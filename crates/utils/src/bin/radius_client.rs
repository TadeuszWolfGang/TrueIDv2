//! Simple RADIUS Accounting-Request test client.

use anyhow::{Context, Result};
use radius::core::code::Code;
use radius::core::packet::Packet;
use radius::core::rfc2865;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

const DEFAULT_SECRET: &str = "secret";
const DEFAULT_SERVER_ADDR: &str = "127.0.0.1:1813";

/// Builds an Accounting-Request packet payload.
///
/// Parameters: `secret` - shared secret used for signing.
/// Returns: encoded packet bytes ready for UDP send.
fn build_packet(secret: &str) -> Result<Vec<u8>> {
    let mut packet = Packet::new(Code::AccountingRequest, secret.as_bytes());
    rfc2865::add_user_name(&mut packet, "MobileUser_77");
    let framed_ip = Ipv4Addr::new(10, 20, 30, 40);
    let nas_ip = Ipv4Addr::new(127, 0, 0, 1);
    rfc2865::add_framed_ip_address(&mut packet, &framed_ip);
    rfc2865::add_nas_ip_address(&mut packet, &nas_ip);

    packet.encode().context("encode packet")
}

/// Sends a single Accounting-Request to the configured server.
///
/// Parameters: none.
/// Returns: `Ok(())` on success or an error.
fn main() -> Result<()> {
    let payload = build_packet(DEFAULT_SECRET)?;
    let server_addr: SocketAddr = DEFAULT_SERVER_ADDR.parse().context("parse server addr")?;
    let socket = UdpSocket::bind("0.0.0.0:0").context("bind udp socket")?;
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .context("set write timeout")?;
    let sent = socket
        .send_to(&payload, server_addr)
        .context("send packet")?;
    println!("Sent {sent} bytes to {server_addr}");
    Ok(())
}
