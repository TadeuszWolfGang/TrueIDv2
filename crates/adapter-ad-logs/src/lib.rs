//! Active Directory log adapter over syslog (UDP/TCP).

use anyhow::{anyhow, Result};
use chrono::Utc;
use net_identity_core::model::{IdentityEvent, SourceType};
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::Sender;
use tracing::warn;

const MAX_PACKET_SIZE: usize = 8192;

/// Syslog listener that extracts identity events from AD logs.
pub struct AdLogsAdapter {
    bind_addr: SocketAddr,
    sender: Sender<IdentityEvent>,
}

impl AdLogsAdapter {
    /// Creates a new adapter instance.
    ///
    /// Parameters: `bind_addr` - UDP/TCP bind address,
    /// `sender` - channel for outgoing events.
    /// Returns: configured `AdLogsAdapter`.
    pub fn new(bind_addr: SocketAddr, sender: Sender<IdentityEvent>) -> Self {
        Self { bind_addr, sender }
    }

    /// Runs UDP and TCP syslog listeners.
    ///
    /// Parameters: none.
    /// Returns: `Ok(())` on graceful shutdown or an error.
    pub async fn run(&self) -> Result<()> {
        let udp_sender = self.sender.clone();
        let udp_addr = self.bind_addr;
        let udp_task = tokio::spawn(async move {
            if let Err(err) = run_udp(udp_addr, udp_sender).await {
                warn!(error = %err, "UDP syslog listener stopped");
            }
        });

        let tcp_sender = self.sender.clone();
        let tcp_addr = self.bind_addr;
        let tcp_task = tokio::spawn(async move {
            if let Err(err) = run_tcp(tcp_addr, tcp_sender).await {
                warn!(error = %err, "TCP syslog listener stopped");
            }
        });

        let _ = tokio::join!(udp_task, tcp_task);
        Ok(())
    }
}

/// Runs the UDP syslog listener loop.
///
/// Parameters: `bind_addr` - UDP bind address, `sender` - event channel.
/// Returns: `Ok(())` on clean shutdown or an error.
async fn run_udp(bind_addr: SocketAddr, sender: Sender<IdentityEvent>) -> Result<()> {
    let socket = UdpSocket::bind(bind_addr).await?;
    let mut buffer = vec![0_u8; MAX_PACKET_SIZE];

    loop {
        let (len, peer) = socket.recv_from(&mut buffer).await?;
        let message = &buffer[..len];
        if let Err(err) = handle_message(message, &sender).await {
            warn!(?peer, error = %err, "Invalid UDP syslog message");
        }
    }
}

/// Runs the TCP syslog listener loop.
///
/// Parameters: `bind_addr` - TCP bind address, `sender` - event channel.
/// Returns: `Ok(())` on clean shutdown or an error.
async fn run_tcp(bind_addr: SocketAddr, sender: Sender<IdentityEvent>) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    loop {
        let (stream, peer) = listener.accept().await?;
        let sender = sender.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_tcp_client(stream, sender).await {
                warn!(?peer, error = %err, "TCP syslog client error");
            }
        });
    }
}

/// Handles an individual TCP client connection.
///
/// Parameters: `stream` - TCP stream, `sender` - event channel.
/// Returns: `Ok(())` on client disconnect or an error.
async fn handle_tcp_client(
    stream: tokio::net::TcpStream,
    sender: Sender<IdentityEvent>,
) -> Result<()> {
    let mut reader = BufReader::new(stream).lines();
    while let Some(line) = reader.next_line().await? {
        if let Err(err) = handle_message(line.as_bytes(), &sender).await {
            warn!(error = %err, "Invalid TCP syslog message");
        }
    }
    Ok(())
}

/// Parses a syslog message and forwards an event if matched.
///
/// Parameters: `message` - raw syslog bytes, `sender` - event channel.
/// Returns: `Ok(())` on success or an error.
async fn handle_message(message: &[u8], sender: &Sender<IdentityEvent>) -> Result<()> {
    if let Some(event) = parse_event(message)? {
        if let Err(err) = sender.send(event).await {
            warn!(error = %err, "Failed to send identity event");
        }
    }
    Ok(())
}

/// Parses a syslog message into an identity event if it matches.
///
/// Parameters: `message` - raw syslog bytes.
/// Returns: optional `IdentityEvent` for matching log lines or an error.
fn parse_event(message: &[u8]) -> Result<Option<IdentityEvent>> {
    let text = String::from_utf8_lossy(message);
    let trimmed = text.trim();

    if trimmed.starts_with('{') {
        return parse_json_event(trimmed).map(|opt| opt.map(|(ip, user, raw)| IdentityEvent {
            source: SourceType::AdLog,
            ip,
            user,
            timestamp: Utc::now(),
            raw_data: raw,
        }));
    }

    parse_text_event(trimmed).map(|opt| opt.map(|(ip, user, raw)| IdentityEvent {
        source: SourceType::AdLog,
        ip,
        user,
        timestamp: Utc::now(),
        raw_data: raw,
    }))
}

/// Parses JSON syslog payload for AD log fields.
///
/// Parameters: `payload` - JSON string.
/// Returns: optional tuple of `(IpAddr, user, raw_data)` or an error.
fn parse_json_event(payload: &str) -> Result<Option<(IpAddr, String, String)>> {
    let value: Value = serde_json::from_str(payload)?;
    let event_id = lookup_json_event_id(&value).ok_or_else(|| anyhow!("Missing EventID"))?;

    if event_id != 4768 && event_id != 4624 {
        return Ok(None);
    }

    let ip = lookup_json_string(&value, "IpAddress")
        .or_else(|| lookup_json_nested_string(&value, "EventData", "IpAddress"))
        .ok_or_else(|| anyhow!("Missing IpAddress"))?;
    let user = lookup_json_string(&value, "TargetUserName")
        .or_else(|| lookup_json_nested_string(&value, "EventData", "TargetUserName"))
        .ok_or_else(|| anyhow!("Missing TargetUserName"))?;

    let ip_addr = ip.parse::<IpAddr>()?;
    Ok(Some((ip_addr, user, payload.to_string())))
}

/// Parses text syslog payload for AD log fields.
///
/// Parameters: `payload` - text message.
/// Returns: optional tuple of `(IpAddr, user, raw_data)` or an error.
fn parse_text_event(payload: &str) -> Result<Option<(IpAddr, String, String)>> {
    let event_id = extract_text_value(payload, "EventID")
        .or_else(|| extract_text_value(payload, "EventId"))
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| anyhow!("Missing EventID"))?;

    if event_id != 4768 && event_id != 4624 {
        return Ok(None);
    }

    let ip = extract_text_value(payload, "IpAddress").ok_or_else(|| anyhow!("Missing IpAddress"))?;
    let user = extract_text_value(payload, "TargetUserName")
        .ok_or_else(|| anyhow!("Missing TargetUserName"))?;
    let ip_addr = ip.parse::<IpAddr>()?;

    Ok(Some((ip_addr, user, payload.to_string())))
}

/// Looks up EventID in JSON payload.
///
/// Parameters: `value` - JSON document.
/// Returns: numeric event id if present.
fn lookup_json_event_id(value: &Value) -> Option<u32> {
    let id = lookup_json_i64(value, "EventID")
        .or_else(|| lookup_json_i64(value, "EventId"))
        .or_else(|| lookup_json_nested_i64(value, "EventData", "EventID"))
        .or_else(|| lookup_json_nested_i64(value, "EventData", "EventId"))?;
    u32::try_from(id).ok()
}

/// Extracts a string field from JSON.
///
/// Parameters: `value` - JSON document, `key` - field name.
/// Returns: field value as string if present.
fn lookup_json_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(|val| match val {
        Value::String(text) => Some(text.clone()),
        Value::Number(num) => Some(num.to_string()),
        _ => None,
    })
}

/// Extracts a nested string field from JSON.
///
/// Parameters: `value` - JSON document, `outer` - parent field, `inner` - child field.
/// Returns: field value as string if present.
fn lookup_json_nested_string(value: &Value, outer: &str, inner: &str) -> Option<String> {
    value.get(outer).and_then(|obj| lookup_json_string(obj, inner))
}

/// Extracts an integer field from JSON.
///
/// Parameters: `value` - JSON document, `key` - field name.
/// Returns: integer if present.
fn lookup_json_i64(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(|val| match val {
        Value::Number(num) => num.as_i64(),
        Value::String(text) => text.parse::<i64>().ok(),
        _ => None,
    })
}

/// Extracts a nested integer field from JSON.
///
/// Parameters: `value` - JSON document, `outer` - parent field, `inner` - child field.
/// Returns: integer if present.
fn lookup_json_nested_i64(value: &Value, outer: &str, inner: &str) -> Option<i64> {
    value.get(outer).and_then(|obj| lookup_json_i64(obj, inner))
}

/// Extracts a key-value pair from text.
///
/// Parameters: `payload` - text message, `key` - field name.
/// Returns: value string if present.
fn extract_text_value(payload: &str, key: &str) -> Option<String> {
    let mut start = 0;
    while let Some(found) = payload[start..].find(key) {
        let idx = start + found + key.len();
        let mut chars = payload[idx..].chars();
        let mut offset = 0;
        while let Some(ch) = chars.next() {
            offset += ch.len_utf8();
            if ch == '=' || ch == ':' {
                break;
            }
            if !ch.is_whitespace() {
                continue;
            }
        }
        let value_start = idx + offset;
        let value = payload[value_start..].trim_start();
        if value.is_empty() {
            start = idx;
            continue;
        }
        if let Some(stripped) = value.strip_prefix('"') {
            if let Some(end) = stripped.find('"') {
                return Some(stripped[..end].to_string());
            }
        }
        let end = value
            .find(|c: char| c.is_whitespace() || c == ',' || c == '}' || c == ']')
            .unwrap_or(value.len());
        let result = value[..end].trim_matches('"');
        if !result.is_empty() {
            return Some(result.to_string());
        }
        start = idx;
    }
    None
}
