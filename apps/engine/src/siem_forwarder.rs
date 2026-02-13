//! SIEM event forwarding in CEF/LEEF/JSON over UDP/TCP.

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{Duration, Instant};
use tracing::warn;

/// Event to forward to SIEM.
#[derive(Clone, Debug)]
pub enum SiemEvent {
    Mapping {
        ip: String,
        user: String,
        mac: Option<String>,
        source: String,
        vendor: Option<String>,
        device_type: Option<String>,
        confidence: u8,
        timestamp: DateTime<Utc>,
    },
    Conflict {
        ip: Option<String>,
        user_old: Option<String>,
        user_new: Option<String>,
        conflict_type: String,
        severity: String,
        timestamp: DateTime<Utc>,
    },
    Alert {
        rule_name: String,
        severity: String,
        ip: Option<String>,
        user: Option<String>,
        message: String,
        timestamp: DateTime<Utc>,
    },
}

/// In-memory SIEM target config.
#[derive(Clone, Debug)]
struct SiemTarget {
    id: i64,
    name: String,
    format: SiemFormat,
    transport: SiemTransport,
    host: String,
    port: u16,
    forward_mappings: bool,
    forward_conflicts: bool,
    forward_alerts: bool,
}

/// SIEM payload format selector.
#[derive(Clone, Debug)]
pub enum SiemFormat {
    Cef,
    Leef,
    Json,
}

/// SIEM transport selector.
#[derive(Clone, Debug)]
enum SiemTransport {
    Udp,
    Tcp,
}

/// Parses SIEM output format from DB value.
///
/// Parameters: `raw` - raw DB format value.
/// Returns: parsed `SiemFormat`.
fn parse_format(raw: &str) -> Result<SiemFormat> {
    match raw {
        "cef" => Ok(SiemFormat::Cef),
        "leef" => Ok(SiemFormat::Leef),
        "json" => Ok(SiemFormat::Json),
        _ => Err(anyhow!("unsupported SIEM format")),
    }
}

/// Parses SIEM transport from DB value.
///
/// Parameters: `raw` - raw DB transport value.
/// Returns: parsed `SiemTransport`.
fn parse_transport(raw: &str) -> Result<SiemTransport> {
    match raw {
        "udp" => Ok(SiemTransport::Udp),
        "tcp" => Ok(SiemTransport::Tcp),
        _ => Err(anyhow!("unsupported SIEM transport")),
    }
}

/// Escapes CEF extension values.
///
/// Parameters: `raw` - original value.
/// Returns: CEF-safe string.
fn escape_cef_value(raw: &str) -> String {
    raw.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', "\\n")
}

/// Escapes LEEF values.
///
/// Parameters: `raw` - original value.
/// Returns: LEEF-safe string.
fn escape_leef_value(raw: &str) -> String {
    raw.replace('\t', "\\t").replace('\n', " ")
}

/// Returns event type label.
///
/// Parameters: `event` - SIEM event.
/// Returns: event type string.
fn event_type(event: &SiemEvent) -> &'static str {
    match event {
        SiemEvent::Mapping { .. } => "identity-mapping",
        SiemEvent::Conflict { .. } => "identity-conflict",
        SiemEvent::Alert { .. } => "alert-fired",
    }
}

/// Returns event timestamp.
///
/// Parameters: `event` - SIEM event.
/// Returns: event timestamp.
fn event_ts(event: &SiemEvent) -> DateTime<Utc> {
    match event {
        SiemEvent::Mapping { timestamp, .. } => *timestamp,
        SiemEvent::Conflict { timestamp, .. } => *timestamp,
        SiemEvent::Alert { timestamp, .. } => *timestamp,
    }
}

/// Formats a SIEM event according to selected output format.
///
/// Parameters: `event` - event payload, `format` - destination format.
/// Returns: formatted syslog message.
pub fn format_event(event: &SiemEvent, format: &SiemFormat) -> String {
    match format {
        SiemFormat::Cef => format_cef(event),
        SiemFormat::Leef => format_leef(event),
        SiemFormat::Json => format_json_syslog(event),
    }
}

/// Formats SIEM event as CEF.
///
/// Parameters: `event` - event payload.
/// Returns: CEF string.
fn format_cef(event: &SiemEvent) -> String {
    match event {
        SiemEvent::Mapping {
            ip,
            user,
            mac,
            source,
            vendor,
            device_type,
            timestamp,
            ..
        } => {
            let rt = timestamp.timestamp_millis();
            format!(
                "CEF:0|TrueID|Engine|1.0|identity-mapping|Identity Mapping|3|src={} suser={} smac={} cs1={} cs1Label=IdentitySource cs2={} cs2Label=DeviceVendor cs3={} cs3Label=DeviceType rt={}",
                escape_cef_value(ip),
                escape_cef_value(user),
                escape_cef_value(mac.as_deref().unwrap_or("")),
                escape_cef_value(source),
                escape_cef_value(vendor.as_deref().unwrap_or("")),
                escape_cef_value(device_type.as_deref().unwrap_or("")),
                rt
            )
        }
        SiemEvent::Conflict {
            ip,
            user_old,
            user_new,
            conflict_type,
            severity,
            timestamp,
        } => {
            let rt = timestamp.timestamp_millis();
            format!(
                "CEF:0|TrueID|Engine|1.0|identity-conflict|Identity Conflict|7|src={} suser={} cs1={} cs1Label=OldUser cs2={} cs2Label=ConflictType cs3={} cs3Label=Severity rt={}",
                escape_cef_value(ip.as_deref().unwrap_or("")),
                escape_cef_value(user_new.as_deref().unwrap_or("")),
                escape_cef_value(user_old.as_deref().unwrap_or("")),
                escape_cef_value(conflict_type),
                escape_cef_value(severity),
                rt
            )
        }
        SiemEvent::Alert {
            rule_name,
            severity,
            ip,
            user,
            message,
            timestamp,
        } => {
            let rt = timestamp.timestamp_millis();
            format!(
                "CEF:0|TrueID|Engine|1.0|alert-fired|Alert Fired|8|src={} suser={} cs1={} cs1Label=RuleName cs2={} cs2Label=Severity cs3={} cs3Label=Message rt={}",
                escape_cef_value(ip.as_deref().unwrap_or("")),
                escape_cef_value(user.as_deref().unwrap_or("")),
                escape_cef_value(rule_name),
                escape_cef_value(severity),
                escape_cef_value(message),
                rt
            )
        }
    }
}

/// Formats SIEM event as LEEF.
///
/// Parameters: `event` - event payload.
/// Returns: LEEF string.
fn format_leef(event: &SiemEvent) -> String {
    match event {
        SiemEvent::Mapping {
            ip,
            user,
            mac,
            source,
            vendor,
            device_type,
            ..
        } => format!(
            "LEEF:2.0|TrueID|Engine|1.0|identity-mapping|src={}\tusrName={}\tmacAddress={}\tidentitySource={}\tdevVendor={}\tdeviceType={}",
            escape_leef_value(ip),
            escape_leef_value(user),
            escape_leef_value(mac.as_deref().unwrap_or("")),
            escape_leef_value(source),
            escape_leef_value(vendor.as_deref().unwrap_or("")),
            escape_leef_value(device_type.as_deref().unwrap_or("")),
        ),
        SiemEvent::Conflict {
            ip,
            user_old,
            user_new,
            conflict_type,
            severity,
            ..
        } => format!(
            "LEEF:2.0|TrueID|Engine|1.0|identity-conflict|src={}\toldUser={}\tnewUser={}\tconflictType={}\tseverity={}",
            escape_leef_value(ip.as_deref().unwrap_or("")),
            escape_leef_value(user_old.as_deref().unwrap_or("")),
            escape_leef_value(user_new.as_deref().unwrap_or("")),
            escape_leef_value(conflict_type),
            escape_leef_value(severity),
        ),
        SiemEvent::Alert {
            rule_name,
            severity,
            ip,
            user,
            message,
            ..
        } => format!(
            "LEEF:2.0|TrueID|Engine|1.0|alert-fired|src={}\tusrName={}\truleName={}\tseverity={}\tmessage={}",
            escape_leef_value(ip.as_deref().unwrap_or("")),
            escape_leef_value(user.as_deref().unwrap_or("")),
            escape_leef_value(rule_name),
            escape_leef_value(severity),
            escape_leef_value(message),
        ),
    }
}

/// Formats SIEM event as RFC5424 syslog with JSON payload.
///
/// Parameters: `event` - event payload.
/// Returns: RFC5424 + JSON string.
fn format_json_syslog(event: &SiemEvent) -> String {
    let timestamp = event_ts(event);
    let payload = match event {
        SiemEvent::Mapping {
            ip,
            user,
            mac,
            source,
            vendor,
            device_type,
            confidence,
            timestamp,
        } => json!({
            "event_type": event_type(event),
            "ip": ip,
            "user": user,
            "mac": mac,
            "source": source,
            "vendor": vendor,
            "device_type": device_type,
            "confidence": confidence,
            "timestamp": timestamp.to_rfc3339(),
        }),
        SiemEvent::Conflict {
            ip,
            user_old,
            user_new,
            conflict_type,
            severity,
            timestamp,
        } => json!({
            "event_type": event_type(event),
            "ip": ip,
            "user_old": user_old,
            "user_new": user_new,
            "conflict_type": conflict_type,
            "severity": severity,
            "timestamp": timestamp.to_rfc3339(),
        }),
        SiemEvent::Alert {
            rule_name,
            severity,
            ip,
            user,
            message,
            timestamp,
        } => json!({
            "event_type": event_type(event),
            "rule_name": rule_name,
            "severity": severity,
            "ip": ip,
            "user": user,
            "message": message,
            "timestamp": timestamp.to_rfc3339(),
        }),
    };
    format!(
        "<14>1 {} trueid-engine - - - {}",
        timestamp.to_rfc3339(),
        payload
    )
}

/// Loads enabled SIEM targets from database.
///
/// Parameters: `pool` - SQLite pool.
/// Returns: list of enabled target configs.
async fn load_siem_targets(pool: &SqlitePool) -> Result<Vec<SiemTarget>> {
    let rows = sqlx::query(
        "SELECT id, name, format, transport, host, port,
                forward_mappings, forward_conflicts, forward_alerts
         FROM siem_targets
         WHERE enabled = 1
         ORDER BY id ASC",
    )
    .fetch_all(pool)
    .await?;

    let mut targets = Vec::with_capacity(rows.len());
    for row in rows {
        let format_raw: String = row.try_get("format").unwrap_or_default();
        let transport_raw: String = row.try_get("transport").unwrap_or_default();
        let port_i64: i64 = row.try_get("port").unwrap_or(514);
        let port = u16::try_from(port_i64).unwrap_or(514);
        let target = SiemTarget {
            id: row.try_get("id").unwrap_or_default(),
            name: row.try_get("name").unwrap_or_default(),
            format: parse_format(&format_raw)?,
            transport: parse_transport(&transport_raw)?,
            host: row.try_get("host").unwrap_or_default(),
            port,
            forward_mappings: row.try_get("forward_mappings").unwrap_or(true),
            forward_conflicts: row.try_get("forward_conflicts").unwrap_or(true),
            forward_alerts: row.try_get("forward_alerts").unwrap_or(true),
        };
        targets.push(target);
    }
    Ok(targets)
}

/// Sends one message to target over UDP or TCP.
///
/// Parameters: `target` - SIEM destination, `message` - formatted payload, `tcp_connections` - persistent TCP cache.
/// Returns: success when message was sent.
async fn send_to_target(
    target: &SiemTarget,
    message: &str,
    tcp_connections: &RwLock<HashMap<i64, TcpStream>>,
) -> Result<()> {
    match target.transport {
        SiemTransport::Udp => {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .context("failed to bind UDP socket")?;
            let addr = format!("{}:{}", target.host, target.port);
            let _ = socket
                .send_to(message.as_bytes(), &addr)
                .await
                .context("failed to send UDP SIEM message")?;
            Ok(())
        }
        SiemTransport::Tcp => {
            let addr = format!("{}:{}", target.host, target.port);
            let line = format!("{message}\n");

            {
                let mut conns = tcp_connections.write().await;
                if let Some(stream) = conns.get_mut(&target.id) {
                    if stream.write_all(line.as_bytes()).await.is_ok() {
                        return Ok(());
                    }
                    conns.remove(&target.id);
                }
            }

            let mut stream = TcpStream::connect(&addr)
                .await
                .context("failed to connect SIEM TCP target")?;
            stream
                .write_all(line.as_bytes())
                .await
                .context("failed to write SIEM TCP message")?;
            let mut conns = tcp_connections.write().await;
            conns.insert(target.id, stream);
            Ok(())
        }
    }
}

/// Checks whether event should be sent to target based on per-type flags.
///
/// Parameters: `event` - event to evaluate, `target` - forwarding target.
/// Returns: true when forwarding is enabled.
fn should_forward(event: &SiemEvent, target: &SiemTarget) -> bool {
    match event {
        SiemEvent::Mapping { .. } => target.forward_mappings,
        SiemEvent::Conflict { .. } => target.forward_conflicts,
        SiemEvent::Alert { .. } => target.forward_alerts,
    }
}

/// Persists batched success counters into database.
///
/// Parameters: `pool` - SQLite pool, `pending_counts` - per-target forwarded counters.
/// Returns: success after counters are flushed.
async fn flush_forward_counters(pool: &SqlitePool, pending_counts: &mut HashMap<i64, i64>) -> Result<()> {
    if pending_counts.is_empty() {
        return Ok(());
    }
    let snapshot = std::mem::take(pending_counts);
    for (target_id, count) in snapshot {
        sqlx::query(
            "UPDATE siem_targets
             SET events_forwarded = events_forwarded + ?,
                 last_forward_at = datetime('now'),
                 last_error = NULL,
                 updated_at = datetime('now')
             WHERE id = ?",
        )
        .bind(count)
        .bind(target_id)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Updates target error status with lightweight debounce.
///
/// Parameters: `pool` - SQLite pool, `target_id` - target id, `error` - failure text, `last_error_update` - debounce map.
/// Returns: success when DB update completed or skipped by debounce.
async fn update_target_error(
    pool: &SqlitePool,
    target_id: i64,
    error: &str,
    last_error_update: &mut HashMap<i64, Instant>,
) -> Result<()> {
    let now = Instant::now();
    if let Some(last) = last_error_update.get(&target_id) {
        if now.duration_since(*last) < Duration::from_secs(30) {
            return Ok(());
        }
    }
    sqlx::query(
        "UPDATE siem_targets
         SET last_error = ?, updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(error.chars().take(500).collect::<String>())
    .bind(target_id)
    .execute(pool)
    .await?;
    last_error_update.insert(target_id, now);
    Ok(())
}

/// Runs background SIEM forwarder loop.
///
/// Parameters: `receiver` - SIEM event channel receiver, `pool` - SQLite pool.
/// Returns: none.
pub async fn run_siem_forwarder(mut receiver: mpsc::Receiver<SiemEvent>, pool: SqlitePool) {
    let tcp_connections = RwLock::new(HashMap::<i64, TcpStream>::new());
    let mut targets = load_siem_targets(&pool).await.unwrap_or_default();
    let mut reload_interval = tokio::time::interval(Duration::from_secs(60));
    let mut flush_interval = tokio::time::interval(Duration::from_secs(5));
    let mut pending_counts = HashMap::<i64, i64>::new();
    let mut last_error_update = HashMap::<i64, Instant>::new();

    loop {
        tokio::select! {
            _ = reload_interval.tick() => {
                match load_siem_targets(&pool).await {
                    Ok(new_targets) => {
                        targets = new_targets;
                    }
                    Err(e) => warn!(error = %e, "Failed to reload SIEM targets"),
                }
            }
            _ = flush_interval.tick() => {
                if let Err(e) = flush_forward_counters(&pool, &mut pending_counts).await {
                    warn!(error = %e, "Failed to flush SIEM forwarded counters");
                }
            }
            maybe_event = receiver.recv() => {
                let Some(event) = maybe_event else {
                    let _ = flush_forward_counters(&pool, &mut pending_counts).await;
                    break;
                };
                for target in &targets {
                    if !should_forward(&event, target) {
                        continue;
                    }
                    let message = format_event(&event, &target.format);
                    match send_to_target(target, &message, &tcp_connections).await {
                        Ok(()) => {
                            *pending_counts.entry(target.id).or_insert(0) += 1;
                        }
                        Err(e) => {
                            warn!(error = %e, target = %target.name, "SIEM forward failed");
                            let _ = update_target_error(&pool, target.id, &e.to_string(), &mut last_error_update).await;
                            if matches!(target.transport, SiemTransport::Tcp) {
                                tcp_connections.write().await.remove(&target.id);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Creates SIEM forwarding channel.
///
/// Returns: `(sender, receiver)` pair for decoupled forwarding.
pub fn create_siem_channel() -> (mpsc::Sender<SiemEvent>, mpsc::Receiver<SiemEvent>) {
    mpsc::channel(10_000)
}
