//! Syslog message formatting with RFC 5425 octet-counting framing.

use chrono::Utc;

/// Syslog facility/severity for the `<PRI>` header.
/// Default: user.notice = (1 * 8) + 5 = 13.
const DEFAULT_PRI: u8 = 13;

/// Formats an AD logon event as a syslog message payload.
///
/// Parameters: `hostname` - originating host, `user` - identity,
/// `ip` - client IP, `port` - source port, `event_id` - Windows Event ID,
/// `status` - logon status code.
/// Returns: formatted syslog payload string.
pub fn format_ad_event(
    hostname: &str,
    user: &str,
    ip: &str,
    port: &str,
    event_id: u32,
    status: &str,
) -> String {
    let ts = Utc::now().format("%b %e %H:%M:%S");
    format!(
        "<{}>{} {} TrueID-Agent: AD_LOGON user={} ip={} port={} event_id={} status={}",
        DEFAULT_PRI, ts, hostname, user, ip, port, event_id, status
    )
}

/// Formats a DHCP lease event as a syslog message payload.
///
/// Parameters: `hostname` - originating host, `ip` - leased IP,
/// `mac` - client MAC, `client_hostname` - client name,
/// `lease_duration` - duration in seconds.
/// Returns: formatted syslog payload string.
pub fn format_dhcp_event(
    hostname: &str,
    ip: &str,
    mac: &str,
    client_hostname: &str,
    lease_duration: u32,
) -> String {
    let ts = Utc::now().format("%b %e %H:%M:%S");
    format!(
        "<{}>{} {} TrueID-Agent: DHCP_LEASE ip={} mac={} hostname={} lease={}",
        DEFAULT_PRI, ts, hostname, ip, mac, client_hostname, lease_duration
    )
}

/// Formats a heartbeat syslog message.
///
/// Parameters: `hostname` - agent host, `uptime_secs` - seconds since start,
/// `events_sent` - total events sent, `events_dropped` - total events lost.
/// Returns: formatted syslog payload string.
pub fn format_heartbeat(
    hostname: &str,
    uptime_secs: u64,
    events_sent: u64,
    events_dropped: u64,
) -> String {
    let ts = Utc::now().format("%b %e %H:%M:%S");
    format!(
        "<{}>{} {} TrueID-Agent: HEARTBEAT hostname={} uptime={} events_sent={} events_dropped={} transport=tls",
        DEFAULT_PRI, ts, hostname, hostname, uptime_secs, events_sent, events_dropped
    )
}

/// Wraps a syslog payload with RFC 5425 octet-counting framing.
///
/// Parameters: `payload` - syslog message string.
/// Returns: framed bytes ready for TCP+TLS send.
pub fn frame_octet_counting(payload: &str) -> Vec<u8> {
    let len = payload.len();
    format!("{} {}\n", len, payload).into_bytes()
}

/// Parses an octet-counting framed syslog message from a byte buffer.
///
/// Parameters: `buf` - input byte slice.
/// Returns: `Some((message, consumed_bytes))` or `None` if incomplete.
pub fn parse_octet_frame(buf: &[u8]) -> Option<(String, usize)> {
    let space_pos = buf.iter().position(|&b| b == b' ')?;
    let len_str = std::str::from_utf8(&buf[..space_pos]).ok()?;
    let msg_len: usize = len_str.parse().ok()?;
    let total = space_pos + 1 + msg_len;
    if buf.len() < total {
        return None;
    }
    let msg = std::str::from_utf8(&buf[space_pos + 1..space_pos + 1 + msg_len])
        .ok()?
        .to_string();
    // Skip trailing newline if present.
    let consumed = if buf.len() > total && buf[total] == b'\n' {
        total + 1
    } else {
        total
    };
    Some((msg, consumed))
}
