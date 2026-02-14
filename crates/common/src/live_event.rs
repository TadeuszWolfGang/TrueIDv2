//! Real-time event payloads for SSE streaming.

use chrono::{DateTime, Utc};
use serde::Serialize;

/// Real-time event types broadcast to connected SSE clients.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LiveEvent {
    /// New or updated identity mapping.
    MappingUpdate {
        ip: String,
        user: String,
        mac: Option<String>,
        source: String,
        timestamp: DateTime<Utc>,
    },
    /// Identity conflict detected.
    ConflictDetected {
        id: i64,
        conflict_type: String,
        severity: String,
        ip: Option<String>,
        user_old: Option<String>,
        user_new: Option<String>,
        detected_at: DateTime<Utc>,
    },
    /// Alert fired.
    AlertFired {
        rule_name: String,
        rule_type: String,
        severity: String,
        ip: Option<String>,
        user: Option<String>,
        fired_at: DateTime<Utc>,
    },
    /// Firewall push completed.
    FirewallPush {
        target_name: String,
        entries_count: i64,
        success: bool,
        pushed_at: DateTime<Utc>,
    },
    /// System status change (adapter up/down).
    AdapterStatus {
        name: String,
        status: String,
        timestamp: DateTime<Utc>,
    },
    /// Heartbeat (sent every 30s to keep connection alive).
    Heartbeat { timestamp: DateTime<Utc> },
}
