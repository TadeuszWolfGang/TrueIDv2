//! Domain models for identity mapping.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Origin of identity data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SourceType {
    /// RADIUS authentication logs.
    Radius,
    /// Active Directory logs.
    AdLog,
    /// DHCP lease logs.
    DhcpLease,
    /// Manually entered records.
    Manual,
}

/// Single identity event coming from an ingestion source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityEvent {
    /// Data source type.
    pub source: SourceType,
    /// IP address associated with the event.
    pub ip: IpAddr,
    /// User identity.
    pub user: String,
    /// Event timestamp in UTC.
    pub timestamp: DateTime<Utc>,
    /// Raw source payload for auditing.
    pub raw_data: String,
    /// Optional MAC address.
    #[serde(default)]
    pub mac: Option<String>,
    /// Confidence score in 0..=100.
    #[serde(default = "default_confidence_score")]
    pub confidence_score: u8,
}

/// Current device-to-user mapping for an IP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceMapping {
    /// Primary key: IP address as string.
    pub ip: String,
    /// Optional MAC address.
    pub mac: Option<String>,
    /// Users currently associated with the device.
    pub current_users: Vec<String>,
    /// Last time the device was seen.
    pub last_seen: DateTime<Utc>,
    /// Source of the most recent mapping.
    pub source: SourceType,
    /// Confidence score in 0..=100.
    pub confidence_score: u8,
    /// Whether the device is currently active (seen within TTL window).
    pub is_active: bool,
    /// Hardware vendor name resolved from OUI database.
    #[serde(default)]
    pub vendor: Option<String>,
}

/// Stored event row from the events table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    /// Auto-increment ID.
    pub id: i64,
    /// IP address associated with the event.
    pub ip: String,
    /// User identity.
    pub user: String,
    /// Source type as string.
    pub source: String,
    /// Event timestamp in UTC.
    pub timestamp: DateTime<Utc>,
    /// Raw source payload.
    pub raw_data: String,
}

/// Agent heartbeat information from the agents table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub hostname: String,
    pub last_heartbeat: DateTime<Utc>,
    pub uptime_seconds: i64,
    pub events_sent: i64,
    pub events_dropped: i64,
    pub transport: String,
    /// Computed: "online" if heartbeat < 3 min ago, else "offline".
    pub status: String,
}

/// Sync integration status row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub integration: String,
    pub last_run_at: Option<DateTime<Utc>>,
    pub status: Option<String>,
    pub message: Option<String>,
    pub records_synced: i64,
}

/// Live adapter status (kept in engine memory, not DB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterStatus {
    pub name: String,
    pub protocol: String,
    pub bind: String,
    pub status: String,
    pub last_event_at: Option<DateTime<Utc>>,
    pub events_total: u64,
}

/// Converts a stored string back to `SourceType`.
///
/// Parameters: `value` - source string from storage.
/// Returns: parsed `SourceType` or `Manual` for unknown values.
pub fn source_from_str(value: &str) -> SourceType {
    match value {
        "Radius" => SourceType::Radius,
        "AdLog" => SourceType::AdLog,
        "Dhcp" | "DhcpLease" => SourceType::DhcpLease,
        "Manual" => SourceType::Manual,
        _ => SourceType::Manual,
    }
}

/// Default confidence score for events.
///
/// Parameters: none.
/// Returns: default confidence score (100).
fn default_confidence_score() -> u8 {
    100
}
