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
}

/// Default confidence score for events.
///
/// Parameters: none.
/// Returns: default confidence score.
fn default_confidence_score() -> u8 {
    100
}
