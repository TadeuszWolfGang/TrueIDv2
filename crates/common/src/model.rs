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
    // ── Phase 2: subnet awareness ──
    /// Subnet ID if IP matches a known subnet definition.
    #[serde(default)]
    pub subnet_id: Option<i64>,
    /// Subnet human-readable name (denormalized for API convenience).
    #[serde(default)]
    pub subnet_name: Option<String>,
    // ── Phase 2: DNS reverse lookup ──
    /// Reverse DNS hostname from PTR record cache.
    #[serde(default)]
    pub hostname: Option<String>,
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

// ── Auth models ────────────────────────────────────────────

/// Role-based access control level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum UserRole {
    Admin,
    Operator,
    Viewer,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin => write!(f, "Admin"),
            Self::Operator => write!(f, "Operator"),
            Self::Viewer => write!(f, "Viewer"),
        }
    }
}

impl std::str::FromStr for UserRole {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Admin" => Ok(Self::Admin),
            "Operator" => Ok(Self::Operator),
            "Viewer" => Ok(Self::Viewer),
            other => Err(anyhow::anyhow!("unknown role: {other}")),
        }
    }
}

/// Internal user record. Never serialize directly (password_hash must not leak).
#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub auth_source: String,
    pub external_id: Option<String>,
    pub token_version: i64,
    pub force_password_change: bool,
    pub failed_attempts: i64,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Safe projection of `User` without sensitive fields.
#[derive(Debug, Clone, Serialize)]
pub struct UserPublic {
    pub id: i64,
    pub username: String,
    pub role: UserRole,
    pub auth_source: String,
    pub force_password_change: bool,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<User> for UserPublic {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            role: u.role,
            auth_source: u.auth_source,
            force_password_change: u.force_password_change,
            locked_until: u.locked_until,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

/// Refresh-token session record.
#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub id: i64,
    pub user_id: i64,
    #[serde(skip_serializing)]
    pub refresh_token_hash: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// API key record. `key_hash` is never serialized.
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyRecord {
    pub id: i64,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub key_prefix: String,
    pub description: String,
    pub role: UserRole,
    pub created_by: i64,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Append-only audit log entry.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<i64>,
    pub username: String,
    pub principal_type: String,
    pub action: String,
    pub target: Option<String>,
    pub details: Option<String>,
    pub ip_address: Option<String>,
    pub request_id: Option<String>,
}
