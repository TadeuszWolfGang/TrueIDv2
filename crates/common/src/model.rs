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
    /// Cisco AnyConnect VPN session logs.
    VpnAnyConnect,
    /// Palo Alto GlobalProtect VPN session logs.
    VpnGlobalProtect,
    /// Fortinet SSL-VPN session logs.
    VpnFortinet,
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
    // ── Phase 2: DHCP fingerprinting ──
    /// Device type identified via DHCP option 55 fingerprint.
    #[serde(default)]
    pub device_type: Option<String>,
    // ── Multi-user session support ──
    /// Whether this IP has multiple concurrent active sessions (terminal server).
    #[serde(default)]
    pub multi_user: bool,
    /// Optional LDAP/AD groups synced for the mapped user.
    #[serde(default)]
    pub groups: Option<Vec<String>>,
    /// Optional ISO country code resolved by GeoIP.
    #[serde(default)]
    pub country_code: Option<String>,
    /// Optional city resolved by GeoIP.
    #[serde(default)]
    pub city: Option<String>,
    /// Optional manually assigned tags for this IP.
    #[serde(default)]
    pub tags: Vec<MappingTag>,
}

/// Manual context tag assigned to an IP mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingTag {
    /// Tag label (e.g. "server", "vip").
    pub tag: String,
    /// Hex color used for dashboard badges.
    pub color: String,
}

impl DeviceMapping {
    /// Constructs a `DeviceMapping` from a SQLx SQLite row.
    ///
    /// Parameters: `row` - row containing mapping projection columns.
    /// Returns: parsed `DeviceMapping` or SQLx decode error.
    pub fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;

        let ip: String = row.try_get("ip")?;
        let user: String = row.try_get("user")?;
        let source: String = row.try_get("source")?;
        let mac: Option<String> = row.try_get("mac")?;
        let last_seen: chrono::DateTime<chrono::Utc> = row.try_get("last_seen")?;
        let confidence: i64 = row.try_get("confidence")?;
        let is_active: bool = row.try_get("is_active")?;
        let vendor: Option<String> = row.try_get("vendor")?;
        let subnet_id: Option<i64> = row.try_get("subnet_id").ok();
        let subnet_name: Option<String> = row.try_get("subnet_name").ok();
        let hostname: Option<String> = row.try_get("hostname").ok();
        let device_type: Option<String> = row.try_get("device_type").ok();
        let multi_user: bool = row.try_get("multi_user").unwrap_or(false);
        let session_users_raw: Option<String> = row.try_get("session_users").ok().flatten();
        let group_names_raw: Option<String> = row.try_get("group_names").ok().flatten();
        let country_code: Option<String> = row.try_get("country_code").ok();
        let city: Option<String> = row.try_get("city").ok();
        let tags_raw: Option<String> = row.try_get("ip_tags_csv").ok().flatten();
        let current_users = match session_users_raw {
            Some(ref csv) if !csv.is_empty() => csv
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>(),
            _ => vec![user.clone()],
        };
        let groups = group_names_raw.and_then(|csv| {
            let parsed = csv
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            if parsed.is_empty() {
                None
            } else {
                Some(parsed)
            }
        });
        let tags = tags_raw
            .map(|csv| {
                csv.split(',')
                    .filter_map(|entry| {
                        let mut parts = entry.splitn(2, '|');
                        let tag = parts.next().unwrap_or("").trim();
                        if tag.is_empty() {
                            return None;
                        }
                        let color = parts.next().unwrap_or("#6b8579").trim();
                        Some(MappingTag {
                            tag: tag.to_string(),
                            color: if color.is_empty() {
                                "#6b8579".to_string()
                            } else {
                                color.to_string()
                            },
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(Self {
            ip,
            mac,
            current_users,
            last_seen,
            source: source_from_str(&source),
            confidence_score: u8::try_from(confidence).unwrap_or(0),
            is_active,
            vendor,
            subnet_id,
            subnet_name,
            hostname,
            device_type,
            multi_user,
            groups,
            country_code,
            city,
            tags,
        })
    }
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
        "vpn_anyconnect" => SourceType::VpnAnyConnect,
        "vpn_globalprotect" => SourceType::VpnGlobalProtect,
        "vpn_fortinet" => SourceType::VpnFortinet,
        _ => SourceType::Manual,
    }
}

/// Normalizes a MAC address to lowercase colon-separated format.
///
/// Parameters: `raw` - MAC address in arbitrary separator format.
/// Returns: normalized `aa:bb:cc:dd:ee:ff` or `None` for invalid input.
pub fn normalize_mac(raw: &str) -> Option<String> {
    let hex: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let h = hex.to_ascii_lowercase();
    Some(format!(
        "{}:{}:{}:{}:{}:{}",
        &h[0..2],
        &h[2..4],
        &h[4..6],
        &h[6..8],
        &h[8..10],
        &h[10..12]
    ))
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
    pub oidc_subject: Option<String>,
    pub oidc_provider: Option<String>,
    pub token_version: i64,
    pub force_password_change: bool,
    pub totp_enabled: bool,
    pub totp_verified_at: Option<DateTime<Utc>>,
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
    pub oidc_subject: Option<String>,
    pub oidc_provider: Option<String>,
    pub force_password_change: bool,
    pub totp_enabled: bool,
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
            oidc_subject: u.oidc_subject,
            oidc_provider: u.oidc_provider,
            force_password_change: u.force_password_change,
            totp_enabled: u.totp_enabled,
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
    pub last_active_at: DateTime<Utc>,
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
    pub rate_limit_rpm: i64,
    pub rate_limit_burst: i64,
    pub created_at: DateTime<Utc>,
}

/// Hourly API key usage aggregate row.
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyUsageHourly {
    pub hour: String,
    pub requests: i64,
    pub errors: i64,
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
