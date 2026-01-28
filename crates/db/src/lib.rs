//! Data access layer for net-identity (SQLite via sqlx).

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use net_identity_core::model::{DeviceMapping, IdentityEvent, SourceType};
use sqlx::{Row, SqlitePool};

/// SQLite-backed database access.
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    /// Creates a new database wrapper from an existing pool.
    ///
    /// Parameters: `pool` - SQLite connection pool.
    /// Returns: `Db` instance.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Inserts or updates a mapping based on event freshness.
    ///
    /// Parameters: `event` - identity event to persist.
    /// Returns: `Ok(())` on success or an error.
    pub async fn upsert_mapping(&self, event: IdentityEvent) -> Result<()> {
        let source = source_to_str(event.source);
        let ip = event.ip.to_string();
        let last_seen = event.timestamp;
        let confidence: i64 = 100;

        sqlx::query(
            "INSERT INTO mappings (ip, user, source, last_seen, confidence)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(ip) DO UPDATE SET
               user = excluded.user,
               source = excluded.source,
               last_seen = excluded.last_seen,
               confidence = excluded.confidence
             WHERE excluded.last_seen > mappings.last_seen",
        )
        .bind(ip)
        .bind(event.user)
        .bind(source)
        .bind(last_seen)
        .bind(confidence)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Retrieves a mapping for the given IP.
    ///
    /// Parameters: `ip` - IP address string to look up.
    /// Returns: optional `DeviceMapping` if found or an error.
    pub async fn get_mapping(&self, ip: &str) -> Result<Option<DeviceMapping>> {
        let row = sqlx::query(
            "SELECT ip, user, last_seen, confidence
             FROM mappings
             WHERE ip = ?",
        )
        .bind(ip)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let ip: String = row.try_get("ip")?;
        let user: String = row.try_get("user")?;
        let last_seen: DateTime<Utc> = row.try_get("last_seen")?;
        let confidence: i64 = row.try_get("confidence")?;
        let confidence_score =
            u8::try_from(confidence).context("confidence value out of u8 range")?;

        Ok(Some(DeviceMapping {
            ip,
            mac: None,
            current_users: vec![user],
            last_seen,
            confidence_score,
        }))
    }
}

/// Converts `SourceType` to a stable string.
///
/// Parameters: `source` - source variant.
/// Returns: string representation for persistence.
fn source_to_str(source: SourceType) -> &'static str {
    match source {
        SourceType::Radius => "Radius",
        SourceType::AdLog => "AdLog",
        SourceType::Manual => "Manual",
    }
}
