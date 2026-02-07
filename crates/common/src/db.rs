//! Data access layer for TrueID (SQLite via sqlx).

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};

use crate::model::{DeviceMapping, IdentityEvent, SourceType, StoredEvent};

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

    /// Gracefully closes the database connection pool.
    ///
    /// Parameters: none.
    /// Returns: nothing.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Inserts or updates a mapping based on event freshness.
    ///
    /// Parameters: `event` - identity event to persist,
    /// `vendor` - optional vendor name resolved from OUI database.
    /// Returns: `Ok(())` on success or an error.
    pub async fn upsert_mapping(&self, event: IdentityEvent, vendor: Option<&str>) -> Result<()> {
        let source = source_to_str(event.source);
        let ip = event.ip.to_string();
        let last_seen = event.timestamp;
        let confidence: i64 = i64::from(event.confidence_score);

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO events (ip, user, source, timestamp, raw_data)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&ip)
        .bind(&event.user)
        .bind(source)
        .bind(last_seen)
        .bind(&event.raw_data)
        .execute(&mut *tx)
        .await?;

        let existing_source: Option<String> =
            sqlx::query("SELECT source FROM mappings WHERE ip = ?")
                .bind(&ip)
                .fetch_optional(&mut *tx)
                .await?
                .map(|row| row.try_get("source"))
                .transpose()?;

        let mac = event.mac.as_deref();
        match existing_source {
            None => {
                sqlx::query(
                    "INSERT INTO mappings (ip, user, source, last_seen, confidence, mac, is_active, vendor)
                     VALUES (?, ?, ?, ?, ?, ?, true, ?)",
                )
                .bind(&ip)
                .bind(&event.user)
                .bind(source)
                .bind(last_seen)
                .bind(confidence)
                .bind(mac)
                .bind(vendor)
                .execute(&mut *tx)
                .await?;
            }
            Some(existing_source) => {
                let existing_priority = source_priority(&source_from_str(&existing_source));
                let incoming_priority = source_priority(&event.source);
                if incoming_priority >= existing_priority {
                    sqlx::query(
                        "UPDATE mappings
                         SET user = ?, source = ?, last_seen = ?, confidence = ?,
                             mac = COALESCE(?, mac), is_active = true,
                             vendor = COALESCE(?, vendor)
                         WHERE ip = ?",
                    )
                    .bind(&event.user)
                    .bind(source)
                    .bind(last_seen)
                    .bind(confidence)
                    .bind(mac)
                    .bind(vendor)
                    .bind(&ip)
                    .execute(&mut *tx)
                    .await?;
                } else {
                    sqlx::query(
                        "UPDATE mappings
                         SET last_seen = ?, confidence = ?, mac = COALESCE(?, mac),
                             is_active = true, vendor = COALESCE(?, vendor)
                         WHERE ip = ?",
                    )
                    .bind(last_seen)
                    .bind(confidence)
                    .bind(mac)
                    .bind(vendor)
                    .bind(&ip)
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }

        tx.commit().await?;

        Ok(())
    }

    /// Retrieves a mapping for the given IP.
    ///
    /// Parameters: `ip` - IP address string to look up.
    /// Returns: optional `DeviceMapping` if found or an error.
    pub async fn get_mapping(&self, ip: &str) -> Result<Option<DeviceMapping>> {
        let row = sqlx::query(
            "SELECT ip, user, source, last_seen, confidence, mac, is_active, vendor
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
        let source: String = row.try_get("source")?;
        let mac: Option<String> = row.try_get("mac")?;
        let last_seen: DateTime<Utc> = row.try_get("last_seen")?;
        let confidence: i64 = row.try_get("confidence")?;
        let confidence_score =
            u8::try_from(confidence).context("confidence value out of u8 range")?;
        let is_active: bool = row.try_get("is_active")?;
        let vendor: Option<String> = row.try_get("vendor")?;

        Ok(Some(DeviceMapping {
            ip,
            mac,
            current_users: vec![user],
            last_seen,
            source: source_from_str(&source),
            confidence_score,
            is_active,
            vendor,
        }))
    }

    /// Marks mappings as inactive when `last_seen` exceeds the TTL.
    ///
    /// Parameters: `ttl_minutes` - inactivity threshold in minutes.
    /// Returns: number of deactivated rows or an error.
    pub async fn deactivate_stale(&self, ttl_minutes: i64) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE mappings SET is_active = false
             WHERE last_seen < datetime('now', ? || ' minutes')
               AND is_active = true",
        )
        .bind(-ttl_minutes)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Retrieves only active mappings (is_active = true).
    ///
    /// Parameters: none.
    /// Returns: list of active `DeviceMapping` values or an error.
    pub async fn get_active_mappings(&self) -> Result<Vec<DeviceMapping>> {
        let rows = sqlx::query(
            "SELECT ip, user, source, last_seen, confidence, mac, is_active, vendor
             FROM mappings
             WHERE is_active = true
             ORDER BY last_seen DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            let ip: String = row.try_get("ip")?;
            let user: String = row.try_get("user")?;
            let source: String = row.try_get("source")?;
            let mac: Option<String> = row.try_get("mac")?;
            let last_seen: DateTime<Utc> = row.try_get("last_seen")?;
            let confidence: i64 = row.try_get("confidence")?;
            let confidence_score =
                u8::try_from(confidence).context("confidence value out of u8 range")?;
            let is_active: bool = row.try_get("is_active")?;
            let vendor: Option<String> = row.try_get("vendor")?;

            results.push(DeviceMapping {
                ip,
                mac,
                current_users: vec![user],
                last_seen,
                source: source_from_str(&source),
                confidence_score,
                is_active,
                vendor,
            });
        }

        Ok(results)
    }

    /// Retrieves events since a given timestamp.
    ///
    /// Parameters: `since` - UTC timestamp; returns events strictly after this time.
    /// Returns: list of `StoredEvent` values or an error.
    pub async fn get_events_since(&self, since: DateTime<Utc>) -> Result<Vec<StoredEvent>> {
        let rows = sqlx::query(
            "SELECT id, ip, user, source, timestamp, raw_data
             FROM events
             WHERE timestamp > ?
             ORDER BY timestamp ASC",
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(StoredEvent {
                id: row.try_get("id")?,
                ip: row.try_get("ip")?,
                user: row.try_get("user")?,
                source: row.try_get("source")?,
                timestamp: row.try_get("timestamp")?,
                raw_data: row.try_get("raw_data")?,
            });
        }

        Ok(results)
    }

    /// Retrieves recent mappings ordered by last_seen.
    ///
    /// Parameters: `limit` - maximum number of records to return.
    /// Returns: list of recent `DeviceMapping` values or an error.
    pub async fn get_recent_mappings(&self, limit: i64) -> Result<Vec<DeviceMapping>> {
        let rows = sqlx::query(
            "SELECT ip, user, source, last_seen, confidence, mac, is_active, vendor
             FROM mappings
             ORDER BY last_seen DESC
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            let ip: String = row.try_get("ip")?;
            let user: String = row.try_get("user")?;
            let source: String = row.try_get("source")?;
            let mac: Option<String> = row.try_get("mac")?;
            let last_seen: DateTime<Utc> = row.try_get("last_seen")?;
            let confidence: i64 = row.try_get("confidence")?;
            let confidence_score =
                u8::try_from(confidence).context("confidence value out of u8 range")?;
            let is_active: bool = row.try_get("is_active")?;
            let vendor: Option<String> = row.try_get("vendor")?;

            results.push(DeviceMapping {
                ip,
                mac,
                current_users: vec![user],
                last_seen,
                source: source_from_str(&source),
                confidence_score,
                is_active,
                vendor,
            });
        }

        Ok(results)
    }
}

/// Connects to the database, runs migrations, and returns a ready `Db` instance.
///
/// Parameters: `db_url` - SQLite connection string (e.g. "sqlite://trueid.db").
/// Returns: initialized `Db` or an error.
pub async fn init_db(db_url: &str) -> Result<Db> {
    let pool = SqlitePool::connect(db_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(Db::new(pool))
}

/// Converts `SourceType` to a stable string for persistence.
///
/// Parameters: `source` - source variant.
/// Returns: string representation.
fn source_to_str(source: SourceType) -> &'static str {
    match source {
        SourceType::Radius => "Radius",
        SourceType::AdLog => "AdLog",
        SourceType::DhcpLease => "DhcpLease",
        SourceType::Manual => "Manual",
    }
}

/// Converts a stored string back to `SourceType`.
///
/// Parameters: `value` - source string from storage.
/// Returns: parsed `SourceType` or `Manual` for unknown values.
fn source_from_str(value: &str) -> SourceType {
    match value {
        "Radius" => SourceType::Radius,
        "AdLog" => SourceType::AdLog,
        "Dhcp" | "DhcpLease" => SourceType::DhcpLease,
        "Manual" => SourceType::Manual,
        _ => SourceType::Manual,
    }
}

/// Returns numeric priority for comparing sources (higher wins).
///
/// Parameters: `source` - source type.
/// Returns: integer priority.
fn source_priority(source: &SourceType) -> u8 {
    match source {
        SourceType::Radius => 3,
        SourceType::AdLog => 2,
        SourceType::DhcpLease => 1,
        SourceType::Manual => 0,
    }
}
