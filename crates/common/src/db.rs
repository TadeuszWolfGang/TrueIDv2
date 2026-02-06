//! Data access layer for TrueID (SQLite via sqlx).

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};

use crate::model::{DeviceMapping, IdentityEvent, SourceType};

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
    /// Parameters: `event` - identity event to persist.
    /// Returns: `Ok(())` on success or an error.
    pub async fn upsert_mapping(&self, event: IdentityEvent) -> Result<()> {
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
                    "INSERT INTO mappings (ip, user, source, last_seen, confidence, mac)
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&ip)
                .bind(&event.user)
                .bind(source)
                .bind(last_seen)
                .bind(confidence)
                .bind(mac)
                .execute(&mut *tx)
                .await?;
            }
            Some(existing_source) => {
                let existing_priority = source_priority(&source_from_str(&existing_source));
                let incoming_priority = source_priority(&event.source);
                if incoming_priority >= existing_priority {
                    sqlx::query(
                        "UPDATE mappings
                         SET user = ?, source = ?, last_seen = ?, confidence = ?, mac = COALESCE(?, mac)
                         WHERE ip = ?",
                    )
                    .bind(&event.user)
                    .bind(source)
                    .bind(last_seen)
                    .bind(confidence)
                    .bind(mac)
                    .bind(&ip)
                    .execute(&mut *tx)
                    .await?;
                } else {
                    sqlx::query(
                        "UPDATE mappings
                         SET last_seen = ?, confidence = ?, mac = COALESCE(?, mac)
                         WHERE ip = ?",
                    )
                    .bind(last_seen)
                    .bind(confidence)
                    .bind(mac)
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
            "SELECT ip, user, source, last_seen, confidence, mac
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

        Ok(Some(DeviceMapping {
            ip,
            mac,
            current_users: vec![user],
            last_seen,
            source: source_from_str(&source),
            confidence_score,
        }))
    }

    /// Retrieves recent mappings ordered by last_seen.
    ///
    /// Parameters: `limit` - maximum number of records to return.
    /// Returns: list of recent `DeviceMapping` values or an error.
    pub async fn get_recent_mappings(&self, limit: i64) -> Result<Vec<DeviceMapping>> {
        let rows = sqlx::query(
            "SELECT ip, user, source, last_seen, confidence, mac
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

            results.push(DeviceMapping {
                ip,
                mac,
                current_users: vec![user],
                last_seen,
                source: source_from_str(&source),
                confidence_score,
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
