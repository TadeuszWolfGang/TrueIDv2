//! Data access layer for TrueID (SQLite via sqlx).

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};

use std::collections::HashMap;

use crate::model::{AgentInfo, DeviceMapping, IdentityEvent, SourceType, StoredEvent, SyncStatus};

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

    /// Returns a reference to the underlying connection pool.
    ///
    /// Useful for running custom queries not covered by Db methods.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
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

    // ── Config CRUD ──────────────────────────────────────────

    /// Reads a config value by key.
    pub async fn get_config(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM config WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.try_get("value")).transpose()?)
    }

    /// Reads a config value as i64, returning `default` if missing.
    pub async fn get_config_i64(&self, key: &str, default: i64) -> i64 {
        self.get_config(key)
            .await
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Writes a config key-value pair (upsert).
    pub async fn set_config(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO config (key, value, updated_at) VALUES (?, ?, datetime('now'))
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Agents ──────────────────────────────────────────────

    /// Upserts an agent heartbeat record.
    pub async fn upsert_agent(
        &self, hostname: &str, uptime: i64, sent: i64, dropped: i64, transport: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO agents (hostname, last_heartbeat, uptime_secs, events_sent, events_dropped, transport, updated_at)
             VALUES (?, datetime('now'), ?, ?, ?, ?, datetime('now'))
             ON CONFLICT(hostname) DO UPDATE SET
                last_heartbeat = datetime('now'), uptime_secs = excluded.uptime_secs,
                events_sent = excluded.events_sent, events_dropped = excluded.events_dropped,
                transport = excluded.transport, updated_at = datetime('now')",
        )
        .bind(hostname).bind(uptime).bind(sent).bind(dropped).bind(transport)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns all registered agents with computed online/offline status.
    pub async fn get_agents(&self) -> Result<Vec<AgentInfo>> {
        let rows = sqlx::query(
            "SELECT hostname, last_heartbeat, uptime_secs, events_sent, events_dropped, transport
             FROM agents ORDER BY last_heartbeat DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        let now = Utc::now();
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let hb: DateTime<Utc> = r.try_get("last_heartbeat")?;
            let status = if (now - hb).num_minutes() < 3 { "online" } else { "offline" };
            out.push(AgentInfo {
                hostname: r.try_get("hostname")?,
                last_heartbeat: hb,
                uptime_seconds: r.try_get("uptime_secs")?,
                events_sent: r.try_get("events_sent")?,
                events_dropped: r.try_get("events_dropped")?,
                transport: r.try_get("transport")?,
                status: status.to_string(),
            });
        }
        Ok(out)
    }

    // ── Sync status ─────────────────────────────────────────

    /// Reads sync status for an integration.
    pub async fn get_sync_status(&self, integration: &str) -> Result<Option<SyncStatus>> {
        let row = sqlx::query(
            "SELECT integration, last_run_at, status, message, records_synced
             FROM sync_status WHERE integration = ?",
        )
        .bind(integration)
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else { return Ok(None) };
        Ok(Some(SyncStatus {
            integration: r.try_get("integration")?,
            last_run_at: r.try_get("last_run_at")?,
            status: r.try_get("status")?,
            message: r.try_get("message")?,
            records_synced: r.try_get::<i64, _>("records_synced").unwrap_or(0),
        }))
    }

    /// Upserts sync status for an integration.
    pub async fn set_sync_status(
        &self, integration: &str, status: &str, message: Option<&str>, records: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO sync_status (integration, last_run_at, status, message, records_synced)
             VALUES (?, datetime('now'), ?, ?, ?)
             ON CONFLICT(integration) DO UPDATE SET
                last_run_at = datetime('now'), status = excluded.status,
                message = excluded.message, records_synced = excluded.records_synced",
        )
        .bind(integration).bind(status).bind(message).bind(records)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Aggregate queries ───────────────────────────────────

    /// Counts mappings, optionally filtered by active status.
    pub async fn count_mappings(&self, active_only: Option<bool>) -> Result<i64> {
        let sql = match active_only {
            Some(true) => "SELECT COUNT(*) as c FROM mappings WHERE is_active = true",
            Some(false) => "SELECT COUNT(*) as c FROM mappings WHERE is_active = false",
            None => "SELECT COUNT(*) as c FROM mappings",
        };
        let row = sqlx::query(sql).fetch_one(&self.pool).await?;
        Ok(row.try_get("c")?)
    }

    /// Counts all events.
    pub async fn count_events(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as c FROM events")
            .fetch_one(&self.pool).await?;
        Ok(row.try_get("c")?)
    }

    /// Counts events grouped by source.
    pub async fn count_events_by_source(&self) -> Result<HashMap<String, i64>> {
        let rows = sqlx::query("SELECT source, COUNT(*) as c FROM events GROUP BY source")
            .fetch_all(&self.pool).await?;
        let mut map = HashMap::new();
        for r in rows {
            map.insert(r.try_get("source")?, r.try_get("c")?);
        }
        Ok(map)
    }

    /// Returns the timestamp of the most recent event.
    pub async fn get_last_event_timestamp(&self) -> Result<Option<DateTime<Utc>>> {
        let row = sqlx::query("SELECT MAX(timestamp) as t FROM events")
            .fetch_one(&self.pool).await?;
        Ok(row.try_get("t")?)
    }

    /// Deletes a mapping by IP. Returns true if a row was deleted.
    pub async fn delete_mapping(&self, ip: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM mappings WHERE ip = ?")
            .bind(ip).execute(&self.pool).await?;
        Ok(res.rows_affected() > 0)
    }

    /// Returns events for a specific IP, most recent first.
    pub async fn get_events_for_ip(&self, ip: &str, limit: i64) -> Result<Vec<StoredEvent>> {
        let rows = sqlx::query(
            "SELECT id, ip, user, source, timestamp, raw_data
             FROM events WHERE ip = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(ip).bind(limit)
        .fetch_all(&self.pool).await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(StoredEvent {
                id: r.try_get("id")?,
                ip: r.try_get("ip")?,
                user: r.try_get("user")?,
                source: r.try_get("source")?,
                timestamp: r.try_get("timestamp")?,
                raw_data: r.try_get("raw_data")?,
            });
        }
        Ok(out)
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

/// Re-export for backwards compatibility.
pub use crate::model::source_from_str;

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
