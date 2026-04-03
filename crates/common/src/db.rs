//! Data access layer for TrueID (SQLite via sqlx).

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use anyhow::{Context, Result};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::model::{AgentInfo, DeviceMapping, IdentityEvent, SourceType, StoredEvent, SyncStatus};

/// Config keys whose values are encrypted at rest when an encryption key is available.
const SENSITIVE_CONFIG_KEYS: &[&str] = &["sycope_pass", "sycope_login"];

/// Canonical SELECT columns for mapping queries.
///
/// Usage: `format!("{MAPPING_SELECT} FROM mappings m LEFT JOIN ... WHERE ...")`.
pub const MAPPING_SELECT: &str =
    "SELECT m.ip, m.user, m.source, m.last_seen, m.confidence, m.mac, m.is_active, m.vendor,
            m.subnet_id, s.name as subnet_name, d.hostname, m.device_type, m.multi_user,
            m.country_code, m.city,
            (SELECT GROUP_CONCAT(DISTINCT ug.group_name)
             FROM user_groups ug
             WHERE lower(ug.username) = lower(m.user)) as group_names,
            (SELECT GROUP_CONCAT(DISTINCT sess.user)
             FROM ip_sessions sess
             WHERE sess.ip = m.ip AND sess.is_active = 1) as session_users,
            (SELECT GROUP_CONCAT(DISTINCT t.tag || '|' || COALESCE(t.color, '#6b8579'))
             FROM ip_tags t
             WHERE t.ip = m.ip) as ip_tags_csv";

/// SQLite-backed database access.
pub struct Db {
    pool: SqlitePool,
    pepper: Option<String>,
    encryption_key: Option<[u8; 32]>,
}

/// Report schedule persistence model.
#[derive(Debug, Clone)]
pub struct ReportScheduleRecord {
    pub id: i64,
    pub name: String,
    pub report_type: String,
    pub schedule_cron: String,
    pub enabled: bool,
    pub channel_ids: String,
    pub include_sections: String,
    pub last_sent_at: Option<String>,
    pub created_by: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

impl Db {
    /// Creates a new database wrapper from an existing pool.
    ///
    /// Parameters: `pool` - SQLite connection pool,
    /// `pepper` - optional Argon2 pepper for password hashing,
    /// `encryption_key` - optional AES-256 key for config encryption.
    /// Returns: `Db` instance.
    pub fn new(pool: SqlitePool, pepper: Option<String>, encryption_key: Option<[u8; 32]>) -> Self {
        Self {
            pool,
            pepper,
            encryption_key,
        }
    }

    /// Returns a reference to the underlying connection pool.
    ///
    /// Useful for running custom queries not covered by Db methods.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Returns the optional Argon2 pepper for password hashing.
    pub fn pepper(&self) -> Option<&str> {
        self.pepper.as_deref()
    }

    /// Encrypts a value using the configured config encryption key.
    ///
    /// Parameters: `plaintext` - value to encrypt.
    /// Returns: encrypted `enc:...` string.
    pub fn encrypt_config_value(&self, plaintext: &str) -> Result<String> {
        let key = self
            .encryption_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("CONFIG_ENCRYPTION_KEY required to encrypt values"))?;
        encrypt_value(key, plaintext)
    }

    /// Decrypts an encrypted config value using the configured key.
    ///
    /// Parameters: `stored` - persisted `enc:...` value.
    /// Returns: plaintext string.
    pub fn decrypt_config_value(&self, stored: &str) -> Result<String> {
        let key = self
            .encryption_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("CONFIG_ENCRYPTION_KEY required to decrypt values"))?;
        decrypt_value(key, stored)
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

        sqlx::query(
            "INSERT INTO ip_sessions (ip, user, source, mac, session_start, last_seen, is_active)
             VALUES (?, ?, ?, ?, ?, ?, 1)
             ON CONFLICT(ip, user, source) DO UPDATE SET
                 last_seen = excluded.last_seen,
                 mac = COALESCE(excluded.mac, ip_sessions.mac),
                 is_active = 1",
        )
        .bind(&ip)
        .bind(&event.user)
        .bind(source)
        .bind(mac)
        .bind(last_seen)
        .bind(last_seen)
        .execute(&mut *tx)
        .await?;

        let active_count: i64 = sqlx::query(
            "SELECT COUNT(DISTINCT user) as c FROM ip_sessions WHERE ip = ? AND is_active = 1",
        )
        .bind(&ip)
        .fetch_one(&mut *tx)
        .await?
        .try_get("c")
        .unwrap_or(0);

        sqlx::query("UPDATE mappings SET multi_user = ? WHERE ip = ?")
            .bind(active_count > 1)
            .bind(&ip)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(())
    }

    /// Retrieves a mapping for the given IP.
    ///
    /// Parameters: `ip` - IP address string to look up.
    /// Returns: optional `DeviceMapping` if found or an error.
    pub async fn get_mapping(&self, ip: &str) -> Result<Option<DeviceMapping>> {
        let sql = format!(
            "{MAPPING_SELECT}
             FROM mappings m
             LEFT JOIN subnets s ON m.subnet_id = s.id
             LEFT JOIN dns_cache d ON m.ip = d.ip
             WHERE m.ip = ?"
        );
        let row = sqlx::query(&sql)
            .bind(ip)
            .fetch_optional(&self.pool)
            .await?;

        let Some(row) = row else {
            return Ok(None);
        };
        Ok(Some(DeviceMapping::from_row(&row)?))
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

        sqlx::query(
            "UPDATE ip_sessions SET is_active = 0
             WHERE is_active = 1 AND last_seen < datetime('now', ? || ' minutes')",
        )
        .bind(-ttl_minutes)
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "UPDATE mappings
             SET multi_user = (
                 SELECT CASE WHEN COUNT(DISTINCT user) > 1 THEN 1 ELSE 0 END
                 FROM ip_sessions
                 WHERE ip = mappings.ip AND is_active = 1
             )",
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Retrieves only active mappings (is_active = true).
    ///
    /// Parameters: none.
    /// Returns: list of active `DeviceMapping` values or an error.
    pub async fn get_active_mappings(&self) -> Result<Vec<DeviceMapping>> {
        let sql = format!(
            "{MAPPING_SELECT}
             FROM mappings m
             LEFT JOIN subnets s ON m.subnet_id = s.id
             LEFT JOIN dns_cache d ON m.ip = d.ip
             WHERE m.is_active = true
             ORDER BY m.last_seen DESC"
        );
        let rows = sqlx::query(&sql).fetch_all(&self.pool).await?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(DeviceMapping::from_row(&row)?);
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
        let raw: Option<String> = row.map(|r| r.try_get("value")).transpose()?;
        match raw {
            Some(v) if v.starts_with("enc:") => {
                let enc_key = self.encryption_key.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "CONFIG_ENCRYPTION_KEY required to decrypt config value for '{key}'"
                    )
                })?;
                Ok(Some(decrypt_value(enc_key, &v)?))
            }
            other => Ok(other),
        }
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
        let stored = if SENSITIVE_CONFIG_KEYS.contains(&key) {
            if let Some(ref enc_key) = self.encryption_key {
                encrypt_value(enc_key, value)?
            } else {
                value.to_string()
            }
        } else {
            value.to_string()
        };
        sqlx::query(
            "INSERT INTO config (key, value, updated_at) VALUES (?, ?, datetime('now'))
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(key)
        .bind(&stored)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Agents ──────────────────────────────────────────────

    /// Upserts an agent heartbeat record.
    pub async fn upsert_agent(
        &self,
        hostname: &str,
        uptime: i64,
        sent: i64,
        dropped: i64,
        transport: &str,
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
            let status = if (now - hb).num_minutes() < 3 {
                "online"
            } else {
                "offline"
            };
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
        &self,
        integration: &str,
        status: &str,
        message: Option<&str>,
        records: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO sync_status (integration, last_run_at, status, message, records_synced)
             VALUES (?, datetime('now'), ?, ?, ?)
             ON CONFLICT(integration) DO UPDATE SET
                last_run_at = datetime('now'), status = excluded.status,
                message = excluded.message, records_synced = excluded.records_synced",
        )
        .bind(integration)
        .bind(status)
        .bind(message)
        .bind(records)
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
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("c")?)
    }

    /// Counts events grouped by source.
    pub async fn count_events_by_source(&self) -> Result<HashMap<String, i64>> {
        let rows = sqlx::query("SELECT source, COUNT(*) as c FROM events GROUP BY source")
            .fetch_all(&self.pool)
            .await?;
        let mut map = HashMap::new();
        for r in rows {
            map.insert(r.try_get("source")?, r.try_get("c")?);
        }
        Ok(map)
    }

    /// Returns the timestamp of the most recent event.
    pub async fn get_last_event_timestamp(&self) -> Result<Option<DateTime<Utc>>> {
        let row = sqlx::query("SELECT MAX(timestamp) as t FROM events")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("t")?)
    }

    /// Deletes a mapping by IP. Returns true if a row was deleted.
    pub async fn delete_mapping(&self, ip: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM mappings WHERE ip = ?")
            .bind(ip)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Returns events for a specific IP, most recent first.
    pub async fn get_events_for_ip(&self, ip: &str, limit: i64) -> Result<Vec<StoredEvent>> {
        let rows = sqlx::query(
            "SELECT id, ip, user, source, timestamp, raw_data
             FROM events WHERE ip = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(ip)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
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
        let sql = format!(
            "{MAPPING_SELECT}
             FROM mappings m
             LEFT JOIN subnets s ON m.subnet_id = s.id
             LEFT JOIN dns_cache d ON m.ip = d.ip
             ORDER BY m.last_seen DESC
             LIMIT ?"
        );
        let rows = sqlx::query(&sql).bind(limit).fetch_all(&self.pool).await?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(DeviceMapping::from_row(&row)?);
        }

        Ok(results)
    }

    /// Lists all report schedules ordered by newest first.
    ///
    /// Parameters: none.
    /// Returns: report schedule rows.
    pub async fn list_report_schedules(&self) -> Result<Vec<ReportScheduleRecord>> {
        let rows = sqlx::query(
            "SELECT id, name, report_type, schedule_cron, enabled, channel_ids, include_sections,
                    last_sent_at, created_by, created_at, updated_at
             FROM report_schedules
             ORDER BY id DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(Self::map_report_schedule_row)
            .collect::<Vec<_>>())
    }

    /// Fetches one report schedule by identifier.
    ///
    /// Parameters: `id` - schedule identifier.
    /// Returns: optional report schedule row.
    pub async fn get_report_schedule(&self, id: i64) -> Result<Option<ReportScheduleRecord>> {
        let row = sqlx::query(
            "SELECT id, name, report_type, schedule_cron, enabled, channel_ids, include_sections,
                    last_sent_at, created_by, created_at, updated_at
             FROM report_schedules
             WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(Self::map_report_schedule_row))
    }

    /// Inserts a new report schedule.
    ///
    /// Parameters: payload fields matching `report_schedules` columns.
    /// Returns: inserted row ID.
    pub async fn create_report_schedule(
        &self,
        name: &str,
        report_type: &str,
        schedule_cron: &str,
        enabled: bool,
        channel_ids_json: &str,
        include_sections_json: &str,
        created_by: i64,
    ) -> Result<i64> {
        let created = sqlx::query(
            "INSERT INTO report_schedules
             (name, report_type, schedule_cron, enabled, channel_ids, include_sections, created_by, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))",
        )
        .bind(name)
        .bind(report_type)
        .bind(schedule_cron)
        .bind(enabled)
        .bind(channel_ids_json)
        .bind(include_sections_json)
        .bind(created_by)
        .execute(&self.pool)
        .await?;
        Ok(created.last_insert_rowid())
    }

    /// Updates an existing report schedule by ID.
    ///
    /// Parameters: payload fields matching updatable columns.
    /// Returns: true when row was updated.
    pub async fn update_report_schedule(
        &self,
        id: i64,
        name: &str,
        report_type: &str,
        schedule_cron: &str,
        enabled: bool,
        channel_ids_json: &str,
        include_sections_json: &str,
    ) -> Result<bool> {
        let updated = sqlx::query(
            "UPDATE report_schedules
             SET name = ?, report_type = ?, schedule_cron = ?, enabled = ?, channel_ids = ?, include_sections = ?, updated_at = datetime('now')
             WHERE id = ?",
        )
        .bind(name)
        .bind(report_type)
        .bind(schedule_cron)
        .bind(enabled)
        .bind(channel_ids_json)
        .bind(include_sections_json)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(updated.rows_affected() > 0)
    }

    /// Deletes report schedule by ID.
    ///
    /// Parameters: `id` - schedule identifier.
    /// Returns: true when row was deleted.
    pub async fn delete_report_schedule(&self, id: i64) -> Result<bool> {
        let deleted = sqlx::query("DELETE FROM report_schedules WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(deleted.rows_affected() > 0)
    }

    /// Returns parsed channel IDs JSON string for report schedule.
    ///
    /// Parameters: `id` - schedule identifier.
    /// Returns: optional channel_ids JSON string.
    pub async fn get_report_schedule_channel_ids(&self, id: i64) -> Result<Option<String>> {
        let row = sqlx::query("SELECT channel_ids FROM report_schedules WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| r.try_get::<String, _>("channel_ids").ok()))
    }

    /// Maps SQL row into `ReportScheduleRecord`.
    ///
    /// Parameters: `row` - row fetched from `report_schedules`.
    /// Returns: normalized record.
    fn map_report_schedule_row(row: &sqlx::sqlite::SqliteRow) -> ReportScheduleRecord {
        ReportScheduleRecord {
            id: row.try_get("id").unwrap_or_default(),
            name: row.try_get("name").unwrap_or_default(),
            report_type: row
                .try_get("report_type")
                .unwrap_or_else(|_| "daily".to_string()),
            schedule_cron: row
                .try_get("schedule_cron")
                .unwrap_or_else(|_| "0 8 * * 1".to_string()),
            enabled: row.try_get("enabled").unwrap_or(true),
            channel_ids: row
                .try_get("channel_ids")
                .unwrap_or_else(|_| "[]".to_string()),
            include_sections: row
                .try_get("include_sections")
                .unwrap_or_else(|_| "[\"summary\",\"conflicts\",\"alerts\"]".to_string()),
            last_sent_at: row.try_get("last_sent_at").ok(),
            created_by: row.try_get("created_by").ok(),
            created_at: row.try_get("created_at").unwrap_or_default(),
            updated_at: row.try_get("updated_at").unwrap_or_default(),
        }
    }
}

/// Analytics helper re-exports for backwards compatibility.
pub use crate::db_analytics::*;

/// Connects to the database, runs migrations, and returns a ready `Db` instance.
///
/// Reads `ARGON2_PEPPER` env var for password hashing pepper.
/// Parameters: `db_url` - SQLite connection string (e.g. "sqlite://trueid.db").
/// Returns: initialized `Db` or an error.
/// Encrypts a plaintext value using AES-256-GCM.
///
/// Parameters: `key` - 32-byte encryption key, `plaintext` - value to encrypt.
/// Returns: "enc:" + base64(nonce ‖ ciphertext+tag).
fn encrypt_value(key: &[u8; 32], plaintext: &str) -> Result<String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt failed: {e}"))?;
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ciphertext);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&blob);
    Ok(format!("enc:{encoded}"))
}

/// Decrypts a stored "enc:..." value using AES-256-GCM.
///
/// Parameters: `key` - 32-byte encryption key, `stored` - "enc:" prefixed value.
/// Returns: decrypted plaintext string.
fn decrypt_value(key: &[u8; 32], stored: &str) -> Result<String> {
    let encoded = stored
        .strip_prefix("enc:")
        .ok_or_else(|| anyhow::anyhow!("not an encrypted value"))?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("base64 decode failed")?;
    if blob.len() < 12 {
        anyhow::bail!("encrypted blob too short");
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-GCM decrypt failed: {e}"))?;
    String::from_utf8(plaintext).context("decrypted value is not valid UTF-8")
}

/// Parses CONFIG_ENCRYPTION_KEY env var (64 hex chars → 32 bytes).
///
/// Returns: `Some([u8; 32])` if set and valid, `None` otherwise.
fn parse_encryption_key() -> Option<[u8; 32]> {
    let hex = std::env::var("CONFIG_ENCRYPTION_KEY").ok()?;
    let hex = hex.trim();
    if hex.is_empty() {
        return None;
    }
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        tracing::warn!("CONFIG_ENCRYPTION_KEY is set but not 64 hex chars — ignoring");
        return None;
    }
    let mut key = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0]);
        let lo = hex_nibble(chunk[1]);
        key[i] = (hi << 4) | lo;
    }
    Some(key)
}

/// Converts an ASCII hex char to its 4-bit value.
fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Auto-encrypts plaintext sensitive config values on startup.
///
/// Parameters: `pool` - database pool, `key` - encryption key.
/// Scans SENSITIVE_CONFIG_KEYS for values not prefixed with "enc:".
async fn auto_encrypt_sensitive_config(pool: &SqlitePool, key: &[u8; 32]) -> Result<()> {
    let mut count = 0u32;
    for cfg_key in SENSITIVE_CONFIG_KEYS {
        let row = sqlx::query("SELECT value FROM config WHERE key = ?")
            .bind(cfg_key)
            .fetch_optional(pool)
            .await?;
        if let Some(row) = row {
            let value: String = row.try_get("value")?;
            if !value.is_empty() && !value.starts_with("enc:") {
                let encrypted = encrypt_value(key, &value)?;
                sqlx::query(
                    "UPDATE config SET value = ?, updated_at = datetime('now') WHERE key = ?",
                )
                .bind(&encrypted)
                .bind(cfg_key)
                .execute(pool)
                .await?;
                count += 1;
            }
        }
    }
    if count > 0 {
        tracing::info!(count, "Auto-encrypted plaintext sensitive config values");
    }
    Ok(())
}

/// Initialises the database: connects, runs migrations, reads secrets from env.
///
/// Migration source is `crates/common/migrations/`.
///
/// Parameters: `db_url` - SQLite connection string (e.g. "sqlite://trueid.db").
/// Returns: initialized `Db` or an error.
/// Reads `ARGON2_PEPPER` and `CONFIG_ENCRYPTION_KEY` env vars.
pub async fn init_db(db_url: &str) -> Result<Db> {
    ensure_sqlite_parent_dir(db_url)?;
    let pool = SqlitePool::connect(db_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    let pepper = std::env::var("ARGON2_PEPPER")
        .ok()
        .filter(|s| !s.is_empty());
    let encryption_key = parse_encryption_key();

    if let Some(ref key) = encryption_key {
        if let Err(e) = auto_encrypt_sensitive_config(&pool, key).await {
            tracing::warn!(error = %e, "Failed to auto-encrypt sensitive config values");
        }
    }

    Ok(Db::new(pool, pepper, encryption_key))
}

/// Extracts a local SQLite file path from a SQLite connection URL.
///
/// Parameters: `db_url` - SQLite URL, e.g. `sqlite:///app/data/net-identity.db?mode=rwc`.
/// Returns: `Some(path)` for file-backed SQLite URLs, otherwise `None`.
fn sqlite_path_from_url(db_url: &str) -> Option<PathBuf> {
    let rest = db_url.strip_prefix("sqlite:")?;
    let path_part = rest.split('?').next().unwrap_or(rest);
    if path_part.is_empty() || path_part == ":memory:" {
        return None;
    }
    if let Some(stripped) = path_part.strip_prefix("///") {
        return Some(PathBuf::from(format!("/{stripped}")));
    }
    if let Some(stripped) = path_part.strip_prefix("//") {
        return Some(PathBuf::from(stripped));
    }
    Some(PathBuf::from(path_part))
}

/// Creates the SQLite parent directory when the URL points to a file path.
///
/// Parameters: `db_url` - database URL used for initialization.
/// Returns: `Ok(())` when no directory is needed or it exists/was created.
fn ensure_sqlite_parent_dir(db_url: &str) -> Result<()> {
    let Some(db_path) = sqlite_path_from_url(db_url) else {
        return Ok(());
    };
    let Some(parent) = db_path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() || parent == Path::new(".") {
        return Ok(());
    }
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create sqlite parent directory '{}' for DATABASE_URL '{}'",
            parent.display(),
            db_url
        )
    })?;
    Ok(())
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
        SourceType::VpnAnyConnect => "vpn_anyconnect",
        SourceType::VpnGlobalProtect => "vpn_globalprotect",
        SourceType::VpnFortinet => "vpn_fortinet",
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
        SourceType::VpnAnyConnect => 2,
        SourceType::VpnGlobalProtect => 2,
        SourceType::VpnFortinet => 2,
        SourceType::DhcpLease => 1,
        SourceType::Manual => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_path_absolute_triple_slash() {
        assert_eq!(
            sqlite_path_from_url("sqlite:///app/data/net-identity.db?mode=rwc"),
            Some(PathBuf::from("/app/data/net-identity.db"))
        );
    }

    #[test]
    fn sqlite_path_absolute_no_query() {
        assert_eq!(
            sqlite_path_from_url("sqlite:///data/test.db"),
            Some(PathBuf::from("/data/test.db"))
        );
    }

    #[test]
    fn sqlite_path_relative_double_slash() {
        assert_eq!(
            sqlite_path_from_url("sqlite://net-identity.db?mode=rwc"),
            Some(PathBuf::from("net-identity.db"))
        );
    }

    #[test]
    fn sqlite_path_relative_no_slashes() {
        assert_eq!(
            sqlite_path_from_url("sqlite:test.db"),
            Some(PathBuf::from("test.db"))
        );
    }

    #[test]
    fn sqlite_path_memory_returns_none() {
        assert_eq!(sqlite_path_from_url("sqlite::memory:"), None);
    }

    #[test]
    fn sqlite_path_empty_returns_none() {
        assert_eq!(sqlite_path_from_url("sqlite:"), None);
    }

    #[test]
    fn sqlite_path_not_sqlite_returns_none() {
        assert_eq!(sqlite_path_from_url("postgres://localhost/db"), None);
    }

    #[test]
    fn ensure_parent_creates_nested_dirs() {
        let base = std::env::temp_dir().join(format!("trueid-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let url = format!("sqlite:///{}/a/b/test.db?mode=rwc", base.display());

        ensure_sqlite_parent_dir(&url).unwrap();
        assert!(base.join("a/b").is_dir());

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn ensure_parent_existing_dir_is_ok() {
        let base = std::env::temp_dir().join(format!("trueid-test2-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let url = format!("sqlite:///{}/test.db", base.display());

        ensure_sqlite_parent_dir(&url).unwrap();

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn ensure_parent_memory_noop() {
        ensure_sqlite_parent_dir("sqlite::memory:").unwrap();
    }

    #[test]
    fn ensure_parent_relative_no_parent_noop() {
        ensure_sqlite_parent_dir("sqlite:test.db").unwrap();
    }

    #[tokio::test]
    async fn init_db_creates_tables() {
        let base = std::env::temp_dir().join(format!("trueid-initdb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let db_path = base.join("init-test.db");
        let url = format!("sqlite:///{}?mode=rwc", db_path.display());

        let db = init_db(&url).await.expect("init_db should succeed");

        assert!(db_path.exists(), "DB file should exist after init");

        let tables: Vec<(String,)> =
            sqlx::query_as("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                .fetch_all(db.pool())
                .await
                .unwrap();

        let table_names: Vec<&str> = tables.iter().map(|t| t.0.as_str()).collect();
        assert!(
            table_names.contains(&"mappings"),
            "mappings table must exist"
        );
        assert!(table_names.contains(&"events"), "events table must exist");
        assert!(table_names.contains(&"users"), "users table must exist");
        assert!(
            table_names.contains(&"sessions"),
            "sessions table must exist"
        );
        assert!(table_names.contains(&"config"), "config table must exist");

        db.close().await;
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn init_db_creates_parent_dir_if_missing() {
        let base = std::env::temp_dir().join(format!("trueid-nested-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let db_path = base.join("sub/dir/nested.db");
        let url = format!("sqlite:///{}?mode=rwc", db_path.display());

        let db = init_db(&url)
            .await
            .expect("init_db should create parent dirs");
        assert!(db_path.exists());

        db.close().await;
        std::fs::remove_dir_all(&base).ok();
    }
}
