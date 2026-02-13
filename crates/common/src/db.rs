//! Data access layer for TrueID (SQLite via sqlx).

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use anyhow::{Context, Result};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};

use std::collections::HashMap;

use crate::model::{AgentInfo, DeviceMapping, IdentityEvent, SourceType, StoredEvent, SyncStatus};

/// Config keys whose values are encrypted at rest when an encryption key is available.
const SENSITIVE_CONFIG_KEYS: &[&str] = &["sycope_pass", "sycope_login"];

/// SQLite-backed database access.
pub struct Db {
    pool: SqlitePool,
    pepper: Option<String>,
    encryption_key: Option<[u8; 32]>,
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

        tx.commit().await?;

        Ok(())
    }

    /// Retrieves a mapping for the given IP.
    ///
    /// Parameters: `ip` - IP address string to look up.
    /// Returns: optional `DeviceMapping` if found or an error.
    pub async fn get_mapping(&self, ip: &str) -> Result<Option<DeviceMapping>> {
        let row = sqlx::query(
            "SELECT m.ip, m.user, m.source, m.last_seen, m.confidence, m.mac, m.is_active, m.vendor,
                    m.subnet_id, s.name as subnet_name, d.hostname
             FROM mappings m
             LEFT JOIN subnets s ON m.subnet_id = s.id
             LEFT JOIN dns_cache d ON m.ip = d.ip
             WHERE m.ip = ?",
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
        let subnet_id: Option<i64> = row.try_get("subnet_id").ok();
        let subnet_name: Option<String> = row.try_get("subnet_name").ok();
        let hostname: Option<String> = row.try_get("hostname").ok();

        Ok(Some(DeviceMapping {
            ip,
            mac,
            current_users: vec![user],
            last_seen,
            source: source_from_str(&source),
            confidence_score,
            is_active,
            vendor,
            subnet_id,
            subnet_name,
            hostname,
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
            "SELECT m.ip, m.user, m.source, m.last_seen, m.confidence, m.mac, m.is_active, m.vendor,
                    m.subnet_id, s.name as subnet_name, d.hostname
             FROM mappings m
             LEFT JOIN subnets s ON m.subnet_id = s.id
             LEFT JOIN dns_cache d ON m.ip = d.ip
             WHERE m.is_active = true
             ORDER BY m.last_seen DESC",
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
            let subnet_id: Option<i64> = row.try_get("subnet_id").ok();
            let subnet_name: Option<String> = row.try_get("subnet_name").ok();
            let hostname: Option<String> = row.try_get("hostname").ok();

            results.push(DeviceMapping {
                ip,
                mac,
                current_users: vec![user],
                last_seen,
                source: source_from_str(&source),
                confidence_score,
                is_active,
                vendor,
                subnet_id,
                subnet_name,
                hostname,
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
        let rows = sqlx::query(
            "SELECT m.ip, m.user, m.source, m.last_seen, m.confidence, m.mac, m.is_active, m.vendor,
                    m.subnet_id, s.name as subnet_name, d.hostname
             FROM mappings m
             LEFT JOIN subnets s ON m.subnet_id = s.id
             LEFT JOIN dns_cache d ON m.ip = d.ip
             ORDER BY m.last_seen DESC
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
            let subnet_id: Option<i64> = row.try_get("subnet_id").ok();
            let subnet_name: Option<String> = row.try_get("subnet_name").ok();
            let hostname: Option<String> = row.try_get("hostname").ok();

            results.push(DeviceMapping {
                ip,
                mac,
                current_users: vec![user],
                last_seen,
                source: source_from_str(&source),
                confidence_score,
                is_active,
                vendor,
                subnet_id,
                subnet_name,
                hostname,
            });
        }

        Ok(results)
    }
}

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
/// Parameters: `db_url` - SQLite connection string (e.g. "sqlite://trueid.db").
/// Returns: initialized `Db` or an error.
/// Reads `ARGON2_PEPPER` and `CONFIG_ENCRYPTION_KEY` env vars.
pub async fn init_db(db_url: &str) -> Result<Db> {
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
