//! DHCP option 55 fingerprint loading, matching and observation persistence.

use anyhow::Result;
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;

/// In-memory fingerprint lookup entry.
pub struct FingerprintEntry {
    pub fingerprint: String,
    pub device_type: String,
    pub os_family: Option<String>,
}

/// In-memory fingerprint database keyed by normalized fingerprint string.
pub type FingerprintDb = HashMap<String, FingerprintEntry>;

/// Loads all fingerprint definitions from database.
///
/// Parameters: `pool` - SQLite connection pool.
/// Returns: map keyed by fingerprint string.
pub async fn load_fingerprints(pool: &SqlitePool) -> Result<FingerprintDb> {
    let rows = sqlx::query("SELECT fingerprint, device_type, os_family FROM dhcp_fingerprints")
        .fetch_all(pool)
        .await?;
    let mut map = HashMap::with_capacity(rows.len());
    for row in rows {
        let fingerprint: String = row.try_get("fingerprint")?;
        let device_type: String = row.try_get("device_type")?;
        let os_family: Option<String> = row.try_get("os_family").ok();
        map.insert(
            fingerprint.clone(),
            FingerprintEntry {
                fingerprint,
                device_type,
                os_family,
            },
        );
    }
    Ok(map)
}

/// Normalizes raw option 55 data into canonical fingerprint string.
///
/// Parameters: `raw` - raw option list (comma/space separated).
/// Returns: sorted, deduplicated, comma-joined fingerprint or `None` if invalid.
pub fn normalize_fingerprint(raw: &str) -> Option<String> {
    let mut codes: Vec<u16> = raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .filter(|&n| n > 0 && n <= 255)
        .collect();
    if codes.is_empty() {
        return None;
    }
    codes.sort_unstable();
    codes.dedup();
    Some(
        codes
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(","),
    )
}

/// Matches normalized fingerprint against in-memory DB.
///
/// Parameters: `fingerprint` - normalized fingerprint, `db` - lookup map.
/// Returns: device type on exact match.
pub fn match_fingerprint(fingerprint: &str, db: &FingerprintDb) -> Option<String> {
    db.get(fingerprint).map(|e| e.device_type.clone())
}

/// Records DHCP observation and optionally updates mapping device_type.
///
/// Parameters: `pool` - SQLite pool, `mac` - normalized MAC, `ip` - IP string,
/// `fingerprint` - normalized fingerprint, `hostname` - optional DHCP hostname,
/// `device_type` - optional resolved device type.
/// Returns: `Ok(())` on success.
pub async fn record_observation(
    pool: &SqlitePool,
    mac: &str,
    ip: &str,
    fingerprint: &str,
    hostname: Option<&str>,
    device_type: Option<&str>,
) -> Result<()> {
    let match_source = if device_type.is_some() {
        Some("exact")
    } else {
        None
    };

    sqlx::query(
        "INSERT INTO dhcp_observations (mac, fingerprint, device_type, hostname, ip, observed_at, match_source)
         VALUES (?, ?, ?, ?, ?, datetime('now'), ?)
         ON CONFLICT(mac) DO UPDATE SET
            fingerprint = excluded.fingerprint,
            device_type = excluded.device_type,
            hostname = COALESCE(excluded.hostname, dhcp_observations.hostname),
            ip = excluded.ip,
            observed_at = excluded.observed_at,
            match_source = excluded.match_source",
    )
    .bind(mac)
    .bind(fingerprint)
    .bind(device_type)
    .bind(hostname)
    .bind(ip)
    .bind(match_source)
    .execute(pool)
    .await?;

    if let Some(dt) = device_type {
        sqlx::query("UPDATE mappings SET device_type = ? WHERE ip = ?")
            .bind(dt)
            .bind(ip)
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Backfills `mappings.device_type` using known DHCP observations by MAC.
///
/// Parameters: `pool` - SQLite pool.
/// Returns: number of mappings updated.
pub async fn backfill_device_types(pool: &SqlitePool) -> Result<u64> {
    let result = sqlx::query(
        "UPDATE mappings SET device_type = (
            SELECT o.device_type FROM dhcp_observations o
            WHERE o.mac = mappings.mac AND o.device_type IS NOT NULL
         )
         WHERE mappings.mac IS NOT NULL
           AND mappings.device_type IS NULL
           AND EXISTS (
               SELECT 1 FROM dhcp_observations o
               WHERE o.mac = mappings.mac AND o.device_type IS NOT NULL
           )",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
