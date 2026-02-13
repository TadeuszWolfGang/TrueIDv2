//! Background DNS reverse (PTR) resolver and cache updater.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tracing::{info, warn};
use trueid_common::db::Db;

const MAX_IPS_PER_CYCLE: i64 = 50;
const MAX_CONCURRENCY: usize = 10;

/// DNS cache entry loaded from DB for decision making.
struct DnsCacheEntry {
    ip: String,
    hostname: Option<String>,
    expires_at: Option<DateTime<Utc>>,
}

/// Result of a single reverse lookup attempt.
struct ResolveResult {
    ip: String,
    hostname: Option<String>,
    error: Option<String>,
}

/// Statistics produced by one resolver cycle.
struct CycleStats {
    resolved: usize,
    failed: usize,
    skipped: usize,
    changed: usize,
}

/// Starts background DNS resolver loop with periodic cycles.
///
/// Parameters: `db` - shared database handle.
/// Returns: nothing; spawns detached Tokio task.
pub fn start_dns_resolver(db: Arc<Db>) {
    tokio::spawn(async move {
        // Warm-up delay to avoid DNS burst right after process startup.
        tokio::time::sleep(Duration::from_secs(30)).await;

        loop {
            let interval_secs = db.get_config_i64("dns_resolve_interval_secs", 300).await;
            let ttl_secs = db.get_config_i64("dns_cache_ttl_secs", 3600).await;

            match resolve_cycle(db.pool(), ttl_secs).await {
                Ok(stats) => {
                    if stats.resolved > 0 || stats.failed > 0 || stats.changed > 0 {
                        info!(
                            resolved = stats.resolved,
                            failed = stats.failed,
                            skipped = stats.skipped,
                            changed = stats.changed,
                            "DNS resolver cycle complete"
                        );
                    }
                }
                Err(e) => warn!(error = %e, "DNS resolver cycle failed"),
            }

            tokio::time::sleep(Duration::from_secs(interval_secs.max(1) as u64)).await;
        }
    });
}

/// Executes one DNS resolve cycle for active mapping IPs.
///
/// Parameters: `pool` - SQLite pool, `ttl_secs` - DNS cache TTL in seconds.
/// Returns: cycle statistics.
async fn resolve_cycle(pool: &SqlitePool, ttl_secs: i64) -> Result<CycleStats> {
    let rows = sqlx::query(
        "SELECT m.ip
         FROM mappings m
         LEFT JOIN dns_cache d ON m.ip = d.ip
         WHERE m.is_active = true
           AND (d.ip IS NULL OR d.expires_at < datetime('now'))
         LIMIT ?",
    )
    .bind(MAX_IPS_PER_CYCLE)
    .fetch_all(pool)
    .await?;

    let mut pending = Vec::with_capacity(rows.len());
    for row in rows {
        let ip: String = row.try_get("ip")?;
        pending.push(ip);
    }

    if pending.is_empty() {
        return Ok(CycleStats {
            resolved: 0,
            failed: 0,
            skipped: 0,
            changed: 0,
        });
    }

    let snapshot = load_cache_entries(pool, &pending).await?;
    let now = Utc::now();
    let mut to_resolve = Vec::with_capacity(pending.len());
    let mut skipped = 0usize;

    for ip in pending {
        if let Some(entry) = snapshot.iter().find(|e| e.ip == ip) {
            let _cached_hostname = entry.hostname.as_deref();
            if let Some(expires_at) = entry.expires_at {
                if expires_at > now {
                    skipped += 1;
                    continue;
                }
            }
            // Expired or missing expiry should re-resolve.
        }
        to_resolve.push(ip);
    }

    if to_resolve.is_empty() {
        return Ok(CycleStats {
            resolved: 0,
            failed: 0,
            skipped,
            changed: 0,
        });
    }

    let results = resolve_batch(to_resolve).await;
    let mut resolved = 0usize;
    let mut failed = 0usize;
    let mut changed = 0usize;

    for result in results {
        if result.hostname.is_some() {
            resolved += 1;
        } else {
            failed += 1;
        }
        if upsert_dns_result(pool, &result, ttl_secs).await? {
            changed += 1;
        }
    }

    Ok(CycleStats {
        resolved,
        failed,
        skipped,
        changed,
    })
}

/// Loads DNS cache entries for candidate IPs.
///
/// Parameters: `pool` - SQLite pool, `ips` - IP list for lookup.
/// Returns: existing cache entries for provided IPs.
async fn load_cache_entries(pool: &SqlitePool, ips: &[String]) -> Result<Vec<DnsCacheEntry>> {
    let mut out = Vec::new();
    for ip in ips {
        let row = sqlx::query("SELECT ip, hostname, expires_at FROM dns_cache WHERE ip = ?")
            .bind(ip)
            .fetch_optional(pool)
            .await?;
        if let Some(row) = row {
            out.push(DnsCacheEntry {
                ip: row.try_get("ip")?,
                hostname: row.try_get("hostname").ok(),
                expires_at: row.try_get("expires_at").ok(),
            });
        }
    }
    Ok(out)
}

/// Resolves one IP address with timeout and captures resolver errors.
///
/// Parameters: `ip_str` - IP address string.
/// Returns: normalized resolve result.
async fn resolve_one(ip_str: &str) -> ResolveResult {
    let _addr: std::net::IpAddr = match ip_str.parse() {
        Ok(a) => a,
        Err(_) => {
            return ResolveResult {
                ip: ip_str.to_string(),
                hostname: None,
                error: Some("invalid IP".into()),
            };
        }
    };

    match tokio::time::timeout(Duration::from_secs(3), reverse_lookup(ip_str)).await {
        Ok(Ok(hostname)) => ResolveResult {
            ip: ip_str.to_string(),
            hostname: Some(hostname),
            error: None,
        },
        Ok(Err(e)) => ResolveResult {
            ip: ip_str.to_string(),
            hostname: None,
            error: Some(e),
        },
        Err(_) => ResolveResult {
            ip: ip_str.to_string(),
            hostname: None,
            error: Some("timeout (3s)".into()),
        },
    }
}

/// Performs reverse lookup using system resolver command.
///
/// Parameters: `ip_str` - IP address string.
/// Returns: resolved hostname or error message.
async fn reverse_lookup(ip_str: &str) -> std::result::Result<String, String> {
    let output = tokio::process::Command::new("nslookup")
        .arg(ip_str)
        .output()
        .await
        .map_err(|e| format!("nslookup failed: {e}"))?;

    if !output.status.success() {
        return Err(format!("nslookup exit status: {}", output.status));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_nslookup_hostname(&stdout).ok_or_else(|| "PTR record not found".to_string())
}

/// Extracts hostname from nslookup output.
///
/// Parameters: `stdout` - raw command output.
/// Returns: parsed hostname without trailing dot.
fn parse_nslookup_hostname(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        if let Some((_, rhs)) = line.split_once("name =") {
            let host = rhs.trim().trim_end_matches('.').to_string();
            if !host.is_empty() {
                return Some(host);
            }
        }
        if line.starts_with("Name:") {
            let host = line.trim_start_matches("Name:").trim().to_string();
            if !host.is_empty() {
                return Some(host.trim_end_matches('.').to_string());
            }
        }
    }
    None
}

/// Resolves a batch of IPs with bounded parallelism.
///
/// Parameters: `ips` - IP list.
/// Returns: lookup results for all submitted IPs.
async fn resolve_batch(ips: Vec<String>) -> Vec<ResolveResult> {
    let mut set = JoinSet::new();
    let mut iter = ips.into_iter();
    let mut active = 0usize;
    let mut results = Vec::new();

    while active < MAX_CONCURRENCY {
        if let Some(ip) = iter.next() {
            set.spawn(async move { resolve_one(&ip).await });
            active += 1;
        } else {
            break;
        }
    }

    while active > 0 {
        if let Some(joined) = set.join_next().await {
            active -= 1;
            if let Ok(result) = joined {
                results.push(result);
            }
            if let Some(ip) = iter.next() {
                set.spawn(async move { resolve_one(&ip).await });
                active += 1;
            }
        }
    }

    results
}

/// Upserts DNS resolve result and tracks hostname changes.
///
/// Parameters: `pool` - SQLite pool, `result` - lookup result, `ttl_secs` - cache TTL in seconds.
/// Returns: `true` when hostname changed from previous value.
async fn upsert_dns_result(
    pool: &SqlitePool,
    result: &ResolveResult,
    ttl_secs: i64,
) -> Result<bool> {
    let now = Utc::now();
    let expires = now + chrono::Duration::seconds(ttl_secs.max(1));

    let existing_hostname: Option<String> =
        sqlx::query_scalar("SELECT hostname FROM dns_cache WHERE ip = ?")
            .bind(&result.ip)
            .fetch_optional(pool)
            .await?
            .flatten();

    let changed = match (&existing_hostname, &result.hostname) {
        (Some(old), Some(new)) if old != new => true,
        (Some(_), None) => false,
        (None, Some(_)) => false,
        _ => false,
    };

    if changed {
        sqlx::query(
            "INSERT INTO dns_cache (ip, hostname, previous_hostname, resolved_at, expires_at, last_error, resolve_count)
             VALUES (?, ?, ?, ?, ?, ?, 1)
             ON CONFLICT(ip) DO UPDATE SET
                hostname = excluded.hostname,
                previous_hostname = dns_cache.hostname,
                resolved_at = excluded.resolved_at,
                expires_at = excluded.expires_at,
                last_error = excluded.last_error,
                resolve_count = dns_cache.resolve_count + 1",
        )
        .bind(&result.ip)
        .bind(&result.hostname)
        .bind(existing_hostname.clone())
        .bind(now)
        .bind(expires)
        .bind(&result.error)
        .execute(pool)
        .await?;

        info!(
            ip = %result.ip,
            old_hostname = ?existing_hostname,
            new_hostname = ?result.hostname,
            "DNS PTR change detected"
        );
    } else {
        sqlx::query(
            "INSERT INTO dns_cache (ip, hostname, resolved_at, expires_at, last_error, resolve_count)
             VALUES (?, ?, ?, ?, ?, 1)
             ON CONFLICT(ip) DO UPDATE SET
                hostname = excluded.hostname,
                resolved_at = excluded.resolved_at,
                expires_at = excluded.expires_at,
                last_error = excluded.last_error,
                resolve_count = dns_cache.resolve_count + 1",
        )
        .bind(&result.ip)
        .bind(&result.hostname)
        .bind(now)
        .bind(expires)
        .bind(&result.error)
        .execute(pool)
        .await?;
    }

    Ok(changed)
}
