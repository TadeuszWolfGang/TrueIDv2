//! Background DNS reverse (PTR) resolver and cache updater.

use anyhow::Result;
use chrono::{DateTime, Utc};
use hickory_resolver::{Resolver, TokioResolver};
use once_cell::sync::OnceCell;
use sqlx::{Row, SqlitePool};
use std::iter::repeat_n;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tracing::{info, warn};
use trueid_common::db::Db;

const MAX_IPS_PER_CYCLE: i64 = 50;
const MAX_CONCURRENCY: usize = 10;
static DNS_RESOLVER: OnceCell<TokioResolver> = OnceCell::new();

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
    if ips.is_empty() {
        return Ok(Vec::new());
    }

    let placeholders = repeat_n("?", ips.len()).collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT ip, hostname, expires_at
         FROM dns_cache
         WHERE ip IN ({placeholders})"
    );

    let mut query = sqlx::query(&sql);
    for ip in ips {
        query = query.bind(ip);
    }

    let rows = query.fetch_all(pool).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(DnsCacheEntry {
            ip: row.try_get("ip")?,
            hostname: row.try_get::<Option<String>, _>("hostname").unwrap_or(None),
            expires_at: row
                .try_get::<Option<DateTime<Utc>>, _>("expires_at")
                .unwrap_or(None),
        });
    }
    Ok(out)
}

/// Resolves one IP address with timeout and captures resolver errors.
///
/// Parameters: `ip_str` - IP address string.
/// Returns: normalized resolve result.
async fn resolve_one(ip_str: &str) -> ResolveResult {
    let addr: IpAddr = match ip_str.parse() {
        Ok(a) => a,
        Err(_) => {
            return ResolveResult {
                ip: ip_str.to_string(),
                hostname: None,
                error: Some("invalid IP".into()),
            };
        }
    };

    match tokio::time::timeout(Duration::from_secs(3), reverse_lookup(addr)).await {
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

/// Builds or returns the shared Hickory resolver with system DNS configuration.
///
/// Returns: shared resolver or initialization error.
fn dns_resolver() -> std::result::Result<&'static TokioResolver, String> {
    DNS_RESOLVER.get_or_try_init(|| {
        Resolver::builder_tokio()
            .map_err(|e| format!("failed to load system DNS config: {e}"))
            .map(|builder| builder.build())
    })
}

/// Performs reverse lookup using the in-process Hickory resolver.
///
/// Parameters: `addr` - IP address.
/// Returns: normalized hostname or error message.
async fn reverse_lookup(addr: IpAddr) -> std::result::Result<String, String> {
    let resolver = dns_resolver()?;
    let lookup = resolver
        .reverse_lookup(addr)
        .await
        .map_err(|e| format!("reverse lookup failed: {e}"))?;

    lookup
        .iter()
        .find_map(|name| normalize_ptr_hostname(&name.to_utf8()))
        .ok_or_else(|| "PTR record not found".to_string())
}

/// Normalizes and validates PTR hostname before storing it in cache.
///
/// Parameters: `raw` - hostname returned by DNS library.
/// Returns: normalized hostname without trailing dot.
fn normalize_ptr_hostname(raw: &str) -> Option<String> {
    let hostname = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty() || hostname.len() > 253 {
        return None;
    }

    let all_labels_valid = hostname.split('.').all(is_valid_hostname_label);
    if !all_labels_valid {
        return None;
    }

    Some(hostname)
}

/// Checks whether one DNS label is structurally safe to expose in API/UI.
///
/// Parameters: `label` - one hostname label.
/// Returns: `true` when label length and characters are acceptable.
fn is_valid_hostname_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }

    let bytes = label.as_bytes();
    if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
        return false;
    }

    label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
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

    let existing_row =
        sqlx::query("SELECT hostname, previous_hostname FROM dns_cache WHERE ip = ?")
            .bind(&result.ip)
            .fetch_optional(pool)
            .await?;
    let existing_hostname = existing_row
        .as_ref()
        .and_then(|row| row.try_get::<Option<String>, _>("hostname").ok().flatten());
    let existing_previous_hostname = existing_row.as_ref().and_then(|row| {
        row.try_get::<Option<String>, _>("previous_hostname")
            .ok()
            .flatten()
    });

    let changed = match (&existing_hostname, &result.hostname) {
        (Some(old), Some(new)) if old != new => true,
        (Some(_), None) => true,
        (None, Some(_)) => false,
        _ => false,
    };

    let next_previous_hostname = if changed {
        existing_hostname.clone()
    } else {
        match (&existing_hostname, &result.hostname) {
            (None, Some(_)) => None,
            _ => existing_previous_hostname,
        }
    };

    sqlx::query(
        "INSERT INTO dns_cache (ip, hostname, previous_hostname, resolved_at, expires_at, last_error, resolve_count)
         VALUES (?, ?, ?, ?, ?, ?, 1)
         ON CONFLICT(ip) DO UPDATE SET
            hostname = excluded.hostname,
            previous_hostname = excluded.previous_hostname,
            resolved_at = excluded.resolved_at,
            expires_at = excluded.expires_at,
            last_error = excluded.last_error,
            resolve_count = dns_cache.resolve_count + 1",
    )
    .bind(&result.ip)
    .bind(&result.hostname)
    .bind(next_previous_hostname)
    .bind(now)
    .bind(expires)
    .bind(&result.error)
    .execute(pool)
    .await?;

    if changed {
        info!(
            ip = %result.ip,
            old_hostname = ?existing_hostname,
            new_hostname = ?result.hostname,
            "DNS PTR change detected"
        );
    }

    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_ptr_hostname_accepts_fqdn_and_lowercases_it() {
        assert_eq!(
            normalize_ptr_hostname("Host-01.Example.LOCAL."),
            Some("host-01.example.local".to_string())
        );
    }

    #[test]
    fn normalize_ptr_hostname_rejects_invalid_labels() {
        assert_eq!(normalize_ptr_hostname("bad host.local"), None);
        assert_eq!(normalize_ptr_hostname("-edge.local"), None);
        assert_eq!(normalize_ptr_hostname(""), None);
    }

    #[tokio::test]
    async fn resolve_one_rejects_invalid_ip() {
        let result = resolve_one("not-an-ip").await;
        assert_eq!(result.ip, "not-an-ip");
        assert_eq!(result.hostname, None);
        assert_eq!(result.error.as_deref(), Some("invalid IP"));
    }

    #[tokio::test]
    async fn upsert_dns_result_tracks_hostname_change() {
        let db = trueid_common::db::init_db("sqlite::memory:")
            .await
            .expect("init db failed");
        let first = ResolveResult {
            ip: "10.0.0.10".to_string(),
            hostname: Some("host-a.example.local".to_string()),
            error: None,
        };
        let second = ResolveResult {
            ip: "10.0.0.10".to_string(),
            hostname: Some("host-b.example.local".to_string()),
            error: None,
        };

        assert!(!upsert_dns_result(db.pool(), &first, 300)
            .await
            .expect("first upsert failed"));
        assert!(upsert_dns_result(db.pool(), &second, 300)
            .await
            .expect("second upsert failed"));

        let row = sqlx::query(
            "SELECT hostname, previous_hostname, resolve_count FROM dns_cache WHERE ip = ?",
        )
        .bind("10.0.0.10")
        .fetch_one(db.pool())
        .await
        .expect("select failed");

        let hostname: Option<String> = row.try_get("hostname").expect("hostname missing");
        let previous: Option<String> = row
            .try_get("previous_hostname")
            .expect("previous hostname missing");
        let resolve_count: i64 = row.try_get("resolve_count").expect("resolve_count missing");

        assert_eq!(hostname.as_deref(), Some("host-b.example.local"));
        assert_eq!(previous.as_deref(), Some("host-a.example.local"));
        assert_eq!(resolve_count, 2);
    }

    #[tokio::test]
    async fn upsert_dns_result_tracks_hostname_loss_and_recovery() {
        let db = trueid_common::db::init_db("sqlite::memory:")
            .await
            .expect("init db failed");
        let first = ResolveResult {
            ip: "10.0.0.11".to_string(),
            hostname: Some("host-a.example.local".to_string()),
            error: None,
        };
        let lost = ResolveResult {
            ip: "10.0.0.11".to_string(),
            hostname: None,
            error: Some("PTR record not found".to_string()),
        };
        let recovered = ResolveResult {
            ip: "10.0.0.11".to_string(),
            hostname: Some("host-b.example.local".to_string()),
            error: None,
        };

        assert!(!upsert_dns_result(db.pool(), &first, 300)
            .await
            .expect("first upsert failed"));
        assert!(upsert_dns_result(db.pool(), &lost, 300)
            .await
            .expect("loss upsert failed"));
        assert!(!upsert_dns_result(db.pool(), &recovered, 300)
            .await
            .expect("recovery upsert failed"));

        let row = sqlx::query(
            "SELECT hostname, previous_hostname, resolve_count FROM dns_cache WHERE ip = ?",
        )
        .bind("10.0.0.11")
        .fetch_one(db.pool())
        .await
        .expect("select failed");

        let hostname: Option<String> = row.try_get("hostname").expect("hostname missing");
        let previous: Option<String> = row
            .try_get("previous_hostname")
            .expect("previous hostname missing");
        let resolve_count: i64 = row.try_get("resolve_count").expect("resolve_count missing");

        assert_eq!(hostname.as_deref(), Some("host-b.example.local"));
        assert_eq!(previous, None);
        assert_eq!(resolve_count, 3);
    }

    #[tokio::test]
    async fn resolve_cycle_ignores_fresh_cache_entries() {
        let db = trueid_common::db::init_db("sqlite::memory:")
            .await
            .expect("init db failed");
        let event = trueid_common::model::IdentityEvent {
            source: trueid_common::model::SourceType::Radius,
            ip: "10.0.0.12".parse().expect("ip parse failed"),
            user: "dns-cache-user".to_string(),
            timestamp: Utc::now(),
            raw_data: "dns cache warm entry".to_string(),
            mac: Some("AA:BB:CC:DD:EE:42".to_string()),
            confidence_score: 90,
        };
        db.upsert_mapping(event, Some("TestVendor"))
            .await
            .expect("upsert mapping failed");
        sqlx::query(
            "INSERT INTO dns_cache (ip, hostname, resolved_at, expires_at, resolve_count)
             VALUES (?, ?, datetime('now'), datetime('now', '+1 hour'), 1)",
        )
        .bind("10.0.0.12")
        .bind("cached.example.local")
        .execute(db.pool())
        .await
        .expect("insert dns cache failed");

        let stats = resolve_cycle(db.pool(), 300)
            .await
            .expect("resolve cycle failed");

        assert_eq!(stats.resolved, 0);
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.skipped, 0);
        assert_eq!(stats.changed, 0);

        let row = sqlx::query("SELECT hostname, resolve_count FROM dns_cache WHERE ip = ?")
            .bind("10.0.0.12")
            .fetch_one(db.pool())
            .await
            .expect("select dns cache failed");
        let hostname: Option<String> = row.try_get("hostname").expect("hostname missing");
        let resolve_count: i64 = row.try_get("resolve_count").expect("resolve_count missing");

        assert_eq!(hostname.as_deref(), Some("cached.example.local"));
        assert_eq!(resolve_count, 1);
    }
}
