//! LDAP/AD group synchronization task.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use sqlx::Row;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{info, warn};
use trueid_common::db::Db;

/// LDAP sync configuration loaded from database.
#[derive(Clone, Debug)]
struct LdapSyncConfig {
    ldap_url: String,
    bind_dn: String,
    bind_password: String,
    base_dn: String,
    search_filter: String,
    sync_interval_secs: i64,
    enabled: bool,
}

/// Extracts CN value from a Distinguished Name.
///
/// Parameters: `dn` - LDAP distinguished name.
/// Returns: optional CN value.
fn extract_cn(dn: &str) -> Option<String> {
    dn.split(',')
        .find_map(|part| part.trim().strip_prefix("CN=").map(|v| v.trim().to_string()))
        .filter(|v| !v.is_empty())
}

/// Loads LDAP sync configuration from database.
///
/// Parameters: `db` - shared database handle.
/// Returns: optional LDAP sync config.
async fn load_config(db: &Db) -> Result<Option<LdapSyncConfig>> {
    let row = sqlx::query(
        "SELECT ldap_url, bind_dn, bind_password_enc, base_dn, search_filter, sync_interval_secs, enabled
         FROM ldap_config
         WHERE id = 1",
    )
    .fetch_optional(db.pool())
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let enabled: bool = row.try_get("enabled").unwrap_or(false);
    let bind_password_enc: Option<String> = row.try_get("bind_password_enc").ok();
    let bind_password = match bind_password_enc {
        Some(v) if !v.is_empty() => db.decrypt_config_value(&v)?,
        _ => String::new(),
    };

    Ok(Some(LdapSyncConfig {
        ldap_url: row.try_get("ldap_url").unwrap_or_default(),
        bind_dn: row.try_get("bind_dn").unwrap_or_default(),
        bind_password,
        base_dn: row.try_get("base_dn").unwrap_or_default(),
        search_filter: row
            .try_get("search_filter")
            .unwrap_or_else(|_| "(&(objectClass=user)(sAMAccountName=*))".to_string()),
        sync_interval_secs: row.try_get("sync_interval_secs").unwrap_or(300).max(60),
        enabled,
    }))
}

/// Updates LDAP sync status metadata.
///
/// Parameters: `pool` - SQLite pool, `status` - sync status, `count` - synced users, `error` - optional error message.
/// Returns: update result.
async fn update_sync_status(
    pool: &sqlx::SqlitePool,
    status: &str,
    count: i64,
    error: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE ldap_config
         SET last_sync_at = datetime('now'),
             last_sync_status = ?,
             last_sync_count = ?,
             last_sync_error = ?,
             updated_at = datetime('now')
         WHERE id = 1",
    )
    .bind(status)
    .bind(count)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

/// Runs one LDAP sync cycle and upserts user group memberships.
///
/// Parameters: `pool` - SQLite pool, `config` - loaded LDAP config.
/// Returns: number of synced users.
async fn sync_once(pool: &sqlx::SqlitePool, config: &LdapSyncConfig) -> Result<u32> {
    if config.bind_password.is_empty() {
        return Err(anyhow!("LDAP bind password is not configured"));
    }
    let (conn, mut ldap) = LdapConnAsync::new(&config.ldap_url).await?;
    ldap3::drive!(conn);

    ldap.simple_bind(&config.bind_dn, &config.bind_password)
        .await?
        .success()?;

    let attrs = vec!["sAMAccountName", "memberOf", "displayName", "department"];
    let (entries, _res) = ldap
        .search(&config.base_dn, Scope::Subtree, &config.search_filter, attrs)
        .await?
        .success()?;

    let sync_mark: DateTime<Utc> = Utc::now();
    let mut users_synced: u32 = 0;

    for entry in entries {
        let se = SearchEntry::construct(entry);
        let username = se
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let Some(username) = username else {
            continue;
        };
        users_synced = users_synced.saturating_add(1);

        let display_name = se
            .attrs
            .get("displayName")
            .and_then(|v| v.first())
            .map(|v| v.to_string());
        let department = se
            .attrs
            .get("department")
            .and_then(|v| v.first())
            .map(|v| v.to_string());
        let groups = se
            .attrs
            .get("memberOf")
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|dn| extract_cn(&dn))
            .collect::<Vec<_>>();

        for group_name in groups {
            sqlx::query(
                "INSERT INTO user_groups (username, group_name, display_name, department, synced_at)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(username, group_name) DO UPDATE SET
                     display_name = excluded.display_name,
                     department = excluded.department,
                     synced_at = excluded.synced_at",
            )
            .bind(&username)
            .bind(&group_name)
            .bind(&display_name)
            .bind(&department)
            .bind(sync_mark)
            .execute(pool)
            .await?;
        }
    }

    sqlx::query("DELETE FROM user_groups WHERE synced_at < ?")
        .bind(sync_mark)
        .execute(pool)
        .await?;
    let _ = ldap.unbind().await;
    Ok(users_synced)
}

/// Forces an immediate LDAP sync cycle.
///
/// Parameters: `db` - shared database handle.
/// Returns: number of synced users.
pub async fn force_sync_once(db: Arc<Db>) -> Result<u32> {
    let config = load_config(&db)
        .await?
        .ok_or_else(|| anyhow!("LDAP config row not found"))?;
    if !config.enabled {
        return Err(anyhow!("LDAP sync is disabled"));
    }
    let count = sync_once(db.pool(), &config).await?;
    update_sync_status(db.pool(), "ok", i64::from(count), None).await?;
    Ok(count)
}

/// Runs background LDAP sync loop with periodic config reload.
///
/// Parameters: `db` - shared database handle.
/// Returns: none.
pub async fn run_ldap_sync(db: Arc<Db>) {
    let mut last_sync: Option<Instant> = None;
    loop {
        let cfg = match load_config(&db).await {
            Ok(Some(cfg)) => cfg,
            Ok(None) => {
                sleep(Duration::from_secs(60)).await;
                continue;
            }
            Err(e) => {
                warn!(error = %e, "Failed to load LDAP config");
                sleep(Duration::from_secs(60)).await;
                continue;
            }
        };

        if !cfg.enabled {
            sleep(Duration::from_secs(60)).await;
            continue;
        }

        let due = match last_sync {
            None => true,
            Some(ts) => ts.elapsed().as_secs() >= cfg.sync_interval_secs as u64,
        };
        if !due {
            sleep(Duration::from_secs(60)).await;
            continue;
        }

        match sync_once(db.pool(), &cfg).await {
            Ok(count) => {
                last_sync = Some(Instant::now());
                let _ = update_sync_status(db.pool(), "ok", i64::from(count), None).await;
                info!(synced_users = count, "LDAP sync completed");
            }
            Err(e) => {
                let msg = e.to_string();
                let _ = update_sync_status(db.pool(), "error", 0, Some(&msg)).await;
                warn!(error = %msg, "LDAP sync failed");
                sleep(Duration::from_secs(60)).await;
            }
        }
    }
}
