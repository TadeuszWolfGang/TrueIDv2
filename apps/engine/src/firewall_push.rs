//! Firewall User-ID push loop (PAN-OS and FortiGate).

use anyhow::{anyhow, Context, Result};
use reqwest::StatusCode;
use sqlx::Row;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};
use trueid_common::db::Db;

/// Firewall vendor type for dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallType {
    PanOs,
    FortiGate,
}

/// Mapping entry to push to firewall.
#[derive(Clone, Debug)]
pub struct PushEntry {
    pub ip: String,
    pub user: String,
    pub timeout_secs: u32,
}

/// In-memory representation of a firewall target (decrypted credentials).
#[derive(Clone, Debug)]
pub struct FirewallTarget {
    pub id: i64,
    pub name: String,
    pub firewall_type: FirewallType,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub verify_tls: bool,
    pub enabled: bool,
    pub push_interval_secs: u64,
    pub subnet_filter: Option<Vec<i64>>,
}

/// Global firewall push shutdown flag.
static FIREWALL_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Sets shutdown state for firewall manager and loops.
///
/// Parameters: `value` - shutdown flag state.
/// Returns: nothing.
pub fn set_shutdown(value: bool) {
    FIREWALL_SHUTDOWN.store(value, Ordering::SeqCst);
}

/// Returns global PAN-OS API key cache (target_id -> key).
fn panos_key_cache() -> &'static RwLock<HashMap<i64, String>> {
    static CACHE: OnceLock<RwLock<HashMap<i64, String>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Parses firewall type string.
///
/// Parameters: `raw` - database value.
/// Returns: parsed enum or error for unsupported values.
fn parse_firewall_type(raw: &str) -> Result<FirewallType> {
    match raw {
        "panos" => Ok(FirewallType::PanOs),
        "fortigate" => Ok(FirewallType::FortiGate),
        other => Err(anyhow!("unsupported firewall_type: {other}")),
    }
}

/// Parses optional comma-separated subnet filter ids.
///
/// Parameters: `raw` - optional CSV subnet id list.
/// Returns: parsed id list or None for missing/empty filter.
fn parse_subnet_filter(raw: Option<String>) -> Option<Vec<i64>> {
    let value = raw?;
    let ids = value
        .split(',')
        .filter_map(|s| s.trim().parse::<i64>().ok())
        .collect::<Vec<_>>();
    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

/// Loads a single firewall target by id and decrypts credentials.
///
/// Parameters: `db` - database handle, `target_id` - target identifier.
/// Returns: target configuration when present.
async fn load_target(db: &Db, target_id: i64) -> Result<Option<FirewallTarget>> {
    let row = sqlx::query(
        "SELECT id, name, firewall_type, host, port, username, password_enc,
                verify_tls, enabled, push_interval_secs, subnet_filter
         FROM firewall_targets
         WHERE id = ?",
    )
    .bind(target_id)
    .fetch_optional(db.pool())
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let firewall_type_raw: String = row.try_get("firewall_type")?;
    let firewall_type = parse_firewall_type(&firewall_type_raw)?;
    let password_enc: Option<String> = row.try_get("password_enc").ok();
    let password = match password_enc {
        Some(v) if !v.is_empty() => Some(db.decrypt_config_value(&v)?),
        _ => None,
    };
    let port_i64: i64 = row.try_get("port").unwrap_or(443);
    let port = u16::try_from(port_i64).unwrap_or(443);
    let interval_i64: i64 = row.try_get("push_interval_secs").unwrap_or(60);
    let push_interval_secs = u64::try_from(interval_i64.max(10)).unwrap_or(60);

    Ok(Some(FirewallTarget {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        firewall_type,
        host: row.try_get("host")?,
        port,
        username: row.try_get("username").ok(),
        password,
        verify_tls: row.try_get("verify_tls").unwrap_or(false),
        enabled: row.try_get("enabled").unwrap_or(false),
        push_interval_secs,
        subnet_filter: parse_subnet_filter(row.try_get("subnet_filter").ok()),
    }))
}

/// Loads all enabled firewall target ids.
///
/// Parameters: `db` - database handle.
/// Returns: enabled target id list.
async fn load_enabled_target_ids(db: &Db) -> Result<Vec<i64>> {
    let rows = sqlx::query("SELECT id FROM firewall_targets WHERE enabled = 1 ORDER BY id ASC")
        .fetch_all(db.pool())
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| r.try_get::<i64, _>("id").ok())
        .collect())
}

/// Builds an HTTP client honoring TLS verification setting.
///
/// Parameters: `verify_tls` - true enables certificate verification.
/// Returns: configured reqwest client.
fn build_client(verify_tls: bool) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(!verify_tls)
        .timeout(Duration::from_secs(15))
        .build()
        .context("failed to build firewall HTTP client")
}

/// Loads active mappings and expands to push entries.
///
/// Parameters: `db` - database handle, `target` - target config with optional subnet filter.
/// Returns: deduplicated push entries.
async fn load_push_entries(db: &Db, target: &FirewallTarget) -> Result<Vec<PushEntry>> {
    let rows = sqlx::query(
        "SELECT m.ip,
                COALESCE(sess.user, m.user) as user,
                m.subnet_id
         FROM mappings m
         LEFT JOIN ip_sessions sess
           ON sess.ip = m.ip AND sess.is_active = 1
         WHERE m.is_active = 1",
    )
    .fetch_all(db.pool())
    .await?;

    let allowed_subnets = target.subnet_filter.clone();
    let mut seen = HashSet::<(String, String)>::new();
    let mut entries = Vec::new();
    for row in rows {
        let subnet_id: Option<i64> = row.try_get("subnet_id").ok();
        if let Some(ref filter) = allowed_subnets {
            let Some(id) = subnet_id else {
                continue;
            };
            if !filter.contains(&id) {
                continue;
            }
        }
        let ip: String = row.try_get("ip").unwrap_or_default();
        let user: String = row.try_get("user").unwrap_or_default();
        if ip.is_empty() || user.is_empty() {
            continue;
        }
        if !seen.insert((ip.clone(), user.clone())) {
            continue;
        }
        entries.push(PushEntry {
            ip,
            user,
            timeout_secs: (target.push_interval_secs.saturating_mul(2)) as u32,
        });
    }
    Ok(entries)
}

/// Requests PAN-OS API key via keygen endpoint.
///
/// Parameters: `client` - HTTP client, `host` - firewall host, `port` - firewall port, `username` - admin user, `password` - admin password.
/// Returns: API key string.
async fn panos_keygen(
    client: &reqwest::Client,
    host: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<String> {
    let url = format!("https://{host}:{port}/api/");
    let resp = client
        .post(url)
        .query(&[
            ("type", "keygen"),
            ("user", username),
            ("password", password),
        ])
        .send()
        .await?;
    let body = resp.text().await?;
    if !body.contains("status=\"success\"") {
        return Err(anyhow!("PAN-OS keygen failed"));
    }
    let start = body
        .find("<key>")
        .ok_or_else(|| anyhow!("PAN-OS keygen response missing <key>"))?;
    let end = body
        .find("</key>")
        .ok_or_else(|| anyhow!("PAN-OS keygen response missing </key>"))?;
    if end <= start + 5 {
        return Err(anyhow!("PAN-OS keygen key is empty"));
    }
    Ok(body[start + 5..end].to_string())
}

/// Builds PAN-OS XML payload for one chunk of entries.
///
/// Parameters: `entries` - chunk entries.
/// Returns: XML payload string.
fn panos_xml_payload(entries: &[PushEntry]) -> String {
    let mut body =
        String::from("<uid-message><version>2.0</version><type>update</type><payload><login>");
    for entry in entries {
        body.push_str(&format!(
            "<entry name=\"{}\" ip=\"{}\" timeout=\"{}\"/>",
            entry.user, entry.ip, entry.timeout_secs
        ));
    }
    body.push_str("</login></payload></uid-message>");
    body
}

/// Sends one PAN-OS user-id chunk.
///
/// Parameters: `client` - HTTP client, `target` - firewall config, `api_key` - keygen token, `chunk` - entries to send.
/// Returns: success or request error.
async fn push_panos_chunk(
    client: &reqwest::Client,
    target: &FirewallTarget,
    api_key: &str,
    chunk: &[PushEntry],
) -> Result<()> {
    let url = format!("https://{}:{}/api/", target.host, target.port);
    let cmd = panos_xml_payload(chunk);
    let resp = client
        .post(url)
        .query(&[("type", "user-id"), ("action", "set"), ("key", api_key)])
        .form(&[("cmd", cmd)])
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return Err(anyhow!("PAN-OS auth failure"));
    }
    if !status.is_success() || !body.contains("status=\"success\"") {
        return Err(anyhow!("PAN-OS push failed"));
    }
    Ok(())
}

/// Pushes mappings to PAN-OS in chunks of 1000.
///
/// Parameters: `client` - HTTP client, `target` - target config, `entries` - mappings to push.
/// Returns: number of pushed mappings.
async fn push_panos(
    client: &reqwest::Client,
    target: &FirewallTarget,
    entries: &[PushEntry],
) -> Result<u32> {
    let username = target
        .username
        .as_deref()
        .ok_or_else(|| anyhow!("PAN-OS username is required"))?;
    let password = target
        .password
        .as_deref()
        .ok_or_else(|| anyhow!("PAN-OS password is required"))?;

    let mut key = {
        let cache = panos_key_cache().read().await;
        cache.get(&target.id).cloned()
    };
    if key.is_none() {
        let new_key = panos_keygen(client, &target.host, target.port, username, password).await?;
        panos_key_cache()
            .write()
            .await
            .insert(target.id, new_key.clone());
        key = Some(new_key);
    }
    let mut api_key = key.expect("key must be set");

    let mut pushed = 0u32;
    for chunk in entries.chunks(1000) {
        let first_try = push_panos_chunk(client, target, &api_key, chunk).await;
        if first_try.is_err() {
            panos_key_cache().write().await.remove(&target.id);
            api_key = panos_keygen(client, &target.host, target.port, username, password).await?;
            panos_key_cache()
                .write()
                .await
                .insert(target.id, api_key.clone());
            push_panos_chunk(client, target, &api_key, chunk).await?;
        }
        pushed = pushed.saturating_add(chunk.len() as u32);
    }

    Ok(pushed)
}

/// Pushes mappings to FortiGate FSSO endpoint sequentially.
///
/// Parameters: `client` - HTTP client, `target` - target config, `entries` - mappings to push.
/// Returns: number of pushed mappings.
async fn push_fortigate(
    client: &reqwest::Client,
    target: &FirewallTarget,
    entries: &[PushEntry],
) -> Result<u32> {
    let token = target
        .password
        .as_deref()
        .ok_or_else(|| anyhow!("FortiGate API token is required"))?;
    let url = format!(
        "https://{}:{}/api/v2/monitor/user/firewall/login",
        target.host, target.port
    );

    let mut pushed = 0u32;
    for entry in entries {
        let resp = client
            .post(&url)
            .bearer_auth(token)
            .json(&serde_json::json!({
                "ip_address": entry.ip,
                "username": entry.user,
                "server": "TrueID"
            }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("FortiGate push failed"));
        }
        pushed = pushed.saturating_add(1);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(pushed)
}

/// Pushes mappings to a target based on firewall type.
///
/// Parameters: `client` - HTTP client, `target` - target config, `entries` - mappings to push.
/// Returns: number of pushed mappings.
pub async fn push_to_target(
    client: &reqwest::Client,
    target: &FirewallTarget,
    entries: &[PushEntry],
) -> Result<u32> {
    match target.firewall_type {
        FirewallType::PanOs => push_panos(client, target, entries).await,
        FirewallType::FortiGate => push_fortigate(client, target, entries).await,
    }
}

/// Writes one push history row.
///
/// Parameters: `pool` - sqlite pool, `target_id` - target id, `mapping_count` - pushed mappings, `status` - status label, `error_message` - optional error, `duration_ms` - optional duration.
/// Returns: success or sql error.
async fn insert_history(
    pool: &sqlx::SqlitePool,
    target_id: i64,
    mapping_count: i64,
    status: &str,
    error_message: Option<&str>,
    duration_ms: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO firewall_push_history (target_id, mapping_count, status, error_message, duration_ms)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(target_id)
    .bind(mapping_count)
    .bind(status)
    .bind(error_message)
    .bind(duration_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Updates target push status columns.
///
/// Parameters: `pool` - sqlite pool, `target_id` - target id, `status` - status label, `count` - pushed count, `error_message` - optional error.
/// Returns: success or sql error.
async fn update_target_status(
    pool: &sqlx::SqlitePool,
    target_id: i64,
    status: &str,
    count: i64,
    error_message: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE firewall_targets
         SET last_push_at = datetime('now'),
             last_push_status = ?,
             last_push_count = ?,
             last_push_error = ?,
             updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(status)
    .bind(count)
    .bind(error_message)
    .bind(target_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Executes one push cycle for a target.
///
/// Parameters: `db` - database handle, `target` - decrypted target config.
/// Returns: pushed count.
async fn run_push_once(db: &Db, target: &FirewallTarget) -> Result<u32> {
    let client = build_client(target.verify_tls)?;
    let entries = load_push_entries(db, target).await?;
    if entries.is_empty() {
        return Ok(0);
    }
    push_to_target(&client, target, &entries).await
}

/// Runs background push loop for one target id.
///
/// Parameters: `db` - database handle, `target_id` - target identifier.
/// Returns: none.
pub async fn run_push_loop(db: Arc<Db>, target_id: i64) {
    loop {
        if FIREWALL_SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }
        let target = match load_target(&db, target_id).await {
            Ok(Some(t)) if t.enabled => t,
            Ok(_) => break,
            Err(e) => {
                warn!(error = %e, target_id, "Firewall push loop failed to load target");
                break;
            }
        };

        let started = Instant::now();
        match run_push_once(&db, &target).await {
            Ok(count) => {
                let duration_ms = started.elapsed().as_millis() as i64;
                if let Err(e) = insert_history(
                    db.pool(),
                    target.id,
                    i64::from(count),
                    "ok",
                    None,
                    duration_ms,
                )
                .await
                {
                    warn!(error = %e, target_id, "Failed to write firewall push history");
                }
                if let Err(e) =
                    update_target_status(db.pool(), target.id, "ok", i64::from(count), None).await
                {
                    warn!(error = %e, target_id, "Failed to update firewall target push status");
                }
                info!(target_id, target = %target.name, pushed = count, "Firewall push cycle complete");
            }
            Err(e) => {
                let duration_ms = started.elapsed().as_millis() as i64;
                let msg = e.to_string();
                if let Err(write_err) =
                    insert_history(db.pool(), target.id, 0, "error", Some(&msg), duration_ms).await
                {
                    warn!(error = %write_err, target_id, "Failed to write firewall push error history");
                }
                if let Err(update_err) =
                    update_target_status(db.pool(), target.id, "error", 0, Some(&msg)).await
                {
                    warn!(error = %update_err, target_id, "Failed to update firewall push error status");
                }
                warn!(error = %msg, target_id, target = %target.name, "Firewall push cycle failed");
            }
        }

        if FIREWALL_SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(target.push_interval_secs)).await;
    }
}

/// Starts firewall push manager.
///
/// Parameters: `db` - database handle.
/// Returns: nothing; spawns detached manager task.
pub fn start_firewall_push(db: Arc<Db>) {
    FIREWALL_SHUTDOWN.store(false, Ordering::SeqCst);
    tokio::spawn(async move {
        let mut running: HashMap<i64, tokio::task::JoinHandle<()>> = HashMap::new();
        loop {
            if FIREWALL_SHUTDOWN.load(Ordering::SeqCst) {
                for (_, handle) in running.drain() {
                    handle.abort();
                }
                break;
            }
            match load_enabled_target_ids(&db).await {
                Ok(target_ids) => {
                    for target_id in &target_ids {
                        if !running.contains_key(target_id) {
                            let loop_db = db.clone();
                            let id = *target_id;
                            let handle =
                                tokio::spawn(async move { run_push_loop(loop_db, id).await });
                            running.insert(id, handle);
                        }
                    }
                    let active_set = target_ids.into_iter().collect::<HashSet<_>>();
                    running.retain(|id, handle| {
                        if handle.is_finished() {
                            return false;
                        }
                        active_set.contains(id)
                    });
                }
                Err(e) => warn!(error = %e, "Firewall push manager failed to load targets"),
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}
