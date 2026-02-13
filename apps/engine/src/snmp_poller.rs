//! Background SNMP poller for MAC-to-switch-port discovery.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use snmp::{ObjIdBuf, SyncSession, Value};
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{info, warn};
use trueid_common::db::Db;

use std::sync::Arc;

/// BRIDGE-MIB: MAC address forwarding table.
const OID_DOT1D_TP_FDB_ADDRESS: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 1];
/// BRIDGE-MIB: MAC -> bridge port index.
const OID_DOT1D_TP_FDB_PORT: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2];
/// BRIDGE-MIB: bridge port -> ifIndex.
const OID_DOT1D_BASE_PORT_IF_INDEX: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2];
/// IF-MIB: ifIndex -> interface description.
const OID_IF_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2];

/// Switch config loaded from DB for polling.
struct SwitchConfig {
    id: i64,
    ip: String,
    community: String,
    port: u16,
    poll_interval_secs: i64,
    last_polled_at: Option<DateTime<Utc>>,
}

/// Discovered MAC-to-port entry from one SNMP poll.
pub(crate) struct DiscoveredPort {
    pub(crate) mac: String,
    pub(crate) port_index: i64,
    pub(crate) if_index: Option<i64>,
    pub(crate) port_name: Option<String>,
}

/// Result of polling one switch.
pub(crate) struct PollResult {
    pub(crate) switch_id: i64,
    pub(crate) entries: Vec<DiscoveredPort>,
    pub(crate) error: Option<String>,
}

/// Poll cycle counters.
#[derive(Default)]
struct CycleStats {
    polled: usize,
    total_macs: usize,
    errors: usize,
}

/// Starts the background SNMP poller loop.
///
/// Parameters: `db` - shared database handle.
/// Returns: nothing; spawns detached Tokio task.
pub fn start_snmp_poller(db: Arc<Db>) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            match poll_cycle(&db).await {
                Ok(stats) => {
                    if stats.polled > 0 {
                        info!(
                            polled = stats.polled,
                            total_macs = stats.total_macs,
                            errors = stats.errors,
                            "SNMP poll cycle complete"
                        );
                    }
                }
                Err(e) => warn!(error = %e, "SNMP poll cycle failed"),
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

/// Runs one poll cycle over all due enabled switches.
///
/// Parameters: `db` - shared database handle.
/// Returns: cycle statistics.
async fn poll_cycle(db: &Db) -> Result<CycleStats> {
    let switches = load_due_switches(db).await?;
    let mut stats = CycleStats::default();
    for sw in switches {
        let _interval_secs = sw.poll_interval_secs;
        let _last_polled = sw.last_polled_at;
        stats.polled += 1;
        let result = poll_switch(&sw).await;
        match result.error.as_deref() {
            None => {
                let count = result.entries.len();
                stats.total_macs += count;
                save_poll_results(db, &result).await?;
                update_switch_status(db.pool(), sw.id, "ok", None, count as i64).await?;
            }
            Some(err) => {
                stats.errors += 1;
                warn!(switch_ip = %sw.ip, error = %err, "SNMP poll failed");
                update_switch_status(db.pool(), sw.id, "error", Some(err), 0).await?;
            }
        }
    }
    Ok(stats)
}

/// Loads enabled switches that are due for polling.
///
/// Parameters: `db` - shared database handle.
/// Returns: decrypted switch configs ready for polling.
async fn load_due_switches(db: &Db) -> Result<Vec<SwitchConfig>> {
    let rows = sqlx::query(
        "SELECT id, ip, community_encrypted, port, poll_interval_secs, last_polled_at
         FROM snmp_switches
         WHERE enabled = true
           AND (last_polled_at IS NULL
                OR datetime(last_polled_at, '+' || poll_interval_secs || ' seconds') < datetime('now'))",
    )
    .fetch_all(db.pool())
    .await?;

    let mut switches = Vec::with_capacity(rows.len());
    for row in rows {
        let community_enc: String = row.try_get("community_encrypted")?;
        let community = db.decrypt_config_value(&community_enc)?;
        let port_i64: i64 = row.try_get("port")?;
        let port = u16::try_from(port_i64)
            .with_context(|| format!("invalid SNMP port value: {port_i64}"))?;
        switches.push(SwitchConfig {
            id: row.try_get("id")?,
            ip: row.try_get("ip")?,
            community,
            port,
            poll_interval_secs: row.try_get("poll_interval_secs")?,
            last_polled_at: row.try_get("last_polled_at").ok(),
        });
    }
    Ok(switches)
}

/// Polls a single switch via SNMPv2c in blocking thread.
///
/// Parameters: `sw` - switch config with decrypted community.
/// Returns: poll result with discovered entries or error.
pub(crate) async fn poll_switch(sw: &SwitchConfig) -> PollResult {
    let ip = sw.ip.clone();
    let community = sw.community.clone();
    let port = sw.port;
    let switch_id = sw.id;

    match tokio::task::spawn_blocking(move || poll_switch_sync(&ip, &community, port)).await {
        Ok(Ok(entries)) => PollResult {
            switch_id,
            entries,
            error: None,
        },
        Ok(Err(e)) => PollResult {
            switch_id,
            entries: Vec::new(),
            error: Some(e.to_string()),
        },
        Err(e) => PollResult {
            switch_id,
            entries: Vec::new(),
            error: Some(format!("task join error: {e}")),
        },
    }
}

/// Synchronous SNMP walk: BRIDGE-MIB + IF-MIB to build MAC->port.
///
/// Parameters: `ip` - switch IP, `community` - SNMPv2c community, `port` - SNMP UDP port.
/// Returns: discovered MAC-to-port rows.
fn poll_switch_sync(ip: &str, community: &str, port: u16) -> Result<Vec<DiscoveredPort>> {
    let addr = format!("{ip}:{port}");
    let timeout = Duration::from_secs(10);
    let mut sess = SyncSession::new(addr.as_str(), community.as_bytes(), Some(timeout), 0)
        .map_err(|e| anyhow::anyhow!("SNMP error: {e:?}"))?;

    let mac_values = walk_table_bytes(&mut sess, OID_DOT1D_TP_FDB_ADDRESS)?;
    let mac_to_bridge_port = walk_table_u32(&mut sess, OID_DOT1D_TP_FDB_PORT)?;
    let bridge_port_to_if_index = walk_table_u32(&mut sess, OID_DOT1D_BASE_PORT_IF_INDEX)?;
    let if_index_to_name = walk_table_strings(&mut sess, OID_IF_DESCR)?;

    let mut mac_by_suffix = HashMap::<Vec<u32>, String>::new();
    for (suffix, value) in mac_values {
        mac_by_suffix.insert(suffix.clone(), bytes_to_mac(&value));
    }

    let mut results = Vec::with_capacity(mac_to_bridge_port.len());
    for (mac_suffix, bridge_port) in &mac_to_bridge_port {
        let mac = mac_by_suffix
            .get(mac_suffix)
            .cloned()
            .unwrap_or_else(|| oid_suffix_to_mac(mac_suffix));
        let if_idx = bridge_port_to_if_index
            .get(&vec![*bridge_port])
            .copied()
            .or_else(|| bridge_port_to_if_index.get(mac_suffix).copied());
        let port_name = if_idx
            .as_ref()
            .and_then(|idx| if_index_to_name.get(&vec![*idx]).cloned());

        results.push(DiscoveredPort {
            mac: normalize_mac(&mac),
            port_index: i64::from(*bridge_port),
            if_index: if_idx.map(i64::from),
            port_name,
        });
    }
    Ok(results)
}

/// Walks SNMP table values as integers.
///
/// Parameters: `sess` - active SNMP session, `base_oid` - table root OID.
/// Returns: map of OID suffix to integer value.
fn walk_table_u32(sess: &mut SyncSession, base_oid: &[u32]) -> Result<HashMap<Vec<u32>, u32>> {
    let mut result = HashMap::new();
    let mut current_oid = base_oid.to_vec();

    loop {
        let mut response = sess
            .getnext(&current_oid)
            .map_err(|e| anyhow::anyhow!("SNMP error: {e:?}"))?;
        let Some((oid, value)) = response.varbinds.next() else {
            break;
        };
        let oid_vec = oid_to_vec(&oid)?;
        if !oid_has_prefix(&oid_vec, base_oid) {
            break;
        }
        let suffix = oid_vec[base_oid.len()..].to_vec();
        match value {
            Value::Integer(v) => {
                if v >= 0 {
                    result.insert(suffix, v as u32);
                }
            }
            Value::Unsigned32(v) | Value::Counter32(v) | Value::Timeticks(v) => {
                result.insert(suffix, v);
            }
            _ => {}
        }
        current_oid = oid_vec;
    }
    Ok(result)
}

/// Walks SNMP table values as UTF-8 strings.
///
/// Parameters: `sess` - active SNMP session, `base_oid` - table root OID.
/// Returns: map of OID suffix to decoded string.
fn walk_table_strings(
    sess: &mut SyncSession,
    base_oid: &[u32],
) -> Result<HashMap<Vec<u32>, String>> {
    let mut result = HashMap::new();
    let mut current_oid = base_oid.to_vec();

    loop {
        let mut response = sess
            .getnext(&current_oid)
            .map_err(|e| anyhow::anyhow!("SNMP error: {e:?}"))?;
        let Some((oid, value)) = response.varbinds.next() else {
            break;
        };
        let oid_vec = oid_to_vec(&oid)?;
        if !oid_has_prefix(&oid_vec, base_oid) {
            break;
        }
        let suffix = oid_vec[base_oid.len()..].to_vec();
        if let Value::OctetString(raw) = value {
            result.insert(suffix, String::from_utf8_lossy(raw).trim().to_string());
        }
        current_oid = oid_vec;
    }
    Ok(result)
}

/// Walks SNMP table values as raw byte arrays.
///
/// Parameters: `sess` - active SNMP session, `base_oid` - table root OID.
/// Returns: map of OID suffix to raw octets.
fn walk_table_bytes(
    sess: &mut SyncSession,
    base_oid: &[u32],
) -> Result<HashMap<Vec<u32>, Vec<u8>>> {
    let mut result = HashMap::new();
    let mut current_oid = base_oid.to_vec();

    loop {
        let mut response = sess
            .getnext(&current_oid)
            .map_err(|e| anyhow::anyhow!("SNMP error: {e:?}"))?;
        let Some((oid, value)) = response.varbinds.next() else {
            break;
        };
        let oid_vec = oid_to_vec(&oid)?;
        if !oid_has_prefix(&oid_vec, base_oid) {
            break;
        }
        let suffix = oid_vec[base_oid.len()..].to_vec();
        if let Value::OctetString(raw) = value {
            result.insert(suffix, raw.to_vec());
        }
        current_oid = oid_vec;
    }
    Ok(result)
}

/// Converts OID suffix bytes to normalized MAC string.
///
/// Parameters: `suffix` - OID suffix containing MAC octets.
/// Returns: lower-case colon-separated MAC.
fn oid_suffix_to_mac(suffix: &[u32]) -> String {
    if suffix.len() < 6 {
        return "00:00:00:00:00:00".to_string();
    }
    let octets = &suffix[suffix.len() - 6..];
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]
    )
}

/// Converts raw MAC bytes to normalized MAC string.
///
/// Parameters: `bytes` - raw octets.
/// Returns: lower-case colon-separated MAC.
fn bytes_to_mac(bytes: &[u8]) -> String {
    if bytes.len() < 6 {
        return "00:00:00:00:00:00".to_string();
    }
    let o = &bytes[bytes.len() - 6..];
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        o[0], o[1], o[2], o[3], o[4], o[5]
    )
}

/// Normalizes MAC into lower-case colon-separated format.
///
/// Parameters: `mac` - input MAC in arbitrary separator format.
/// Returns: normalized MAC or zero MAC if input invalid.
fn normalize_mac(mac: &str) -> String {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return "00:00:00:00:00:00".to_string();
    }
    let lower = hex.to_ascii_lowercase();
    format!(
        "{}:{}:{}:{}:{}:{}",
        &lower[0..2],
        &lower[2..4],
        &lower[4..6],
        &lower[6..8],
        &lower[8..10],
        &lower[10..12]
    )
}

/// Converts SNMP object identifier to vector of u32.
///
/// Parameters: `oid` - borrowed SNMP object identifier.
/// Returns: parsed OID components.
fn oid_to_vec(oid: &snmp::ObjectIdentifier<'_>) -> Result<Vec<u32>> {
    let mut buf: ObjIdBuf = [0; 128];
    let name = oid
        .read_name(&mut buf)
        .map_err(|e| anyhow::anyhow!("SNMP error: {e:?}"))?;
    Ok(name.to_vec())
}

/// Checks whether OID begins with the expected prefix.
///
/// Parameters: `oid` - candidate oid, `prefix` - base oid.
/// Returns: true if `prefix` is oid prefix.
fn oid_has_prefix(oid: &[u32], prefix: &[u32]) -> bool {
    oid.len() >= prefix.len() && oid[..prefix.len()] == *prefix
}

/// Upserts discovered mappings and removes stale entries.
///
/// Parameters: `db` - shared db handle, `result` - switch poll output.
/// Returns: success or database error.
pub(crate) async fn save_poll_results(db: &Db, result: &PollResult) -> Result<()> {
    let pool = db.pool();
    let now = Utc::now();
    let mut tx = pool.begin().await?;

    for entry in &result.entries {
        sqlx::query(
            "INSERT INTO switch_port_mappings (switch_id, mac, port_index, if_index, port_name, last_seen)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(switch_id, mac) DO UPDATE SET
                port_index = excluded.port_index,
                if_index = excluded.if_index,
                port_name = excluded.port_name,
                last_seen = excluded.last_seen",
        )
        .bind(result.switch_id)
        .bind(&entry.mac)
        .bind(entry.port_index)
        .bind(entry.if_index)
        .bind(&entry.port_name)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query(
        "DELETE FROM switch_port_mappings
         WHERE switch_id = ? AND last_seen < datetime('now', '-1 hour')",
    )
    .bind(result.switch_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Updates latest polling metadata for a switch.
///
/// Parameters: `pool` - sqlite pool, `switch_id` - switch id, `status` - poll status,
/// `error` - optional error text, `mac_count` - discovered count.
/// Returns: success or SQL error.
async fn update_switch_status(
    pool: &SqlitePool,
    switch_id: i64,
    status: &str,
    error: Option<&str>,
    mac_count: i64,
) -> Result<()> {
    sqlx::query(
        "UPDATE snmp_switches
         SET last_polled_at = datetime('now'),
             last_poll_status = ?,
             last_poll_error = ?,
             mac_count = ?,
             updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(status)
    .bind(error)
    .bind(mac_count)
    .bind(switch_id)
    .execute(pool)
    .await?;
    Ok(())
}
