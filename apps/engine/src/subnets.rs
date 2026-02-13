//! Subnet cache loading and mapping auto-tagging logic.

use anyhow::Result;
use sqlx::{Row, SqlitePool};

/// Cached subnet entry used for CIDR matching.
pub struct SubnetEntry {
    pub id: i64,
    pub cidr: String,
    network: SubnetNetwork,
}

/// Parsed CIDR network for IPv4 or IPv6 subnet.
enum SubnetNetwork {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

/// Parses CIDR into network and mask.
///
/// Parameters: `cidr` - CIDR string.
/// Returns: parsed subnet network for valid IPv4/IPv6 CIDR.
fn parse_cidr(cidr: &str) -> Option<SubnetNetwork> {
    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return None;
    }
    let prefix_len: u32 = parts[1].parse().ok()?;

    if let Ok(v4) = parts[0].parse::<std::net::Ipv4Addr>() {
        if prefix_len > 32 {
            return None;
        }
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        let network = u32::from(v4) & mask;
        return Some(SubnetNetwork::V4 { network, mask });
    }

    if let Ok(v6) = parts[0].parse::<std::net::Ipv6Addr>() {
        if prefix_len > 128 {
            return None;
        }
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u128 << (128 - prefix_len)
        };
        let network = u128::from(v6) & mask;
        return Some(SubnetNetwork::V6 { network, mask });
    }

    None
}

/// Loads all valid subnet definitions from DB into cache.
///
/// Parameters: `pool` - SQLite pool.
/// Returns: list of parsed subnet entries.
pub async fn load_subnets(pool: &SqlitePool) -> Result<Vec<SubnetEntry>> {
    let rows = sqlx::query("SELECT id, cidr FROM subnets ORDER BY id ASC")
        .fetch_all(pool)
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let id: i64 = row.try_get("id")?;
        let cidr: String = row.try_get("cidr")?;
        if let Some(network) = parse_cidr(&cidr) {
            out.push(SubnetEntry { id, cidr, network });
        } else {
            tracing::warn!(subnet_id = id, cidr = %cidr, "Skipping invalid subnet CIDR");
        }
    }
    Ok(out)
}

/// Finds best matching subnet for an IP using longest-prefix match.
///
/// Parameters: `ip` - target IP, `subnets` - cached subnet entries.
/// Returns: matched subnet ID or `None` when no match.
pub fn match_subnet(ip: &std::net::IpAddr, subnets: &[SubnetEntry]) -> Option<i64> {
    let mut best: Option<(i64, u32)> = None;

    for entry in subnets {
        let matches = match (&entry.network, ip) {
            (SubnetNetwork::V4 { network, mask }, std::net::IpAddr::V4(v4)) => {
                (u32::from(*v4) & mask) == *network
            }
            (SubnetNetwork::V6 { network, mask }, std::net::IpAddr::V6(v6)) => {
                (u128::from(*v6) & mask) == *network
            }
            _ => false,
        };
        if !matches {
            continue;
        }
        let prefix_len = match &entry.network {
            SubnetNetwork::V4 { mask, .. } => mask.count_ones(),
            SubnetNetwork::V6 { mask, .. } => mask.count_ones(),
        };
        if best.is_none() || prefix_len > best.map(|(_, p)| p).unwrap_or(0) {
            best = Some((entry.id, prefix_len));
        }
    }

    best.map(|(id, _)| id)
}

/// Tags a mapping row with subnet_id based on cached subnet definitions.
///
/// Parameters: `pool` - SQLite pool, `ip` - mapping IP string, `subnets` - cached subnet entries.
/// Returns: success/failure of DB updates.
pub async fn tag_subnet(pool: &SqlitePool, ip: &str, subnets: &[SubnetEntry]) -> Result<()> {
    let parsed_ip: std::net::IpAddr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return Ok(()),
    };
    let subnet_id = match match_subnet(&parsed_ip, subnets) {
        Some(id) => id,
        None => {
            sqlx::query(
                "UPDATE mappings SET subnet_id = NULL WHERE ip = ? AND subnet_id IS NOT NULL",
            )
            .bind(ip)
            .execute(pool)
            .await?;
            return Ok(());
        }
    };
    if let Some(entry) = subnets.iter().find(|s| s.id == subnet_id) {
        tracing::debug!(ip = %ip, subnet_id, cidr = %entry.cidr, "Subnet matched for mapping");
    }
    sqlx::query("UPDATE mappings SET subnet_id = ? WHERE ip = ?")
        .bind(subnet_id)
        .bind(ip)
        .execute(pool)
        .await?;
    Ok(())
}
