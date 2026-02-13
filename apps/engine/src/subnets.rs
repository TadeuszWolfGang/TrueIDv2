//! Subnet cache loading and mapping auto-tagging logic.

use anyhow::Result;
use sqlx::{Row, SqlitePool};

/// Cached subnet entry used for CIDR matching.
pub struct SubnetEntry {
    pub id: i64,
    pub network: u32,
    pub mask: u32,
    pub cidr: String,
}

/// Parses IPv4 CIDR (e.g. "10.1.2.0/24") into network and mask.
///
/// Parameters: `cidr` - CIDR string.
/// Returns: `(network_u32, mask_u32)` when valid IPv4 CIDR, otherwise `None`.
fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip: std::net::Ipv4Addr = parts[0].parse().ok()?;
    let prefix_len: u32 = parts[1].parse().ok()?;
    if prefix_len > 32 {
        return None;
    }
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    let network = u32::from(ip) & mask;
    Some((network, mask))
}

/// Loads all valid IPv4 subnet definitions from DB into cache.
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
        if let Some((network, mask)) = parse_cidr(&cidr) {
            out.push(SubnetEntry {
                id,
                network,
                mask,
                cidr,
            });
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
    let ip_u32 = match ip {
        std::net::IpAddr::V4(v4) => u32::from(*v4),
        std::net::IpAddr::V6(_) => return None, // TODO: Phase 4
    };
    subnets
        .iter()
        .filter(|s| (ip_u32 & s.mask) == s.network)
        .max_by_key(|s| s.mask.count_ones())
        .map(|s| s.id)
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
