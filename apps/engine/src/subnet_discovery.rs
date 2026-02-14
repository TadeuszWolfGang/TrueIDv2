//! Passive auto-subnet discovery from observed event IP addresses.

use anyhow::Result;
use sqlx::SqlitePool;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::subnets::{self, SubnetEntry};

/// Maintains known subnets and stores inferred subnets not yet managed.
pub struct SubnetDiscovery {
    pool: SqlitePool,
    known_subnets: Arc<RwLock<Vec<SubnetEntry>>>,
}

impl SubnetDiscovery {
    /// Creates subnet discovery service and loads known subnet cache.
    ///
    /// Parameters: `pool` - SQLite pool.
    /// Returns: initialized subnet discovery instance.
    pub async fn new(pool: SqlitePool) -> Self {
        let known = subnets::load_subnets(&pool).await.unwrap_or_default();
        Self {
            pool,
            known_subnets: Arc::new(RwLock::new(known)),
        }
    }

    /// Observes one IP and records inferred subnet if unmanaged.
    ///
    /// Parameters: `ip` - observed IP address.
    /// Returns: none.
    pub async fn observe_ip(&self, ip: &IpAddr) {
        {
            let known = self.known_subnets.read().await;
            if subnets::match_subnet(ip, &known).is_some() {
                return;
            }
        }
        let cidr = match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(v6) => {
                let seg = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", seg[0], seg[1], seg[2], seg[3])
            }
        };
        let _ = sqlx::query(
            "INSERT INTO discovered_subnets (cidr, ip_count, first_seen, last_seen)
             VALUES (?, 1, datetime('now'), datetime('now'))
             ON CONFLICT(cidr) DO UPDATE SET
                ip_count = ip_count + 1,
                last_seen = datetime('now')",
        )
        .bind(cidr)
        .execute(&self.pool)
        .await;
    }

    /// Reloads managed subnets cache from database.
    ///
    /// Returns: success/failure of refresh.
    pub async fn refresh_known_subnets(&self) -> Result<()> {
        let loaded = subnets::load_subnets(&self.pool).await?;
        let mut known = self.known_subnets.write().await;
        *known = loaded;
        Ok(())
    }
}
