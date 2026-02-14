//! GeoIP resolver with SQLite cache and optional MaxMind MMDB backend.

use anyhow::Result;
use maxminddb::{geoip2, Reader};
use sqlx::{Row, SqlitePool};
use std::net::IpAddr;
use tracing::info;

/// GeoIP enrichment payload for one IP address.
#[derive(Debug, Clone)]
pub struct GeoInfo {
    /// Country ISO code (e.g. "PL").
    pub country_code: Option<String>,
    /// Country long name.
    pub country_name: Option<String>,
    /// City name.
    pub city: Option<String>,
    /// Latitude coordinate.
    pub latitude: Option<f64>,
    /// Longitude coordinate.
    pub longitude: Option<f64>,
    /// ASN number when available.
    pub asn: Option<u32>,
    /// ASN organization label.
    pub as_org: Option<String>,
    /// Whether the IP belongs to private/local ranges.
    pub is_private: bool,
}

/// Geo resolver that checks SQLite cache and falls back to MMDB lookup.
pub struct GeoResolver {
    reader: Option<Reader<Vec<u8>>>,
    pool: SqlitePool,
}

impl GeoResolver {
    /// Creates GeoResolver and optionally loads MMDB reader.
    ///
    /// Parameters: `mmdb_path` - optional path to GeoLite2 City database, `pool` - SQLite pool.
    /// Returns: initialized resolver.
    pub fn new(mmdb_path: Option<&str>, pool: SqlitePool) -> Self {
        let reader = mmdb_path.and_then(|path| {
            std::fs::read(path)
                .ok()
                .and_then(|bytes| Reader::from_source(bytes).ok())
                .map(|r| {
                    info!(path = %path, "GeoIP database loaded");
                    r
                })
        });
        Self { reader, pool }
    }

    /// Resolves IP to geo context using cache and optional MMDB.
    ///
    /// Parameters: `ip` - target IP.
    /// Returns: resolved geo info or `None` when not available.
    pub async fn resolve(&self, ip: &IpAddr) -> Option<GeoInfo> {
        if is_private(ip) {
            let info = GeoInfo::private();
            let _ = self.cache_result(ip, &info).await;
            return Some(info);
        }
        if let Ok(Some(cached)) = self.get_cached(ip).await {
            return Some(cached);
        }
        let Some(reader) = &self.reader else {
            return None;
        };
        if let Ok(city) = reader.lookup::<geoip2::City<'_>>(*ip) {
            let mut info = GeoInfo::from_maxmind_city(&city);
            info.is_private = false;
            let _ = self.cache_result(ip, &info).await;
            return Some(info);
        }
        None
    }

    /// Reads cached GeoInfo row from SQLite.
    ///
    /// Parameters: `ip` - target IP.
    /// Returns: optional cached value.
    async fn get_cached(&self, ip: &IpAddr) -> Result<Option<GeoInfo>> {
        let row = sqlx::query(
            "SELECT country_code, country_name, city, latitude, longitude, asn, as_org, is_private
             FROM ip_geo_cache
             WHERE ip = ?",
        )
        .bind(ip.to_string())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(Some(GeoInfo {
            country_code: row.try_get("country_code").ok(),
            country_name: row.try_get("country_name").ok(),
            city: row.try_get("city").ok(),
            latitude: row.try_get("latitude").ok(),
            longitude: row.try_get("longitude").ok(),
            asn: row
                .try_get::<Option<i64>, _>("asn")
                .ok()
                .flatten()
                .and_then(|v| u32::try_from(v).ok()),
            as_org: row.try_get("as_org").ok(),
            is_private: row.try_get::<i64, _>("is_private").unwrap_or(0) != 0,
        }))
    }

    /// Caches resolved geo info in SQLite.
    ///
    /// Parameters: `ip` - target IP, `info` - geo payload to store.
    /// Returns: success/failure of cache write.
    async fn cache_result(&self, ip: &IpAddr, info: &GeoInfo) -> Result<()> {
        sqlx::query(
            "INSERT INTO ip_geo_cache (
                ip, country_code, country_name, city, latitude, longitude, asn, as_org, is_private, resolved_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
             ON CONFLICT(ip) DO UPDATE SET
                country_code = excluded.country_code,
                country_name = excluded.country_name,
                city = excluded.city,
                latitude = excluded.latitude,
                longitude = excluded.longitude,
                asn = excluded.asn,
                as_org = excluded.as_org,
                is_private = excluded.is_private,
                resolved_at = datetime('now')",
        )
        .bind(ip.to_string())
        .bind(info.country_code.as_deref())
        .bind(info.country_name.as_deref())
        .bind(info.city.as_deref())
        .bind(info.latitude)
        .bind(info.longitude)
        .bind(info.asn.map(i64::from))
        .bind(info.as_org.as_deref())
        .bind(if info.is_private { 1 } else { 0 })
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

impl GeoInfo {
    /// Builds private-network GeoInfo placeholder.
    ///
    /// Returns: private marker object.
    pub fn private() -> Self {
        Self {
            country_code: None,
            country_name: None,
            city: Some("Private".to_string()),
            latitude: None,
            longitude: None,
            asn: None,
            as_org: None,
            is_private: true,
        }
    }

    /// Builds GeoInfo from MaxMind City lookup result.
    ///
    /// Parameters: `city` - MaxMind city record.
    /// Returns: normalized GeoInfo.
    fn from_maxmind_city(city: &geoip2::City<'_>) -> Self {
        let country_code = city
            .country
            .as_ref()
            .and_then(|c| c.iso_code.map(str::to_string));
        let country_name = city
            .country
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en").map(|v| v.to_string()));
        let city_name = city
            .city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en").map(|v| v.to_string()));
        let latitude = city.location.as_ref().and_then(|l| l.latitude);
        let longitude = city.location.as_ref().and_then(|l| l.longitude);
        Self {
            country_code,
            country_name,
            city: city_name,
            latitude,
            longitude,
            asn: None,
            as_org: None,
            is_private: false,
        }
    }
}

/// Checks whether IP belongs to private/local-only ranges.
///
/// Parameters: `ip` - target IP.
/// Returns: `true` for private, loopback, link-local, or ULA addresses.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            let is_ula = (seg0 & 0xfe00) == 0xfc00;
            is_ula || v6.is_loopback() || v6.is_unspecified()
        }
    }
}
