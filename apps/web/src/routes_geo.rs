//! GeoIP lookup and statistics endpoints backed by cache and private-IP detection.

use axum::{extract::Path, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use sqlx::Row;
use tracing::warn;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;

/// Geo lookup response payload.
#[derive(Debug, Serialize)]
struct GeoLookupResponse {
    ip: String,
    country_code: Option<String>,
    country_name: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    asn: Option<i64>,
    as_org: Option<String>,
    is_private: bool,
    resolved_at: Option<String>,
}

/// Country aggregate row for geo stats.
#[derive(Debug, Serialize)]
struct CountryCount {
    country_code: String,
    country_name: String,
    count: i64,
}

/// Returns geo data for one IP address.
///
/// Parameters: `auth` - authenticated principal, `state` - app state, `ip` - target IP string.
/// Returns: geo record from cache or private-IP placeholder.
pub(crate) async fn lookup(
    auth: AuthUser,
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(ip): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let parsed = ip.parse::<std::net::IpAddr>().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Invalid IP format",
        )
        .with_request_id(&auth.request_id)
    })?;
    if is_private(&parsed) {
        return Ok(Json(GeoLookupResponse {
            ip,
            country_code: None,
            country_name: None,
            city: Some("Private".to_string()),
            latitude: None,
            longitude: None,
            asn: None,
            as_org: None,
            is_private: true,
            resolved_at: None,
        }));
    }
    let db = helpers::require_db(&state, &auth.request_id)?;
    let row = sqlx::query(
        "SELECT country_code, country_name, city, latitude, longitude, asn, as_org, is_private, resolved_at
         FROM ip_geo_cache
         WHERE ip = ?",
    )
    .bind(&ip)
    .fetch_optional(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, ip = %ip, "Failed geo lookup");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to lookup geo info",
        )
        .with_request_id(&auth.request_id)
    })?;
    let Some(row) = row else {
        return Ok(Json(GeoLookupResponse {
            ip,
            country_code: None,
            country_name: None,
            city: None,
            latitude: None,
            longitude: None,
            asn: None,
            as_org: None,
            is_private: false,
            resolved_at: None,
        }));
    };
    Ok(Json(GeoLookupResponse {
        ip,
        country_code: row.try_get("country_code").ok(),
        country_name: row.try_get("country_name").ok(),
        city: row.try_get("city").ok(),
        latitude: row.try_get("latitude").ok(),
        longitude: row.try_get("longitude").ok(),
        asn: row.try_get("asn").ok(),
        as_org: row.try_get("as_org").ok(),
        is_private: row.try_get::<i64, _>("is_private").unwrap_or(0) != 0,
        resolved_at: row.try_get("resolved_at").ok(),
    }))
}

/// Returns GeoIP resolution distribution and summary counters.
///
/// Parameters: `auth` - authenticated principal, `state` - app state.
/// Returns: aggregated geo stats.
pub(crate) async fn stats(
    auth: AuthUser,
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let total_resolved: i64 = sqlx::query("SELECT COUNT(*) as c FROM ip_geo_cache")
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to count geo cache rows");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to read geo stats",
            )
            .with_request_id(&auth.request_id)
        })?
        .try_get("c")
        .unwrap_or(0);
    let private_ips: i64 =
        sqlx::query("SELECT COUNT(*) as c FROM ip_geo_cache WHERE is_private = 1")
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to count private geo rows");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to read geo stats",
                )
                .with_request_id(&auth.request_id)
            })?
            .try_get("c")
            .unwrap_or(0);
    let rows = sqlx::query(
        "SELECT COALESCE(country_code, '??') as country_code,
                COALESCE(country_name, 'Unknown') as country_name,
                COUNT(*) as c
         FROM ip_geo_cache
         WHERE is_private = 0
         GROUP BY country_code, country_name
         ORDER BY c DESC
         LIMIT 20",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to aggregate country geo stats");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to read geo stats",
        )
        .with_request_id(&auth.request_id)
    })?;
    let countries: Vec<CountryCount> = rows
        .iter()
        .map(|r| CountryCount {
            country_code: r
                .try_get("country_code")
                .unwrap_or_else(|_| "??".to_string()),
            country_name: r
                .try_get("country_name")
                .unwrap_or_else(|_| "Unknown".to_string()),
            count: r.try_get("c").unwrap_or(0),
        })
        .collect();
    Ok(Json(serde_json::json!({
        "total_resolved": total_resolved,
        "private_ips": private_ips,
        "countries": countries
    })))
}

/// Refreshes geo cache for active mappings with private-IP fast-path only.
///
/// Parameters: `auth` - authenticated admin, `state` - app state.
/// Returns: number of refreshed private IPs.
pub(crate) async fn refresh(
    auth: AuthUser,
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = sqlx::query("SELECT ip FROM mappings WHERE is_active = 1")
        .fetch_all(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to load active mappings for geo refresh");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to refresh geo data",
            )
            .with_request_id(&auth.request_id)
        })?;
    let mut refreshed_private = 0_i64;
    for row in rows {
        let ip: String = row.try_get("ip").unwrap_or_default();
        let parsed = match ip.parse::<std::net::IpAddr>() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if is_private(&parsed) {
            let _ = sqlx::query(
                "INSERT INTO ip_geo_cache (ip, is_private, city, resolved_at)
                 VALUES (?, 1, 'Private', datetime('now'))
                 ON CONFLICT(ip) DO UPDATE SET
                    is_private = 1,
                    city = 'Private',
                    resolved_at = datetime('now')",
            )
            .bind(&ip)
            .execute(db.pool())
            .await;
            refreshed_private += 1;
        }
    }
    helpers::audit(
        db,
        &auth,
        "geo_refresh",
        None,
        Some(&format!("private_refreshed={refreshed_private}")),
    )
    .await;
    Ok(Json(serde_json::json!({
        "success": true,
        "refreshed_private": refreshed_private
    })))
}

/// Checks if address is private/local.
///
/// Parameters: `ip` - IP address to classify.
/// Returns: `true` for private, loopback, link-local, and ULA ranges.
fn is_private(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            let is_ula = (seg0 & 0xfe00) == 0xfc00;
            is_ula || v6.is_loopback() || v6.is_unspecified()
        }
    }
}
