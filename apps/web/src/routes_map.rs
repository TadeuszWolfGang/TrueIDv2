//! Network map/topology API endpoints for dashboard visualization.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashMap;
use tracing::warn;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;

/// Subnet node payload for topology graph.
#[derive(Debug, Serialize)]
pub struct MapSubnet {
    pub id: i64,
    pub name: String,
    pub cidr: String,
    pub active_ips: i64,
    pub total_mappings: i64,
    pub conflict_count: i64,
    pub top_users: Vec<String>,
}

/// Discovered subnet payload for topology graph.
#[derive(Debug, Serialize)]
pub struct MapDiscoveredSubnet {
    pub id: i64,
    pub cidr: String,
    pub ip_count: i64,
}

/// Adapter node payload for topology graph.
#[derive(Debug, Serialize)]
pub struct MapAdapter {
    pub name: String,
    pub r#type: String,
    pub status: String,
    pub event_count: i64,
}

/// Integration counters for topology right-side nodes.
#[derive(Debug, Serialize)]
pub struct MapIntegrations {
    pub firewall_targets: i64,
    pub siem_targets: i64,
    pub ldap_configured: bool,
}

/// High-level map statistics.
#[derive(Debug, Serialize)]
pub struct MapStats {
    pub total_ips: i64,
    pub total_users: i64,
    pub active_conflicts: i64,
}

/// Full topology response payload.
#[derive(Debug, Serialize)]
pub struct TopologyResponse {
    pub subnets: Vec<MapSubnet>,
    pub discovered_subnets: Vec<MapDiscoveredSubnet>,
    pub adapters: Vec<MapAdapter>,
    pub integrations: MapIntegrations,
    pub stats: MapStats,
}

/// One flow entry for map animation feed.
#[derive(Debug, Serialize)]
pub struct FlowEntry {
    pub source_type: String,
    pub ip: String,
    pub user: String,
    pub subnet_name: String,
    pub timestamp: String,
}

/// Flow stream response payload.
#[derive(Debug, Serialize)]
pub struct FlowsResponse {
    pub flows: Vec<FlowEntry>,
    pub window_minutes: i64,
}

/// Query parameters for flow window.
#[derive(Debug, Deserialize)]
pub struct FlowsQuery {
    pub minutes: Option<i64>,
}

/// Maps source string to stable adapter type label.
///
/// Parameters: `source` - source/raw adapter label.
/// Returns: normalized adapter type.
fn adapter_type_from_source(source: &str) -> String {
    let s = source.to_ascii_lowercase();
    if s.contains("radius") {
        "Radius".to_string()
    } else if s.contains("ad") {
        "AdLog".to_string()
    } else if s.contains("dhcp") {
        "DhcpLease".to_string()
    } else if s.contains("vpn") {
        "Vpn".to_string()
    } else {
        source.to_string()
    }
}

/// Loads adapter status from engine admin API with DB fallback.
///
/// Parameters: `state` - app state, `db_counts` - source counts from events table.
/// Returns: adapter list suitable for map rendering.
async fn load_adapters(state: &AppState, db_counts: &HashMap<String, i64>) -> Vec<MapAdapter> {
    let mut fallback = vec![
        MapAdapter {
            name: "RADIUS".to_string(),
            r#type: "Radius".to_string(),
            status: "listening".to_string(),
            event_count: *db_counts.get("Radius").unwrap_or(&0),
        },
        MapAdapter {
            name: "AD Syslog".to_string(),
            r#type: "AdLog".to_string(),
            status: "listening".to_string(),
            event_count: *db_counts.get("AdLog").unwrap_or(&0),
        },
        MapAdapter {
            name: "DHCP Syslog".to_string(),
            r#type: "DhcpLease".to_string(),
            status: "listening".to_string(),
            event_count: *db_counts.get("DhcpLease").unwrap_or(&0),
        },
        MapAdapter {
            name: "VPN Syslog".to_string(),
            r#type: "Vpn".to_string(),
            status: "listening".to_string(),
            event_count: db_counts
                .iter()
                .filter(|(k, _)| k.starts_with("Vpn"))
                .map(|(_, v)| *v)
                .sum(),
        },
    ];

    let url = format!("{}/engine/status/adapters", state.engine_url);
    let mut req = state.http_client.get(url);
    if let Some(token) = &state.engine_service_token {
        req = req.header("X-Service-Token", token);
    }
    let Ok(resp) = req.send().await else {
        return fallback;
    };
    let Ok(body) = resp.json::<serde_json::Value>().await else {
        return fallback;
    };
    let Some(rows) = body.get("adapters").and_then(|v| v.as_array()) else {
        return fallback;
    };

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let name = row
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("adapter")
            .to_string();
        let status = row
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let event_count = row
            .get("events_total")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        out.push(MapAdapter {
            r#type: adapter_type_from_source(&name),
            name,
            status,
            event_count,
        });
    }
    if out.is_empty() {
        fallback
    } else {
        // Keep deterministic order for frontend layout.
        out.sort_by(|a, b| a.name.cmp(&b.name));
        // Ensure known adapters exist even if engine omits one.
        for item in fallback.drain(..) {
            if !out.iter().any(|x| x.r#type == item.r#type) {
                out.push(item);
            }
        }
        out
    }
}

/// Returns network topology data for SVG map view.
///
/// Parameters: `auth` - authenticated principal, `state` - app state.
/// Returns: topology graph payload.
pub(crate) async fn topology(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let pool = db.pool();

    let subnet_rows = sqlx::query(
        "SELECT
            s.id, s.name, s.cidr,
            COALESCE(SUM(CASE WHEN m.is_active = 1 THEN 1 ELSE 0 END), 0) AS active_ips,
            COALESCE(COUNT(m.ip), 0) AS total_mappings,
            COALESCE((
                SELECT COUNT(*)
                FROM conflicts c
                JOIN mappings m2 ON m2.ip = c.ip
                WHERE m2.subnet_id = s.id
                  AND c.resolved_at IS NULL
            ), 0) AS conflict_count,
            COALESCE((
                SELECT GROUP_CONCAT(u.user)
                FROM (
                    SELECT m3.user
                    FROM mappings m3
                    WHERE m3.subnet_id = s.id AND m3.user IS NOT NULL AND m3.user != ''
                    GROUP BY m3.user
                    ORDER BY COUNT(*) DESC
                    LIMIT 3
                ) u
            ), '') AS top_users_csv
         FROM subnets s
         LEFT JOIN mappings m ON m.subnet_id = s.id
         GROUP BY s.id, s.name, s.cidr
         ORDER BY s.cidr ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to load map topology subnets");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to load topology subnets",
        )
        .with_request_id(&auth.request_id)
    })?;

    let subnets = subnet_rows
        .iter()
        .map(|r| {
            let top_users_csv: String = r.try_get("top_users_csv").unwrap_or_default();
            MapSubnet {
                id: r.try_get("id").unwrap_or_default(),
                name: r.try_get("name").unwrap_or_default(),
                cidr: r.try_get("cidr").unwrap_or_default(),
                active_ips: r.try_get("active_ips").unwrap_or(0),
                total_mappings: r.try_get("total_mappings").unwrap_or(0),
                conflict_count: r.try_get("conflict_count").unwrap_or(0),
                top_users: top_users_csv
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                    .collect(),
            }
        })
        .collect::<Vec<_>>();

    let discovered_rows = sqlx::query(
        "SELECT id, cidr, ip_count
         FROM discovered_subnets
         WHERE promoted = 0
         ORDER BY ip_count DESC, cidr ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to load discovered subnets for map");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to load discovered subnets",
        )
        .with_request_id(&auth.request_id)
    })?;

    let discovered_subnets = discovered_rows
        .iter()
        .map(|r| MapDiscoveredSubnet {
            id: r.try_get("id").unwrap_or_default(),
            cidr: r.try_get("cidr").unwrap_or_default(),
            ip_count: r.try_get("ip_count").unwrap_or(0),
        })
        .collect::<Vec<_>>();

    let source_rows = sqlx::query(
        "SELECT source, COUNT(*) AS cnt
         FROM events
         GROUP BY source",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to load event source counts for map");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to load topology adapter stats",
        )
        .with_request_id(&auth.request_id)
    })?;
    let mut source_counts = HashMap::new();
    for r in source_rows {
        let source: String = r.try_get("source").unwrap_or_default();
        let cnt: i64 = r.try_get("cnt").unwrap_or(0);
        source_counts.insert(source, cnt);
    }

    let adapters = load_adapters(&state, &source_counts).await;

    let firewall_targets: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM firewall_targets WHERE enabled = 1")
            .fetch_one(pool)
            .await
            .unwrap_or(0);
    let siem_targets: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM siem_targets WHERE enabled = 1")
            .fetch_one(pool)
            .await
            .unwrap_or(0);
    let ldap_configured: bool =
        sqlx::query_scalar::<_, i64>("SELECT COALESCE(enabled, 0) FROM ldap_config WHERE id = 1")
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
            .unwrap_or(0)
            == 1;

    let total_ips: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT ip) FROM mappings")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    let total_users: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT lower(user)) FROM mappings WHERE user IS NOT NULL AND user != ''",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    let active_conflicts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM conflicts WHERE resolved_at IS NULL")
            .fetch_one(pool)
            .await
            .unwrap_or(0);

    Ok(Json(TopologyResponse {
        subnets,
        discovered_subnets,
        adapters,
        integrations: MapIntegrations {
            firewall_targets,
            siem_targets,
            ldap_configured,
        },
        stats: MapStats {
            total_ips,
            total_users,
            active_conflicts,
        },
    }))
}

/// Returns recent flow list for map line animations.
///
/// Parameters: `auth` - authenticated principal, `state` - app state, `query` - flow window.
/// Returns: recent identity flows.
pub(crate) async fn flows(
    auth: AuthUser,
    State(state): State<AppState>,
    Query(query): Query<FlowsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let window_minutes = query.minutes.unwrap_or(30).clamp(5, 240);

    let rows = sqlx::query(
        "SELECT
            e.source AS source_type,
            e.ip,
            e.user,
            COALESCE(s.name, 'Unassigned') AS subnet_name,
            e.timestamp
         FROM events e
         LEFT JOIN mappings m ON m.ip = e.ip
         LEFT JOIN subnets s ON s.id = m.subnet_id
         WHERE e.timestamp >= datetime('now', '-' || ? || ' minutes')
         ORDER BY e.timestamp DESC
         LIMIT 300",
    )
    .bind(window_minutes)
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to load map flows");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to load map flows",
        )
        .with_request_id(&auth.request_id)
    })?;

    let flows = rows
        .iter()
        .map(|r| FlowEntry {
            source_type: r.try_get("source_type").unwrap_or_default(),
            ip: r.try_get("ip").unwrap_or_default(),
            user: r.try_get("user").unwrap_or_default(),
            subnet_name: r
                .try_get("subnet_name")
                .unwrap_or_else(|_| "Unassigned".to_string()),
            timestamp: r.try_get::<String, _>("timestamp").unwrap_or_default(),
        })
        .collect::<Vec<_>>();

    Ok(Json(FlowsResponse {
        flows,
        window_minutes,
    }))
}
