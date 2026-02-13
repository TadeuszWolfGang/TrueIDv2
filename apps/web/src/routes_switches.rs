//! SNMP switch CRUD and switch-port mapping endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tracing::warn;
use trueid_common::model::normalize_mac;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;

/// API response for switch configuration.
#[derive(Serialize)]
struct SwitchResponse {
    id: i64,
    ip: String,
    name: String,
    snmp_version: String,
    port: i64,
    poll_interval_secs: i64,
    enabled: bool,
    subnet_id: Option<i64>,
    location: Option<String>,
    last_polled_at: Option<DateTime<Utc>>,
    last_poll_status: Option<String>,
    last_poll_error: Option<String>,
    mac_count: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Request payload for creating a switch.
#[derive(Deserialize)]
pub(crate) struct CreateSwitchRequest {
    ip: String,
    name: String,
    community: String,
    snmp_version: Option<String>,
    port: Option<i64>,
    poll_interval_secs: Option<i64>,
    enabled: Option<bool>,
    subnet_id: Option<i64>,
    location: Option<String>,
}

/// Request payload for updating a switch.
#[derive(Deserialize)]
pub(crate) struct UpdateSwitchRequest {
    ip: Option<String>,
    name: Option<String>,
    community: Option<String>,
    port: Option<i64>,
    poll_interval_secs: Option<i64>,
    enabled: Option<bool>,
    subnet_id: Option<i64>,
    location: Option<String>,
}

/// API response for discovered switch-port mapping.
#[derive(Serialize)]
struct PortMappingResponse {
    id: i64,
    switch_id: i64,
    switch_name: String,
    mac: String,
    port_index: i64,
    if_index: Option<i64>,
    port_name: Option<String>,
    vlan_id: Option<i64>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

/// Aggregate switch polling statistics.
#[derive(Serialize)]
struct SwitchStatsResponse {
    total_switches: i64,
    enabled_switches: i64,
    total_mac_entries: i64,
    last_poll_time: Option<DateTime<Utc>>,
    switches_with_errors: i64,
}

/// Port mapping list filters.
#[derive(Deserialize)]
pub(crate) struct PortQuery {
    mac: Option<String>,
    switch_id: Option<i64>,
    port_name: Option<String>,
    page: Option<i64>,
    limit: Option<i64>,
}

/// Paginated switch-ports response.
#[derive(Serialize)]
struct PaginatedPorts {
    data: Vec<PortMappingResponse>,
    total: i64,
    page: i64,
    limit: i64,
}

/// Force poll response.
#[derive(Serialize)]
struct ForcePollResponse {
    switch_id: i64,
    queued: bool,
    message: String,
}

/// Validates switch create/update fields.
///
/// Parameters: request field values and `request_id`.
/// Returns: validation result with ApiError on invalid data.
fn validate_switch_fields(
    ip: Option<&str>,
    name: Option<&str>,
    community: Option<&str>,
    port: Option<i64>,
    poll_interval_secs: Option<i64>,
    request_id: &str,
) -> Result<(), ApiError> {
    if let Some(ip) = ip {
        if ip.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "ip must be a valid IPv4 address",
            )
            .with_request_id(request_id));
        }
    }
    if let Some(name) = name {
        if name.trim().is_empty() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "name is required",
            )
            .with_request_id(request_id));
        }
    }
    if let Some(community) = community {
        if community.trim().is_empty() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "community is required",
            )
            .with_request_id(request_id));
        }
    }
    if let Some(port) = port {
        if !(1..=65535).contains(&port) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "port must be in range 1..65535",
            )
            .with_request_id(request_id));
        }
    }
    if let Some(interval) = poll_interval_secs {
        if interval < 60 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "poll_interval_secs must be >= 60",
            )
            .with_request_id(request_id));
        }
    }
    Ok(())
}

/// Maps SQL row to switch response.
///
/// Parameters: `row` - SQL row.
/// Returns: `SwitchResponse`.
fn map_switch_row(row: &sqlx::sqlite::SqliteRow) -> SwitchResponse {
    SwitchResponse {
        id: row.try_get("id").unwrap_or_default(),
        ip: row.try_get("ip").unwrap_or_default(),
        name: row.try_get("name").unwrap_or_default(),
        snmp_version: row
            .try_get("snmp_version")
            .unwrap_or_else(|_| "v2c".to_string()),
        port: row.try_get("port").unwrap_or(161),
        poll_interval_secs: row.try_get("poll_interval_secs").unwrap_or(300),
        enabled: row.try_get("enabled").unwrap_or(true),
        subnet_id: row.try_get("subnet_id").ok(),
        location: row.try_get("location").ok(),
        last_polled_at: row.try_get("last_polled_at").ok(),
        last_poll_status: row.try_get("last_poll_status").ok(),
        last_poll_error: row.try_get("last_poll_error").ok(),
        mac_count: row.try_get("mac_count").unwrap_or(0),
        created_at: row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        updated_at: row.try_get("updated_at").unwrap_or_else(|_| Utc::now()),
    }
}

/// Lists all configured switches.
///
/// Parameters: `auth` - authenticated user, `state` - app state.
/// Returns: list of switches without community values.
pub(crate) async fn list_switches(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let rows = sqlx::query(
        "SELECT id, ip, name, snmp_version, port, poll_interval_secs, enabled, subnet_id, location,
                last_polled_at, last_poll_status, last_poll_error, mac_count, created_at, updated_at
         FROM snmp_switches
         ORDER BY name ASC",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to list switches");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list switches",
        )
        .with_request_id(&auth.request_id)
    })?;

    let data = rows.iter().map(map_switch_row).collect::<Vec<_>>();
    Ok(Json(data))
}

/// Returns one switch by identifier.
///
/// Parameters: `auth` - authenticated user, `id` - switch ID, `state` - app state.
/// Returns: switch details.
pub(crate) async fn get_switch(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let row = sqlx::query(
        "SELECT id, ip, name, snmp_version, port, poll_interval_secs, enabled, subnet_id, location,
                last_polled_at, last_poll_status, last_poll_error, mac_count, created_at, updated_at
         FROM snmp_switches WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, switch_id = id, "Failed to fetch switch");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to fetch switch",
        )
        .with_request_id(&auth.request_id)
    })?;

    match row {
        Some(row) => Ok(Json(map_switch_row(&row)).into_response()),
        None => Err(
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "Switch not found")
                .with_request_id(&auth.request_id),
        ),
    }
}

/// Creates a new SNMP switch configuration.
///
/// Parameters: `auth` - authenticated admin, `req` - create payload, `state` - app state.
/// Returns: created switch response.
pub(crate) async fn create_switch(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateSwitchRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    validate_switch_fields(
        Some(&req.ip),
        Some(&req.name),
        Some(&req.community),
        req.port,
        req.poll_interval_secs,
        &auth.request_id,
    )?;
    let snmp_version = req.snmp_version.unwrap_or_else(|| "v2c".to_string());
    if snmp_version != "v2c" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Only snmp_version=v2c is supported",
        )
        .with_request_id(&auth.request_id));
    }
    let encrypted = db.encrypt_config_value(req.community.trim()).map_err(|e| {
        warn!(error = %e, "Failed to encrypt switch community");
        ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Cannot encrypt community. Check CONFIG_ENCRYPTION_KEY",
        )
        .with_request_id(&auth.request_id)
    })?;

    let result = sqlx::query(
        "INSERT INTO snmp_switches
         (ip, name, community_encrypted, snmp_version, port, poll_interval_secs, enabled, subnet_id, location)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(req.ip.trim())
    .bind(req.name.trim())
    .bind(encrypted)
    .bind(snmp_version)
    .bind(req.port.unwrap_or(161))
    .bind(req.poll_interval_secs.unwrap_or(300))
    .bind(req.enabled.unwrap_or(true))
    .bind(req.subnet_id)
    .bind(req.location.as_deref().map(str::trim))
    .execute(db.pool())
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("UNIQUE constraint failed") {
            ApiError::new(
                StatusCode::CONFLICT,
                error::CONFLICT,
                "Switch with this IP already exists",
            )
            .with_request_id(&auth.request_id)
        } else {
            warn!(error = %e, "Failed to create switch");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to create switch",
            )
            .with_request_id(&auth.request_id)
        }
    })?;

    let created_id = result.last_insert_rowid();
    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "switch_create",
            Some(&created_id.to_string()),
            Some(&req.name),
            None,
            Some(&auth.request_id),
        )
        .await;

    get_switch(auth, Path(created_id), State(state)).await
}

/// Updates existing SNMP switch configuration.
///
/// Parameters: `auth` - authenticated admin, `id` - switch ID, `req` - update payload, `state` - app state.
/// Returns: updated switch response.
pub(crate) async fn update_switch(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(req): Json<UpdateSwitchRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    validate_switch_fields(
        req.ip.as_deref(),
        req.name.as_deref(),
        req.community.as_deref(),
        req.port,
        req.poll_interval_secs,
        &auth.request_id,
    )?;

    if sqlx::query("SELECT 1 FROM snmp_switches WHERE id = ?")
        .bind(id)
        .fetch_optional(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, switch_id = id, "Failed to check switch existence");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to update switch",
            )
            .with_request_id(&auth.request_id)
        })?
        .is_none()
    {
        return Err(
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "Switch not found")
                .with_request_id(&auth.request_id),
        );
    }

    let encrypted_community = match req.community.as_deref() {
        Some(v) => Some(db.encrypt_config_value(v.trim()).map_err(|e| {
            warn!(error = %e, "Failed to encrypt switch community");
            ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "Cannot encrypt community. Check CONFIG_ENCRYPTION_KEY",
            )
            .with_request_id(&auth.request_id)
        })?),
        None => None,
    };

    sqlx::query(
        "UPDATE snmp_switches
         SET ip = COALESCE(?, ip),
             name = COALESCE(?, name),
             community_encrypted = COALESCE(?, community_encrypted),
             port = COALESCE(?, port),
             poll_interval_secs = COALESCE(?, poll_interval_secs),
             enabled = COALESCE(?, enabled),
             subnet_id = ?,
             location = ?,
             updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(req.ip.as_deref().map(str::trim))
    .bind(req.name.as_deref().map(str::trim))
    .bind(encrypted_community)
    .bind(req.port)
    .bind(req.poll_interval_secs)
    .bind(req.enabled)
    .bind(req.subnet_id)
    .bind(req.location.as_deref().map(str::trim))
    .bind(id)
    .execute(db.pool())
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("UNIQUE constraint failed") {
            ApiError::new(
                StatusCode::CONFLICT,
                error::CONFLICT,
                "Switch with this IP already exists",
            )
            .with_request_id(&auth.request_id)
        } else {
            warn!(error = %e, switch_id = id, "Failed to update switch");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to update switch",
            )
            .with_request_id(&auth.request_id)
        }
    })?;

    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "switch_update",
            Some(&id.to_string()),
            None,
            None,
            Some(&auth.request_id),
        )
        .await;

    get_switch(auth, Path(id), State(state)).await
}

/// Deletes switch configuration and cascaded port mappings.
///
/// Parameters: `auth` - authenticated admin, `id` - switch ID, `state` - app state.
/// Returns: HTTP 204 on success.
pub(crate) async fn delete_switch(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let result = sqlx::query("DELETE FROM snmp_switches WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, switch_id = id, "Failed to delete switch");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to delete switch",
            )
            .with_request_id(&auth.request_id)
        })?;
    if result.rows_affected() == 0 {
        return Err(
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "Switch not found")
                .with_request_id(&auth.request_id),
        );
    }

    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "switch_delete",
            Some(&id.to_string()),
            None,
            None,
            Some(&auth.request_id),
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Forces near-immediate poll by resetting `last_polled_at`.
///
/// Parameters: `auth` - authenticated admin, `id` - switch ID, `state` - app state.
/// Returns: queued poll confirmation.
pub(crate) async fn force_poll(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let result = sqlx::query(
        "UPDATE snmp_switches
         SET last_polled_at = NULL, updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(id)
    .execute(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, switch_id = id, "Failed to queue forced poll");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to force poll",
        )
        .with_request_id(&auth.request_id)
    })?;

    if result.rows_affected() == 0 {
        return Err(
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "Switch not found")
                .with_request_id(&auth.request_id),
        );
    }

    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "switch_force_poll",
            Some(&id.to_string()),
            None,
            None,
            Some(&auth.request_id),
        )
        .await;

    Ok((
        StatusCode::OK,
        Json(ForcePollResponse {
            switch_id: id,
            queued: true,
            message: "Poll queued for next SNMP cycle".to_string(),
        }),
    ))
}

/// Returns aggregated switch polling statistics.
///
/// Parameters: `auth` - authenticated user, `state` - app state.
/// Returns: switch stats.
pub(crate) async fn switch_stats(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let total_switches: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM snmp_switches")
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to count switches");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to read switch stats",
            )
            .with_request_id(&auth.request_id)
        })?;
    let enabled_switches: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM snmp_switches WHERE enabled = true")
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to count enabled switches");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to read switch stats",
                )
                .with_request_id(&auth.request_id)
            })?;
    let total_mac_entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM switch_port_mappings")
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to count switch port mappings");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to read switch stats",
            )
            .with_request_id(&auth.request_id)
        })?;
    let last_poll_time: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT MAX(last_polled_at) FROM snmp_switches")
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to read last poll time");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to read switch stats",
                )
                .with_request_id(&auth.request_id)
            })?;
    let switches_with_errors: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM snmp_switches
         WHERE last_poll_status = 'error' OR last_poll_status = 'timeout'",
    )
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to count switches with errors");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to read switch stats",
        )
        .with_request_id(&auth.request_id)
    })?;

    Ok(Json(SwitchStatsResponse {
        total_switches,
        enabled_switches,
        total_mac_entries,
        last_poll_time,
        switches_with_errors,
    }))
}

/// Lists switch-port mappings with filters and pagination.
///
/// Parameters: `auth` - authenticated user, `q` - list filters, `state` - app state.
/// Returns: paginated list of port mappings.
pub(crate) async fn list_port_mappings(
    auth: AuthUser,
    Query(q): Query<PortQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * limit;

    let mut conditions = Vec::<String>::new();
    let mut binds = Vec::<String>::new();
    if let Some(mac) = q.mac.as_deref() {
        let normalized = normalize_mac(mac).unwrap_or_else(|| mac.to_ascii_lowercase());
        conditions.push("sp.mac LIKE ?".to_string());
        binds.push(format!("%{normalized}%"));
    }
    if let Some(port_name) = q.port_name.as_deref() {
        conditions.push("sp.port_name LIKE ?".to_string());
        binds.push(format!("%{}%", port_name.trim()));
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let count_sql = if q.switch_id.is_some() {
        format!(
            "SELECT COUNT(*) as c FROM switch_port_mappings sp {where_clause} AND sp.switch_id = ?"
        )
    } else {
        format!("SELECT COUNT(*) as c FROM switch_port_mappings sp {where_clause}")
    };
    let mut count_q = sqlx::query(&count_sql);
    for b in &binds {
        count_q = count_q.bind(b);
    }
    if let Some(switch_id) = q.switch_id {
        count_q = count_q.bind(switch_id);
    }
    let total: i64 = count_q
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to count switch port mappings");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to list switch port mappings",
            )
            .with_request_id(&auth.request_id)
        })?
        .try_get("c")
        .unwrap_or(0);

    let data_sql = if q.switch_id.is_some() {
        format!(
            "SELECT sp.id, sp.switch_id, sw.name as switch_name, sp.mac, sp.port_index, sp.if_index, sp.port_name, sp.vlan_id, sp.first_seen, sp.last_seen
             FROM switch_port_mappings sp
             JOIN snmp_switches sw ON sp.switch_id = sw.id
             {where_clause} AND sp.switch_id = ?
             ORDER BY sp.last_seen DESC
             LIMIT ? OFFSET ?"
        )
    } else {
        format!(
            "SELECT sp.id, sp.switch_id, sw.name as switch_name, sp.mac, sp.port_index, sp.if_index, sp.port_name, sp.vlan_id, sp.first_seen, sp.last_seen
             FROM switch_port_mappings sp
             JOIN snmp_switches sw ON sp.switch_id = sw.id
             {where_clause}
             ORDER BY sp.last_seen DESC
             LIMIT ? OFFSET ?"
        )
    };

    let mut data_q = sqlx::query(&data_sql);
    for b in &binds {
        data_q = data_q.bind(b);
    }
    if let Some(switch_id) = q.switch_id {
        data_q = data_q.bind(switch_id);
    }
    let rows = data_q
        .bind(limit)
        .bind(offset)
        .fetch_all(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to fetch switch port mappings");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to list switch port mappings",
            )
            .with_request_id(&auth.request_id)
        })?;

    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        data.push(PortMappingResponse {
            id: row.try_get("id").unwrap_or_default(),
            switch_id: row.try_get("switch_id").unwrap_or_default(),
            switch_name: row.try_get("switch_name").unwrap_or_default(),
            mac: row.try_get("mac").unwrap_or_default(),
            port_index: row.try_get("port_index").unwrap_or_default(),
            if_index: row.try_get("if_index").ok(),
            port_name: row.try_get("port_name").ok(),
            vlan_id: row.try_get("vlan_id").ok(),
            first_seen: row.try_get("first_seen").unwrap_or_else(|_| Utc::now()),
            last_seen: row.try_get("last_seen").unwrap_or_else(|_| Utc::now()),
        });
    }

    Ok(Json(PaginatedPorts {
        data,
        total,
        page,
        limit,
    }))
}

/// Finds latest switch-port mapping for a specific MAC.
///
/// Parameters: `auth` - authenticated user, `mac` - target MAC address, `state` - app state.
/// Returns: list ordered by recency.
pub(crate) async fn port_by_mac(
    auth: AuthUser,
    Path(mac): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let target = normalize_mac(&mac).unwrap_or_else(|| mac.to_ascii_lowercase());

    let rows = sqlx::query(
        "SELECT sp.id, sp.switch_id, sw.name as switch_name, sp.mac, sp.port_index, sp.if_index, sp.port_name, sp.vlan_id, sp.first_seen, sp.last_seen
         FROM switch_port_mappings sp
         JOIN snmp_switches sw ON sp.switch_id = sw.id
         WHERE sp.mac = ?
         ORDER BY sp.last_seen DESC",
    )
    .bind(target)
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, mac = %mac, "Failed to fetch switch port by MAC");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query switch port mapping",
        )
        .with_request_id(&auth.request_id)
    })?;

    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        data.push(PortMappingResponse {
            id: row.try_get("id").unwrap_or_default(),
            switch_id: row.try_get("switch_id").unwrap_or_default(),
            switch_name: row.try_get("switch_name").unwrap_or_default(),
            mac: row.try_get("mac").unwrap_or_default(),
            port_index: row.try_get("port_index").unwrap_or_default(),
            if_index: row.try_get("if_index").ok(),
            port_name: row.try_get("port_name").ok(),
            vlan_id: row.try_get("vlan_id").ok(),
            first_seen: row.try_get("first_seen").unwrap_or_else(|_| Utc::now()),
            last_seen: row.try_get("last_seen").unwrap_or_else(|_| Utc::now()),
        });
    }

    Ok(Json(data))
}
