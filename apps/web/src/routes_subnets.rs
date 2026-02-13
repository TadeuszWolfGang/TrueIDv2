//! Subnet/VLAN management and subnet statistics endpoints.

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
use trueid_common::model::DeviceMapping;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;

/// API response for a subnet definition.
#[derive(Serialize)]
struct SubnetResponse {
    id: i64,
    cidr: String,
    name: String,
    vlan_id: Option<i64>,
    location: Option<String>,
    description: Option<String>,
    gateway: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Create subnet payload.
#[derive(Deserialize)]
pub struct CreateSubnetRequest {
    cidr: String,
    name: String,
    vlan_id: Option<i64>,
    location: Option<String>,
    description: Option<String>,
    gateway: Option<String>,
}

/// Partial update payload for subnet definition.
#[derive(Deserialize)]
pub struct UpdateSubnetRequest {
    cidr: Option<String>,
    name: Option<String>,
    vlan_id: Option<i64>,
    location: Option<String>,
    description: Option<String>,
    gateway: Option<String>,
}

/// Subnet statistics summary.
#[derive(Serialize)]
struct SubnetStats {
    total_subnets: i64,
    total_tagged_mappings: i64,
    untagged_mappings: i64,
    per_subnet: Vec<SubnetCount>,
}

/// Per-subnet mapping counters.
#[derive(Serialize)]
struct SubnetCount {
    id: i64,
    name: String,
    cidr: String,
    active_mappings: i64,
    total_mappings: i64,
}

/// Query parameters for subnet mappings listing.
#[derive(Deserialize)]
pub(crate) struct SubnetMappingsQuery {
    page: Option<i64>,
    per_page: Option<i64>,
}

/// Paginated mappings response for subnet scope.
#[derive(Serialize)]
struct PaginatedSubnetMappings {
    data: Vec<DeviceMapping>,
    total: i64,
    page: i64,
    per_page: i64,
}

/// Parses IPv4/IPv6 CIDR into network/mask components.
///
/// Parameters: `cidr` - CIDR string.
/// Returns: `Some(())` for valid CIDR, otherwise `None`.
fn parse_cidr(cidr: &str) -> Option<()> {
    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return None;
    }
    let prefix_len: u32 = parts[1].parse().ok()?;
    if let Ok(_ip) = parts[0].parse::<std::net::Ipv4Addr>() {
        if prefix_len <= 32 {
            return Some(());
        }
    }
    if let Ok(_ip) = parts[0].parse::<std::net::Ipv6Addr>() {
        if prefix_len <= 128 {
            return Some(());
        }
    }
    None
}

/// Validates subnet payload fields.
///
/// Parameters: `cidr` - optional CIDR, `name` - optional name, `vlan_id` - optional VLAN ID, `request_id` - request correlation ID.
/// Returns: validation success or API validation error.
fn validate_fields(
    cidr: Option<&str>,
    name: Option<&str>,
    vlan_id: Option<i64>,
    request_id: &str,
) -> Result<(), ApiError> {
    if let Some(cidr) = cidr {
        if parse_cidr(cidr).is_none() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "Invalid CIDR. Use valid IPv4 or IPv6 CIDR.",
            )
            .with_request_id(request_id));
        }
    }
    if let Some(name) = name {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.len() > 200 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "Name must be non-empty and up to 200 characters.",
            )
            .with_request_id(request_id));
        }
    }
    if let Some(vlan_id) = vlan_id {
        if !(1..=4094).contains(&vlan_id) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "vlan_id must be in range 1..=4094.",
            )
            .with_request_id(request_id));
        }
    }
    Ok(())
}

/// Maps SQL row into subnet DTO.
///
/// Parameters: `row` - SQL row.
/// Returns: parsed subnet response struct.
fn map_subnet_row(row: &sqlx::sqlite::SqliteRow) -> SubnetResponse {
    SubnetResponse {
        id: row.try_get("id").unwrap_or_default(),
        cidr: row.try_get("cidr").unwrap_or_default(),
        name: row.try_get("name").unwrap_or_default(),
        vlan_id: row.try_get("vlan_id").ok(),
        location: row.try_get("location").ok(),
        description: row.try_get("description").ok(),
        gateway: row.try_get("gateway").ok(),
        created_at: row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        updated_at: row.try_get("updated_at").unwrap_or_else(|_| Utc::now()),
    }
}

/// Lists all subnet definitions.
///
/// Parameters: `auth` - authenticated principal, `state` - app state.
/// Returns: list of subnet definitions.
pub(crate) async fn list_subnets(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let rows = sqlx::query(
        "SELECT id, cidr, name, vlan_id, location, description, gateway, created_at, updated_at
         FROM subnets
         ORDER BY cidr ASC",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to list subnets");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list subnets",
        )
        .with_request_id(&auth.request_id)
    })?;

    Ok(Json(
        rows.iter()
            .map(map_subnet_row)
            .collect::<Vec<SubnetResponse>>(),
    ))
}

/// Creates a subnet definition.
///
/// Parameters: `auth` - authenticated admin, `state` - app state, `body` - create payload.
/// Returns: created subnet.
pub(crate) async fn create_subnet(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<CreateSubnetRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    validate_fields(
        Some(body.cidr.trim()),
        Some(body.name.trim()),
        body.vlan_id,
        &auth.request_id,
    )?;

    let insert = sqlx::query(
        "INSERT INTO subnets (cidr, name, vlan_id, location, description, gateway, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
    )
    .bind(body.cidr.trim())
    .bind(body.name.trim())
    .bind(body.vlan_id)
    .bind(body.location)
    .bind(body.description)
    .bind(body.gateway)
    .execute(db.pool())
    .await;

    let result = match insert {
        Ok(res) => res,
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            if msg.contains("unique") {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    error::CONFLICT,
                    "Subnet CIDR already exists",
                )
                .with_request_id(&auth.request_id));
            }
            warn!(error = %e, "Failed to create subnet");
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to create subnet",
            )
            .with_request_id(&auth.request_id));
        }
    };

    let subnet_id = result.last_insert_rowid();
    let row = sqlx::query(
        "SELECT id, cidr, name, vlan_id, location, description, gateway, created_at, updated_at
         FROM subnets WHERE id = ?",
    )
    .bind(subnet_id)
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, subnet_id, "Failed to fetch created subnet");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to create subnet",
        )
        .with_request_id(&auth.request_id)
    })?;

    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "create_subnet",
            Some(&format!("subnet:{subnet_id}")),
            Some(&format!(
                "cidr={}",
                row.try_get::<String, _>("cidr").unwrap_or_default()
            )),
            None,
            Some(&auth.request_id),
        )
        .await;

    Ok((StatusCode::CREATED, Json(map_subnet_row(&row))))
}

/// Updates a subnet definition.
///
/// Parameters: `auth` - authenticated admin, `id` - subnet ID, `state` - app state, `body` - partial update payload.
/// Returns: updated subnet.
pub(crate) async fn update_subnet(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(body): Json<UpdateSubnetRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let existing = sqlx::query("SELECT id FROM subnets WHERE id = ?")
        .bind(id)
        .fetch_optional(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, subnet_id = id, "Failed to query subnet");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to update subnet",
            )
            .with_request_id(&auth.request_id)
        })?;
    if existing.is_none() {
        return Err(
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "Subnet not found")
                .with_request_id(&auth.request_id),
        );
    }

    validate_fields(
        body.cidr.as_deref().map(str::trim),
        body.name.as_deref().map(str::trim),
        body.vlan_id,
        &auth.request_id,
    )?;

    let mut sets = Vec::<String>::new();
    let mut binds = Vec::<serde_json::Value>::new();

    if let Some(cidr) = body.cidr.as_deref().map(str::trim) {
        sets.push("cidr = ?".to_string());
        binds.push(serde_json::Value::String(cidr.to_string()));
    }
    if let Some(name) = body.name.as_deref().map(str::trim) {
        sets.push("name = ?".to_string());
        binds.push(serde_json::Value::String(name.to_string()));
    }
    if let Some(vlan_id) = body.vlan_id {
        sets.push("vlan_id = ?".to_string());
        binds.push(serde_json::Value::Number(vlan_id.into()));
    }
    if let Some(location) = body.location {
        sets.push("location = ?".to_string());
        binds.push(serde_json::Value::String(location));
    }
    if let Some(description) = body.description {
        sets.push("description = ?".to_string());
        binds.push(serde_json::Value::String(description));
    }
    if let Some(gateway) = body.gateway {
        sets.push("gateway = ?".to_string());
        binds.push(serde_json::Value::String(gateway));
    }

    if sets.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "No fields to update",
        )
        .with_request_id(&auth.request_id));
    }
    sets.push("updated_at = datetime('now')".to_string());

    let sql = format!("UPDATE subnets SET {} WHERE id = ?", sets.join(", "));
    let mut q = sqlx::query(&sql);
    for bind in binds {
        q = match bind {
            serde_json::Value::String(v) => q.bind(v),
            serde_json::Value::Number(v) => q.bind(v.as_i64()),
            _ => q,
        };
    }
    let update_result = q.bind(id).execute(db.pool()).await;
    if let Err(e) = update_result {
        let msg = e.to_string().to_lowercase();
        if msg.contains("unique") {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                error::CONFLICT,
                "Subnet CIDR already exists",
            )
            .with_request_id(&auth.request_id));
        }
        warn!(error = %e, subnet_id = id, "Failed to update subnet");
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to update subnet",
        )
        .with_request_id(&auth.request_id));
    }

    let row = sqlx::query(
        "SELECT id, cidr, name, vlan_id, location, description, gateway, created_at, updated_at
         FROM subnets WHERE id = ?",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, subnet_id = id, "Failed to fetch updated subnet");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to update subnet",
        )
        .with_request_id(&auth.request_id)
    })?;

    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "update_subnet",
            Some(&format!("subnet:{id}")),
            Some("subnet updated"),
            None,
            Some(&auth.request_id),
        )
        .await;

    Ok(Json(map_subnet_row(&row)))
}

/// Deletes subnet definition and clears associated mapping tags.
///
/// Parameters: `auth` - authenticated admin, `id` - subnet ID, `state` - app state.
/// Returns: HTTP 204 on success.
pub(crate) async fn delete_subnet(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let exists = sqlx::query("SELECT id FROM subnets WHERE id = ?")
        .bind(id)
        .fetch_optional(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, subnet_id = id, "Failed to query subnet");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to delete subnet",
            )
            .with_request_id(&auth.request_id)
        })?;
    if exists.is_none() {
        return Err(
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "Subnet not found")
                .with_request_id(&auth.request_id),
        );
    }

    sqlx::query("UPDATE mappings SET subnet_id = NULL WHERE subnet_id = ?")
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, subnet_id = id, "Failed to clear subnet references");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to delete subnet",
            )
            .with_request_id(&auth.request_id)
        })?;

    sqlx::query("DELETE FROM subnets WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, subnet_id = id, "Failed to delete subnet");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to delete subnet",
            )
            .with_request_id(&auth.request_id)
        })?;

    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "delete_subnet",
            Some(&format!("subnet:{id}")),
            None,
            None,
            Some(&auth.request_id),
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Returns subnet-aware mapping statistics.
///
/// Parameters: `auth` - authenticated principal, `state` - app state.
/// Returns: aggregate subnet statistics payload.
pub(crate) async fn subnet_stats(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let total_subnets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subnets")
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to count subnets");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to build subnet stats",
            )
            .with_request_id(&auth.request_id)
        })?;

    let total_tagged_mappings: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE subnet_id IS NOT NULL")
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to count tagged mappings");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to build subnet stats",
                )
                .with_request_id(&auth.request_id)
            })?;

    let untagged_mappings: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE subnet_id IS NULL")
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to count untagged mappings");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to build subnet stats",
                )
                .with_request_id(&auth.request_id)
            })?;

    let rows = sqlx::query(
        "SELECT s.id, s.name, s.cidr,
                SUM(CASE WHEN m.is_active = true THEN 1 ELSE 0 END) as active_mappings,
                COUNT(m.ip) as total_mappings
         FROM subnets s
         LEFT JOIN mappings m ON m.subnet_id = s.id
         GROUP BY s.id, s.name, s.cidr
         ORDER BY s.cidr ASC",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to compute per-subnet stats");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to build subnet stats",
        )
        .with_request_id(&auth.request_id)
    })?;

    let per_subnet = rows
        .into_iter()
        .map(|row| SubnetCount {
            id: row.try_get("id").unwrap_or_default(),
            name: row.try_get("name").unwrap_or_default(),
            cidr: row.try_get("cidr").unwrap_or_default(),
            active_mappings: row.try_get("active_mappings").unwrap_or(0),
            total_mappings: row.try_get("total_mappings").unwrap_or(0),
        })
        .collect::<Vec<SubnetCount>>();

    Ok(Json(SubnetStats {
        total_subnets,
        total_tagged_mappings,
        untagged_mappings,
        per_subnet,
    }))
}

/// Lists mappings assigned to a specific subnet.
///
/// Parameters: `auth` - authenticated principal, `id` - subnet ID, `q` - pagination params, `state` - app state.
/// Returns: paginated mappings for given subnet.
pub(crate) async fn subnet_mappings(
    auth: AuthUser,
    Path(id): Path<i64>,
    Query(q): Query<SubnetMappingsQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * per_page;

    let exists = sqlx::query("SELECT id FROM subnets WHERE id = ?")
        .bind(id)
        .fetch_optional(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, subnet_id = id, "Failed to query subnet for mappings");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to list subnet mappings",
            )
            .with_request_id(&auth.request_id)
        })?;
    if exists.is_none() {
        return Err(
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "Subnet not found")
                .with_request_id(&auth.request_id),
        );
    }

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE subnet_id = ?")
        .bind(id)
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, subnet_id = id, "Failed to count subnet mappings");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to list subnet mappings",
            )
            .with_request_id(&auth.request_id)
        })?;

    let rows = sqlx::query(
        "SELECT m.ip, m.user, m.source, m.last_seen, m.confidence, m.mac, m.is_active, m.vendor,
                m.subnet_id, s.name as subnet_name, d.hostname, m.device_type, m.multi_user,
                (SELECT GROUP_CONCAT(DISTINCT sess.user)
                 FROM ip_sessions sess
                 WHERE sess.ip = m.ip AND sess.is_active = 1) as session_users
         FROM mappings m
         LEFT JOIN subnets s ON m.subnet_id = s.id
         LEFT JOIN dns_cache d ON m.ip = d.ip
         WHERE m.subnet_id = ?
         ORDER BY m.last_seen DESC
         LIMIT ? OFFSET ?",
    )
    .bind(id)
    .bind(per_page)
    .bind(offset)
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, subnet_id = id, "Failed to fetch subnet mappings");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list subnet mappings",
        )
        .with_request_id(&auth.request_id)
    })?;

    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        let mapping = DeviceMapping::from_row(&row).map_err(|e| {
            warn!(error = %e, subnet_id = id, "Failed to decode subnet mapping row");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to list subnet mappings",
            )
            .with_request_id(&auth.request_id)
        })?;
        data.push(mapping);
    }

    Ok(Json(PaginatedSubnetMappings {
        data,
        total,
        page,
        per_page,
    }))
}
