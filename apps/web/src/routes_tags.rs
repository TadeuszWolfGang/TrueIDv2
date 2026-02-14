//! IP tag management endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tracing::warn;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;

/// IP tag response object.
#[derive(Debug, Serialize)]
struct IpTagDto {
    id: i64,
    ip: String,
    tag: String,
    color: String,
    created_by: Option<i64>,
    created_at: String,
}

/// Aggregated tag with number of associated IP addresses.
#[derive(Debug, Serialize)]
struct TagSummaryDto {
    tag: String,
    color: String,
    ip_count: i64,
}

/// Tag create request payload.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateTagRequest {
    ip: String,
    tag: String,
    color: Option<String>,
}

/// Tag search query.
#[derive(Debug, Deserialize)]
pub(crate) struct TagSearchQuery {
    tag: String,
}

/// Returns aggregated tag list with counts.
///
/// Parameters: `auth` - authenticated principal, `state` - app state.
/// Returns: distinct tags with IP counts.
pub(crate) async fn list_tags(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = sqlx::query(
        "SELECT tag, COALESCE(color, '#6b8579') as color, COUNT(DISTINCT ip) as ip_count
         FROM ip_tags
         GROUP BY tag, color
         ORDER BY ip_count DESC, tag ASC",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to list tags");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list tags",
        )
        .with_request_id(&auth.request_id)
    })?;

    let mut data: Vec<TagSummaryDto> = rows
        .iter()
        .map(|r| TagSummaryDto {
            tag: r.try_get("tag").unwrap_or_default(),
            color: r
                .try_get::<Option<String>, _>("color")
                .ok()
                .flatten()
                .unwrap_or_else(|| "#6b8579".to_string()),
            ip_count: r.try_get("ip_count").unwrap_or(0),
        })
        .collect();
    for (tag, color) in predefined_tags() {
        if !data.iter().any(|t| t.tag == *tag) {
            data.push(TagSummaryDto {
                tag: tag.to_string(),
                color: color.to_string(),
                ip_count: 0,
            });
        }
    }
    Ok(Json(serde_json::json!({ "data": data })))
}

/// Returns tags assigned to one IP.
///
/// Parameters: `auth` - authenticated principal, `state` - app state, `ip` - target IP.
/// Returns: list of tag rows for the IP.
pub(crate) async fn tags_for_ip(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Invalid IP format",
        )
        .with_request_id(&auth.request_id));
    }
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = sqlx::query(
        "SELECT id, ip, tag, COALESCE(color, '#6b8579') as color, created_by, created_at
         FROM ip_tags
         WHERE ip = ?
         ORDER BY tag ASC",
    )
    .bind(&ip)
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, %ip, "Failed to load tags for IP");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to load tags",
        )
        .with_request_id(&auth.request_id)
    })?;
    let data: Vec<IpTagDto> = rows
        .iter()
        .map(|r| IpTagDto {
            id: r.try_get("id").unwrap_or_default(),
            ip: r.try_get("ip").unwrap_or_default(),
            tag: r.try_get("tag").unwrap_or_default(),
            color: r
                .try_get::<Option<String>, _>("color")
                .ok()
                .flatten()
                .unwrap_or_else(|| "#6b8579".to_string()),
            created_by: r.try_get("created_by").ok(),
            created_at: r
                .try_get::<String, _>("created_at")
                .unwrap_or_else(|_| "-".to_string()),
        })
        .collect();
    Ok(Json(serde_json::json!({ "ip": ip, "data": data })))
}

/// Creates a new tag assignment for an IP.
///
/// Parameters: `auth` - authenticated principal, `state` - app state, `body` - create payload.
/// Returns: created tag row.
pub(crate) async fn create_tag(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<CreateTagRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let ip = body.ip.trim();
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Invalid IP format",
        )
        .with_request_id(&auth.request_id));
    }
    let tag = body.tag.trim().to_lowercase();
    if tag.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Tag must not be empty",
        )
        .with_request_id(&auth.request_id));
    }
    let color = sanitize_color(body.color.as_deref().unwrap_or("#6b8579"));
    let db = helpers::require_db(&state, &auth.request_id)?;
    let inserted = sqlx::query(
        "INSERT INTO ip_tags (ip, tag, color, created_by)
         VALUES (?, ?, ?, ?)",
    )
    .bind(ip)
    .bind(&tag)
    .bind(&color)
    .bind(auth.user_id)
    .execute(db.pool())
    .await;
    let insert = match inserted {
        Ok(v) => v,
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            if msg.contains("unique") {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    error::CONFLICT,
                    "Tag already exists for this IP",
                )
                .with_request_id(&auth.request_id));
            }
            warn!(error = %e, "Failed to create tag");
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to create tag",
            )
            .with_request_id(&auth.request_id));
        }
    };
    let id = insert.last_insert_rowid();
    let row = sqlx::query(
        "SELECT id, ip, tag, COALESCE(color, '#6b8579') as color, created_by, created_at
         FROM ip_tags
         WHERE id = ?",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, tag_id = id, "Failed to fetch created tag");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to create tag",
        )
        .with_request_id(&auth.request_id)
    })?;
    helpers::audit(
        db,
        &auth,
        "ip_tag_created",
        Some(&format!("tag:{id}")),
        Some(&format!("ip={ip},tag={tag}")),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(IpTagDto {
            id: row.try_get("id").unwrap_or_default(),
            ip: row.try_get("ip").unwrap_or_default(),
            tag: row.try_get("tag").unwrap_or_default(),
            color: row
                .try_get::<Option<String>, _>("color")
                .ok()
                .flatten()
                .unwrap_or_else(|| "#6b8579".to_string()),
            created_by: row.try_get("created_by").ok(),
            created_at: row
                .try_get::<String, _>("created_at")
                .unwrap_or_else(|_| "-".to_string()),
        }),
    ))
}

/// Deletes one tag assignment by id.
///
/// Parameters: `auth` - authenticated principal, `state` - app state, `id` - tag row id.
/// Returns: HTTP 200 when deleted.
pub(crate) async fn delete_tag(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let res = sqlx::query("DELETE FROM ip_tags WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, tag_id = id, "Failed to delete tag");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to delete tag",
            )
            .with_request_id(&auth.request_id)
        })?;
    if res.rows_affected() == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "Tag not found")
            .with_request_id(&auth.request_id));
    }
    helpers::audit(
        db,
        &auth,
        "ip_tag_deleted",
        Some(&format!("tag:{id}")),
        None,
    )
    .await;
    Ok(StatusCode::OK)
}

/// Searches IPs by exact tag label.
///
/// Parameters: `auth` - authenticated principal, `state` - app state, `query` - tag filter.
/// Returns: list of matching IP-tag rows.
pub(crate) async fn search_by_tag(
    auth: AuthUser,
    State(state): State<AppState>,
    Query(query): Query<TagSearchQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let tag = query.tag.trim().to_lowercase();
    if tag.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "tag query parameter is required",
        )
        .with_request_id(&auth.request_id));
    }
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = sqlx::query(
        "SELECT id, ip, tag, COALESCE(color, '#6b8579') as color, created_by, created_at
         FROM ip_tags
         WHERE lower(tag) = lower(?)
         ORDER BY ip ASC",
    )
    .bind(&tag)
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, tag = %tag, "Failed to search tags");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to search tags",
        )
        .with_request_id(&auth.request_id)
    })?;
    let data: Vec<IpTagDto> = rows
        .iter()
        .map(|r| IpTagDto {
            id: r.try_get("id").unwrap_or_default(),
            ip: r.try_get("ip").unwrap_or_default(),
            tag: r.try_get("tag").unwrap_or_default(),
            color: r
                .try_get::<Option<String>, _>("color")
                .ok()
                .flatten()
                .unwrap_or_else(|| "#6b8579".to_string()),
            created_by: r.try_get("created_by").ok(),
            created_at: r
                .try_get::<String, _>("created_at")
                .unwrap_or_else(|_| "-".to_string()),
        })
        .collect();
    Ok(Json(serde_json::json!({ "data": data })))
}

/// Sanitizes a hex color string and falls back to default.
///
/// Parameters: `value` - candidate color value.
/// Returns: normalized hex color.
fn sanitize_color(value: &str) -> String {
    let v = value.trim();
    if v.len() == 7 && v.starts_with('#') && v.chars().skip(1).all(|c| c.is_ascii_hexdigit()) {
        return v.to_ascii_lowercase();
    }
    "#6b8579".to_string()
}

/// Returns predefined tag labels and colors for UI defaults.
///
/// Returns: static slice of `(tag, color)` pairs.
fn predefined_tags() -> &'static [(&'static str, &'static str)] {
    &[
        ("server", "#3b82f6"),
        ("printer", "#22c55e"),
        ("camera", "#8b5cf6"),
        ("iot", "#f59e0b"),
        ("vip", "#d4af37"),
        ("quarantine", "#ef4444"),
    ]
}
