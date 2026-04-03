//! LDAP configuration and group enrichment endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tracing::warn;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::routes_proxy;
use crate::AppState;

/// LDAP configuration response (without password).
#[derive(Serialize)]
pub(crate) struct LdapConfigResponse {
    ldap_url: String,
    bind_dn: String,
    password_set: bool,
    base_dn: String,
    search_filter: String,
    sync_interval_secs: i64,
    enabled: bool,
    last_sync_at: Option<DateTime<Utc>>,
    last_sync_status: Option<String>,
    last_sync_count: i64,
    last_sync_error: Option<String>,
}

/// LDAP configuration update request.
#[derive(Deserialize)]
pub(crate) struct UpdateLdapConfigRequest {
    ldap_url: Option<String>,
    bind_dn: Option<String>,
    bind_password: Option<String>,
    base_dn: Option<String>,
    search_filter: Option<String>,
    sync_interval_secs: Option<i64>,
    enabled: Option<bool>,
}

/// Distinct LDAP group response row.
#[derive(Serialize)]
pub(crate) struct GroupRow {
    group_name: String,
}

/// LDAP group member response row.
#[derive(Serialize)]
pub(crate) struct GroupMemberRow {
    username: String,
    display_name: Option<String>,
    department: Option<String>,
}

/// User group response row.
#[derive(Serialize)]
pub(crate) struct UserGroupRow {
    group_name: String,
}

/// Validates LDAP filter syntax with a conservative parser.
///
/// Parameters: `filter` - LDAP filter string.
/// Returns: `true` when the filter is structurally valid.
fn is_valid_ldap_filter(filter: &str) -> bool {
    fn parse_filter_expr(bytes: &[u8], start: usize) -> Option<usize> {
        if *bytes.get(start)? != b'(' {
            return None;
        }
        let mut idx = start + 1;
        match *bytes.get(idx)? {
            b'&' | b'|' => {
                idx += 1;
                let mut count = 0usize;
                while bytes.get(idx) == Some(&b'(') {
                    idx = parse_filter_expr(bytes, idx)?;
                    count += 1;
                }
                if count == 0 {
                    return None;
                }
            }
            b'!' => {
                idx += 1;
                idx = parse_filter_expr(bytes, idx)?;
            }
            _ => {
                idx = parse_filter_item(bytes, idx)?;
            }
        }
        if *bytes.get(idx)? != b')' {
            return None;
        }
        Some(idx + 1)
    }

    fn parse_filter_item(bytes: &[u8], start: usize) -> Option<usize> {
        let mut idx = start;
        let mut eq_pos = None;
        while let Some(&ch) = bytes.get(idx) {
            match ch {
                b'(' | b')' => break,
                b'=' if eq_pos.is_none() => {
                    eq_pos = Some(idx);
                    idx += 1;
                }
                b'\\' => {
                    idx += 1;
                    bytes.get(idx)?;
                    idx += 1;
                }
                _ => idx += 1,
            }
        }
        let Some(eq_idx) = eq_pos else {
            return None;
        };
        if eq_idx == start {
            return None;
        }
        Some(idx)
    }

    let trimmed = filter.trim();
    if trimmed.is_empty() {
        return false;
    }
    matches!(parse_filter_expr(trimmed.as_bytes(), 0), Some(end) if end == trimmed.len())
}

/// Loads LDAP config row from database.
///
/// Parameters: `db` - database handle.
/// Returns: LDAP config response payload.
async fn load_ldap_config(db: &trueid_common::db::Db) -> Result<LdapConfigResponse, sqlx::Error> {
    let row = sqlx::query(
        "SELECT ldap_url, bind_dn, bind_password_enc, base_dn, search_filter, sync_interval_secs,
                enabled, last_sync_at, last_sync_status, last_sync_count, last_sync_error
         FROM ldap_config
         WHERE id = 1",
    )
    .fetch_one(db.pool())
    .await?;

    let password_set = row
        .try_get::<Option<String>, _>("bind_password_enc")
        .ok()
        .flatten()
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    Ok(LdapConfigResponse {
        ldap_url: row.try_get("ldap_url").unwrap_or_default(),
        bind_dn: row.try_get("bind_dn").unwrap_or_default(),
        password_set,
        base_dn: row.try_get("base_dn").unwrap_or_default(),
        search_filter: row
            .try_get("search_filter")
            .unwrap_or_else(|_| "(&(objectClass=user)(sAMAccountName=*))".to_string()),
        sync_interval_secs: row.try_get("sync_interval_secs").unwrap_or(300),
        enabled: row.try_get("enabled").unwrap_or(false),
        last_sync_at: row.try_get("last_sync_at").ok(),
        last_sync_status: row.try_get("last_sync_status").ok(),
        last_sync_count: row.try_get("last_sync_count").unwrap_or(0),
        last_sync_error: row.try_get("last_sync_error").ok(),
    })
}

/// Returns LDAP config without secret fields.
///
/// Parameters: `auth` - authenticated admin, `state` - app state.
/// Returns: LDAP configuration.
pub(crate) async fn get_ldap_config(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let cfg = load_ldap_config(db).await.map_err(|e| {
        warn!(error = %e, "Failed to load LDAP config");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to load LDAP config",
        )
        .with_request_id(&auth.request_id)
    })?;
    Ok(Json(cfg))
}

/// Updates LDAP configuration and optionally encrypted bind password.
///
/// Parameters: `auth` - authenticated admin, `state` - app state, `body` - partial config payload.
/// Returns: updated LDAP configuration.
pub(crate) async fn update_ldap_config(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<UpdateLdapConfigRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    if let Some(v) = body.sync_interval_secs {
        if !(60..=86_400).contains(&v) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "sync_interval_secs must be in range 60..86400",
            )
            .with_request_id(&auth.request_id));
        }
    }

    if let Some(ref v) = body.ldap_url {
        if v.trim().is_empty() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "ldap_url cannot be empty",
            )
            .with_request_id(&auth.request_id));
        }
    }
    if let Some(ref v) = body.bind_dn {
        if v.trim().is_empty() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "bind_dn cannot be empty",
            )
            .with_request_id(&auth.request_id));
        }
    }
    if let Some(ref v) = body.base_dn {
        if v.trim().is_empty() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "base_dn cannot be empty",
            )
            .with_request_id(&auth.request_id));
        }
    }
    if let Some(ref v) = body.search_filter {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "search_filter cannot be empty",
            )
            .with_request_id(&auth.request_id));
        }
        if !is_valid_ldap_filter(trimmed) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "search_filter is not a valid LDAP filter",
            )
            .with_request_id(&auth.request_id));
        }
    }

    let encrypted_password = match body.bind_password.as_deref() {
        Some(p) if !p.trim().is_empty() => {
            Some(db.encrypt_config_value(p.trim()).map_err(|e| {
                warn!(error = %e, "Failed to encrypt LDAP bind password");
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    error::INVALID_INPUT,
                    "Cannot encrypt LDAP password. Check CONFIG_ENCRYPTION_KEY",
                )
                .with_request_id(&auth.request_id)
            })?)
        }
        _ => None,
    };

    sqlx::query(
        "UPDATE ldap_config
         SET ldap_url = COALESCE(?, ldap_url),
             bind_dn = COALESCE(?, bind_dn),
             bind_password_enc = COALESCE(?, bind_password_enc),
             base_dn = COALESCE(?, base_dn),
             search_filter = COALESCE(?, search_filter),
             sync_interval_secs = COALESCE(?, sync_interval_secs),
             enabled = COALESCE(?, enabled),
             updated_at = datetime('now')
         WHERE id = 1",
    )
    .bind(body.ldap_url.as_deref().map(str::trim))
    .bind(body.bind_dn.as_deref().map(str::trim))
    .bind(encrypted_password)
    .bind(body.base_dn.as_deref().map(str::trim))
    .bind(body.search_filter.as_deref().map(str::trim))
    .bind(body.sync_interval_secs)
    .bind(body.enabled)
    .execute(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to update LDAP config");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to update LDAP config",
        )
        .with_request_id(&auth.request_id)
    })?;

    helpers::audit(db, &auth, "ldap_config_update", Some("ldap_config"), None).await;

    get_ldap_config(auth, State(state)).await
}

/// Triggers immediate LDAP sync through engine admin API.
///
/// Parameters: `auth` - authenticated admin, `state` - app state.
/// Returns: sync trigger status from engine.
pub(crate) async fn force_ldap_sync(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let res =
        routes_proxy::proxy_to_engine(&state, reqwest::Method::POST, "/engine/ldap/sync", None)
            .await
            .map_err(|_| {
                ApiError::new(
                    StatusCode::BAD_GATEWAY,
                    error::INTERNAL_ERROR,
                    "Failed to trigger LDAP sync",
                )
                .with_request_id(&auth.request_id)
            })?;
    helpers::audit(db, &auth, "ldap_force_sync", Some("ldap_config"), None).await;
    Ok(res)
}

/// Lists distinct LDAP groups.
///
/// Parameters: `auth` - authenticated user, `state` - app state.
/// Returns: distinct group list.
pub(crate) async fn list_groups(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = sqlx::query("SELECT DISTINCT group_name FROM user_groups ORDER BY group_name ASC")
        .fetch_all(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to list LDAP groups");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to list LDAP groups",
            )
            .with_request_id(&auth.request_id)
        })?;
    let data = rows
        .into_iter()
        .map(|r| GroupRow {
            group_name: r.try_get("group_name").unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    Ok(Json(data))
}

/// Lists members of a specific LDAP group.
///
/// Parameters: `auth` - authenticated user, `group` - group name, `state` - app state.
/// Returns: group members.
pub(crate) async fn group_members(
    auth: AuthUser,
    Path(group): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = sqlx::query(
        "SELECT username, display_name, department
         FROM user_groups
         WHERE group_name = ?
         ORDER BY username ASC",
    )
    .bind(group)
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to list LDAP group members");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list LDAP group members",
        )
        .with_request_id(&auth.request_id)
    })?;
    let data = rows
        .into_iter()
        .map(|r| GroupMemberRow {
            username: r.try_get("username").unwrap_or_default(),
            display_name: r.try_get("display_name").ok(),
            department: r.try_get("department").ok(),
        })
        .collect::<Vec<_>>();
    Ok(Json(data))
}

/// Lists LDAP groups assigned to a user.
///
/// Parameters: `auth` - authenticated user, `username` - account name, `state` - app state.
/// Returns: user group list.
pub(crate) async fn user_groups(
    auth: AuthUser,
    Path(username): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = sqlx::query(
        "SELECT group_name
         FROM user_groups
         WHERE lower(username) = lower(?)
         ORDER BY group_name ASC",
    )
    .bind(username)
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to list user LDAP groups");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list user LDAP groups",
        )
        .with_request_id(&auth.request_id)
    })?;
    let data = rows
        .into_iter()
        .map(|r| UserGroupRow {
            group_name: r.try_get("group_name").unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    Ok(Json(data))
}

#[cfg(test)]
mod tests {
    use super::is_valid_ldap_filter;

    #[test]
    fn test_is_valid_ldap_filter_accepts_common_filters() {
        assert!(is_valid_ldap_filter(
            "(&(objectClass=user)(sAMAccountName=*))"
        ));
        assert!(is_valid_ldap_filter(
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        ));
    }

    #[test]
    fn test_is_valid_ldap_filter_rejects_broken_syntax() {
        assert!(!is_valid_ldap_filter(""));
        assert!(!is_valid_ldap_filter("(uid=test"));
        assert!(!is_valid_ldap_filter("(|(uid=*)"));
        assert!(!is_valid_ldap_filter("()"));
    }
}
