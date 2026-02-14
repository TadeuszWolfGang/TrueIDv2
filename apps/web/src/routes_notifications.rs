//! Notification channel management API.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::Value;
use sqlx::Row;
use tracing::warn;
use trueid_common::notification::{ChannelConfig, ChannelResponse};

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::{routes_proxy, AppState};

/// Create/update payload for notification channel.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateChannelRequest {
    name: String,
    channel_type: String,
    enabled: Option<bool>,
    config: Value,
}

/// Delivery log entry returned by API.
#[derive(Debug, serde::Serialize)]
struct DeliveryEntry {
    id: i64,
    channel_id: i64,
    alert_history_id: Option<i64>,
    alert_rule_name: Option<String>,
    status: String,
    error_message: Option<String>,
    delivered_at: String,
}

/// Parses and validates channel config JSON against declared type.
///
/// Parameters: `channel_type` - normalized channel type, `config` - raw JSON config, `request_id` - request correlation id.
/// Returns: validated typed config.
fn parse_config(
    channel_type: &str,
    config: Value,
    request_id: &str,
) -> Result<ChannelConfig, ApiError> {
    let parsed = match channel_type {
        "email" => serde_json::from_value::<ChannelConfig>(serde_json::json!({
            "type": "email",
            "smtp_host": config.get("smtp_host").cloned().unwrap_or(Value::Null),
            "smtp_port": config.get("smtp_port").cloned().unwrap_or(Value::Null),
            "smtp_tls": config.get("smtp_tls").cloned().unwrap_or(Value::Bool(true)),
            "smtp_user": config.get("smtp_user").cloned().unwrap_or(Value::Null),
            "smtp_pass": config.get("smtp_pass").cloned().unwrap_or(Value::Null),
            "from_address": config.get("from_address").cloned().unwrap_or(Value::Null),
            "to_addresses": config.get("to_addresses").cloned().unwrap_or(Value::Array(Vec::new())),
            "subject_prefix": config.get("subject_prefix").cloned().unwrap_or(Value::Null),
        })),
        "slack" => serde_json::from_value::<ChannelConfig>(serde_json::json!({
            "type": "slack",
            "webhook_url": config.get("webhook_url").cloned().unwrap_or(Value::Null),
            "channel": config.get("channel").cloned().unwrap_or(Value::Null),
            "username": config.get("username").cloned().unwrap_or(Value::Null),
            "icon_emoji": config.get("icon_emoji").cloned().unwrap_or(Value::Null),
        })),
        "teams" => serde_json::from_value::<ChannelConfig>(serde_json::json!({
            "type": "teams",
            "webhook_url": config.get("webhook_url").cloned().unwrap_or(Value::Null),
        })),
        "webhook" => serde_json::from_value::<ChannelConfig>(serde_json::json!({
            "type": "webhook",
            "url": config.get("url").cloned().unwrap_or(Value::Null),
            "headers": config.get("headers").cloned().unwrap_or(Value::Null),
            "method": config.get("method").cloned().unwrap_or(Value::Null),
        })),
        _ => Err(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid channel_type",
        ))),
    }
    .map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Invalid config payload for channel_type",
        )
        .with_request_id(request_id)
    })?;

    match &parsed {
        ChannelConfig::Email {
            smtp_host,
            smtp_port,
            from_address,
            to_addresses,
            ..
        } => {
            if smtp_host.trim().is_empty() {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    error::INVALID_INPUT,
                    "smtp_host is required",
                )
                .with_request_id(request_id));
            }
            if ![25_u16, 465, 587, 2525].contains(smtp_port) {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    error::INVALID_INPUT,
                    "smtp_port must be one of 25, 465, 587, 2525",
                )
                .with_request_id(request_id));
            }
            if !is_valid_email(from_address) {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    error::INVALID_INPUT,
                    "from_address must be a valid email",
                )
                .with_request_id(request_id));
            }
            if to_addresses.is_empty() || !to_addresses.iter().all(|e| is_valid_email(e)) {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    error::INVALID_INPUT,
                    "to_addresses must contain valid email(s)",
                )
                .with_request_id(request_id));
            }
        }
        ChannelConfig::Slack { webhook_url, .. } => {
            if !webhook_url.starts_with("https://hooks.slack.com/") {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    error::INVALID_INPUT,
                    "Slack webhook_url must start with https://hooks.slack.com/",
                )
                .with_request_id(request_id));
            }
        }
        ChannelConfig::Teams { webhook_url } => {
            let ok = webhook_url.contains("webhook.office.com")
                || webhook_url.contains("logic.azure.com");
            if !ok {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    error::INVALID_INPUT,
                    "Teams webhook_url must contain webhook.office.com or logic.azure.com",
                )
                .with_request_id(request_id));
            }
        }
        ChannelConfig::Webhook { url, .. } => {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    error::INVALID_INPUT,
                    "Webhook url must start with http:// or https://",
                )
                .with_request_id(request_id));
            }
        }
    }

    Ok(parsed)
}

/// Basic email validator suitable for API input checks.
///
/// Parameters: `email` - candidate email address.
/// Returns: true if email has basic user@domain structure.
fn is_valid_email(email: &str) -> bool {
    let trimmed = email.trim();
    let at = trimmed.find('@');
    let dot = trimmed.rfind('.');
    matches!((at, dot), (Some(a), Some(d)) if a > 0 && d > a + 1 && d < trimmed.len() - 1)
}

/// Maps one DB row to external channel response.
///
/// Parameters: `row` - DB row.
/// Returns: channel response with secret-safe summary.
fn map_channel_row(row: &sqlx::sqlite::SqliteRow, summary: String) -> ChannelResponse {
    ChannelResponse {
        id: row.try_get("id").unwrap_or_default(),
        name: row.try_get("name").unwrap_or_default(),
        channel_type: row.try_get("channel_type").unwrap_or_default(),
        enabled: row.try_get("enabled").unwrap_or(true),
        config_summary: summary,
        created_at: row.try_get("created_at").unwrap_or_default(),
        updated_at: row.try_get("updated_at").unwrap_or_default(),
    }
}

/// Lists all configured notification channels.
///
/// Parameters: `auth` - authenticated admin, `state` - app state.
/// Returns: channel list with redacted summaries.
pub(crate) async fn list_channels(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = sqlx::query(
        "SELECT id, name, channel_type, enabled, config_enc, created_at, updated_at
         FROM notification_channels
         ORDER BY name ASC",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to list notification channels");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list notification channels",
        )
        .with_request_id(&auth.request_id)
    })?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let cfg_enc: String = row.try_get("config_enc").unwrap_or_default();
        let summary = db
            .decrypt_config_value(&cfg_enc)
            .ok()
            .and_then(|raw| serde_json::from_str::<ChannelConfig>(&raw).ok())
            .map(|cfg| cfg.summary())
            .unwrap_or_else(|| "Invalid or unavailable config".to_string());
        out.push(map_channel_row(&row, summary));
    }
    Ok(Json(out))
}

/// Creates a new notification channel.
///
/// Parameters: `auth` - authenticated admin, `state` - app state, `body` - create payload.
/// Returns: created channel descriptor.
pub(crate) async fn create_channel(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<CreateChannelRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "name cannot be empty",
        )
        .with_request_id(&auth.request_id));
    }
    if !matches!(
        body.channel_type.as_str(),
        "email" | "slack" | "teams" | "webhook"
    ) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "channel_type must be one of: email, slack, teams, webhook",
        )
        .with_request_id(&auth.request_id));
    }
    let cfg = parse_config(&body.channel_type, body.config, &auth.request_id)?;
    let cfg_raw = serde_json::to_string(&cfg).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to serialize channel config",
        )
        .with_request_id(&auth.request_id)
    })?;
    let cfg_enc = db.encrypt_config_value(&cfg_raw).map_err(|e| {
        warn!(error = %e, "Failed to encrypt channel config");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to encrypt channel config",
        )
        .with_request_id(&auth.request_id)
    })?;

    let insert = sqlx::query(
        "INSERT INTO notification_channels (name, channel_type, enabled, config_enc)
         VALUES (?, ?, ?, ?)",
    )
    .bind(name)
    .bind(&body.channel_type)
    .bind(body.enabled.unwrap_or(true))
    .bind(cfg_enc)
    .execute(db.pool())
    .await;
    let result = match insert {
        Ok(v) => v,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE") || msg.contains("unique") {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    error::CONFLICT,
                    "Channel name already exists",
                )
                .with_request_id(&auth.request_id));
            }
            warn!(error = %e, "Failed to create notification channel");
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to create notification channel",
            )
            .with_request_id(&auth.request_id));
        }
    };
    let id = result.last_insert_rowid();
    helpers::audit(
        db,
        &auth,
        "create_notification_channel",
        Some(&id.to_string()),
        Some(&format!("channel_type={}", body.channel_type)),
    )
    .await;

    let row = sqlx::query(
        "SELECT id, name, channel_type, enabled, created_at, updated_at
         FROM notification_channels WHERE id = ?",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, channel_id = id, "Failed to fetch created channel");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to create notification channel",
        )
        .with_request_id(&auth.request_id)
    })?;
    Ok((
        StatusCode::CREATED,
        Json(map_channel_row(&row, cfg.summary())),
    ))
}

/// Returns details of one notification channel.
///
/// Parameters: `auth` - authenticated admin, `id` - channel id, `state` - app state.
/// Returns: channel response.
pub(crate) async fn get_channel(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let row = sqlx::query(
        "SELECT id, name, channel_type, enabled, config_enc, created_at, updated_at
         FROM notification_channels WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, channel_id = id, "Failed to fetch channel");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to fetch notification channel",
        )
        .with_request_id(&auth.request_id)
    })?;
    let Some(row) = row else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "Notification channel not found",
        )
        .with_request_id(&auth.request_id));
    };
    let cfg_enc: String = row.try_get("config_enc").unwrap_or_default();
    let cfg = db
        .decrypt_config_value(&cfg_enc)
        .ok()
        .and_then(|raw| serde_json::from_str::<ChannelConfig>(&raw).ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to decode notification channel config",
            )
            .with_request_id(&auth.request_id)
        })?;
    Ok(Json(map_channel_row(&row, cfg.summary())))
}

/// Updates an existing notification channel.
///
/// Parameters: `auth` - authenticated admin, `id` - channel id, `state` - app state, `body` - update payload.
/// Returns: updated channel response.
pub(crate) async fn update_channel(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(body): Json<CreateChannelRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    if !matches!(
        body.channel_type.as_str(),
        "email" | "slack" | "teams" | "webhook"
    ) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "channel_type must be one of: email, slack, teams, webhook",
        )
        .with_request_id(&auth.request_id));
    }
    let cfg = parse_config(&body.channel_type, body.config, &auth.request_id)?;
    let cfg_raw = serde_json::to_string(&cfg).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to serialize channel config",
        )
        .with_request_id(&auth.request_id)
    })?;
    let cfg_enc = db.encrypt_config_value(&cfg_raw).map_err(|e| {
        warn!(error = %e, "Failed to encrypt channel config");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to encrypt channel config",
        )
        .with_request_id(&auth.request_id)
    })?;
    let result = sqlx::query(
        "UPDATE notification_channels
         SET name = ?, channel_type = ?, enabled = ?, config_enc = ?, updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(body.name.trim())
    .bind(&body.channel_type)
    .bind(body.enabled.unwrap_or(true))
    .bind(cfg_enc)
    .bind(id)
    .execute(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, channel_id = id, "Failed to update channel");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to update notification channel",
        )
        .with_request_id(&auth.request_id)
    })?;
    if result.rows_affected() == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "Notification channel not found",
        )
        .with_request_id(&auth.request_id));
    }

    helpers::audit(
        db,
        &auth,
        "update_notification_channel",
        Some(&id.to_string()),
        Some("channel updated"),
    )
    .await;

    let row = sqlx::query(
        "SELECT id, name, channel_type, enabled, created_at, updated_at
         FROM notification_channels WHERE id = ?",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, channel_id = id, "Failed to fetch updated channel");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to update notification channel",
        )
        .with_request_id(&auth.request_id)
    })?;
    Ok(Json(map_channel_row(&row, cfg.summary())))
}

/// Deletes a notification channel by id.
///
/// Parameters: `auth` - authenticated admin, `id` - channel id, `state` - app state.
/// Returns: no content on success.
pub(crate) async fn delete_channel(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let result = sqlx::query("DELETE FROM notification_channels WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, channel_id = id, "Failed to delete channel");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to delete notification channel",
            )
            .with_request_id(&auth.request_id)
        })?;
    if result.rows_affected() == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "Notification channel not found",
        )
        .with_request_id(&auth.request_id));
    }
    helpers::audit(
        db,
        &auth,
        "delete_notification_channel",
        Some(&id.to_string()),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Triggers a test notification for a given channel via engine admin API.
///
/// Parameters: `auth` - authenticated admin, `id` - channel id, `state` - app state.
/// Returns: success/failure JSON from engine.
pub(crate) async fn test_channel(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let path = format!("/engine/notifications/channels/{id}/test");
    let response = routes_proxy::proxy_to_engine(&state, reqwest::Method::POST, &path, None)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                error::SERVICE_UNAVAILABLE,
                "Engine test endpoint unavailable",
            )
            .with_request_id(&auth.request_id)
        })?;
    helpers::audit(
        db,
        &auth,
        "test_notification_channel",
        Some(&id.to_string()),
        None,
    )
    .await;
    Ok(response)
}

/// Returns delivery history for one channel.
///
/// Parameters: `auth` - authenticated admin, `id` - channel id, `state` - app state.
/// Returns: latest delivery rows for channel.
pub(crate) async fn channel_deliveries(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = sqlx::query(
        "SELECT d.id, d.channel_id, d.alert_history_id, a.rule_name, d.status, d.error_message, d.delivered_at
         FROM notification_deliveries d
         LEFT JOIN alert_history a ON a.id = d.alert_history_id
         WHERE d.channel_id = ?
         ORDER BY d.delivered_at DESC
         LIMIT 50",
    )
    .bind(id)
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, channel_id = id, "Failed to fetch notification deliveries");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to fetch notification deliveries",
        )
        .with_request_id(&auth.request_id)
    })?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(DeliveryEntry {
            id: row.try_get("id").unwrap_or_default(),
            channel_id: row.try_get("channel_id").unwrap_or_default(),
            alert_history_id: row.try_get("alert_history_id").ok(),
            alert_rule_name: row.try_get("rule_name").ok(),
            status: row
                .try_get("status")
                .unwrap_or_else(|_| "failed".to_string()),
            error_message: row.try_get("error_message").ok(),
            delivered_at: row.try_get("delivered_at").unwrap_or_default(),
        });
    }
    Ok(Json(out))
}
