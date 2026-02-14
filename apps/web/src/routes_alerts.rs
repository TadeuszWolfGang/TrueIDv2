//! Alert rule management and alert history endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::{HashMap, HashSet};
use tracing::warn;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;

/// Alert rule database record.
#[derive(Debug, Clone, Serialize)]
pub struct AlertRuleRecord {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub rule_type: String,
    pub severity: String,
    pub conditions: Option<String>,
    pub action_webhook_url: Option<String>,
    pub action_webhook_headers: Option<String>,
    pub action_log: bool,
    pub cooldown_seconds: i64,
    pub channels: Vec<RuleChannelInfo>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Notification channel linked to a rule.
#[derive(Debug, Clone, Serialize)]
pub struct RuleChannelInfo {
    pub id: i64,
    pub name: String,
    pub channel_type: String,
}

/// Alert history row returned by API.
#[derive(Debug, Clone, Serialize)]
pub struct AlertHistoryRecord {
    pub id: i64,
    pub rule_id: i64,
    pub rule_name: String,
    pub rule_type: String,
    pub severity: String,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub user_name: Option<String>,
    pub source: Option<String>,
    pub details: Option<String>,
    pub webhook_status: Option<String>,
    pub webhook_response: Option<String>,
    pub fired_at: DateTime<Utc>,
}

/// Response wrapper for rules listing.
#[derive(Debug, Serialize)]
struct RulesResponse {
    rules: Vec<AlertRuleRecord>,
}

/// Create alert rule payload.
#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    pub rule_type: String,
    pub severity: String,
    pub conditions: Option<String>,
    pub action_webhook_url: Option<String>,
    pub action_webhook_headers: Option<String>,
    pub action_log: bool,
    pub cooldown_seconds: i64,
    pub channel_ids: Option<Vec<i64>>,
}

/// Partial update payload for alert rule.
#[derive(Debug, Deserialize)]
pub struct UpdateRuleRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub rule_type: Option<String>,
    pub severity: Option<String>,
    pub conditions: Option<String>,
    pub action_webhook_url: Option<String>,
    pub action_webhook_headers: Option<String>,
    pub action_log: Option<bool>,
    pub cooldown_seconds: Option<i64>,
    pub channel_ids: Option<Vec<i64>>,
}

/// Query parameters for alert history listing.
#[derive(Debug, Deserialize)]
pub struct AlertHistoryQuery {
    pub rule_id: Option<i64>,
    pub severity: Option<String>,
    pub rule_type: Option<String>,
    pub ip: Option<String>,
    #[serde(rename = "from")]
    pub from_ts: Option<String>,
    #[serde(rename = "to")]
    pub to_ts: Option<String>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// Paginated history response.
#[derive(Debug, Serialize)]
struct AlertHistoryResponse {
    data: Vec<AlertHistoryRecord>,
    total: i64,
    page: u32,
    limit: u32,
}

/// Alert statistics response.
#[derive(Debug, Serialize)]
struct AlertStatsResponse {
    total_rules: i64,
    enabled_rules: i64,
    total_fired_24h: i64,
    by_severity_24h: HashMap<String, i64>,
    by_type_24h: HashMap<String, i64>,
    webhook_success_rate_24h: f64,
}

/// Dynamic SQL bind parameter.
#[derive(Debug, Clone)]
enum BindParam {
    Text(String),
    I64(i64),
    Bool(bool),
    DateTime(DateTime<Utc>),
}

const RULE_TYPES: [&str; 5] = [
    "new_mac",
    "ip_conflict",
    "user_change",
    "new_subnet",
    "source_down",
];
const SEVERITIES: [&str; 3] = ["info", "warning", "critical"];

/// Parses RFC3339 or naive datetime string into UTC timestamp.
///
/// Parameters: `raw` - datetime string from query parameter.
/// Returns: parsed UTC datetime or `None` for unsupported format.
fn parse_datetime(raw: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S") {
        return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S") {
        return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
    }
    None
}

/// Parses optional datetime parameter with API-style validation errors.
///
/// Parameters: `raw` - optional datetime string, `field_name` - query field name, `request_id` - request correlation ID.
/// Returns: parsed optional UTC datetime.
fn parse_datetime_param(
    raw: &Option<String>,
    field_name: &str,
    request_id: &str,
) -> Result<Option<DateTime<Utc>>, ApiError> {
    match raw {
        Some(value) => parse_datetime(value).map(Some).ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                &format!("Invalid datetime for '{field_name}'"),
            )
            .with_request_id(request_id)
        }),
        None => Ok(None),
    }
}

/// Applies dynamic bind parameters to a SQLx query.
///
/// Parameters: `query` - SQL query object, `binds` - bind values.
/// Returns: query with binds attached.
fn apply_binds<'q>(
    mut query: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    binds: &'q [BindParam],
) -> sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    for bind in binds {
        query = match bind {
            BindParam::Text(v) => query.bind(v),
            BindParam::I64(v) => query.bind(v),
            BindParam::Bool(v) => query.bind(v),
            BindParam::DateTime(v) => query.bind(v),
        };
    }
    query
}

/// Validates rule type, severity, cooldown and webhook URL.
///
/// Parameters: `name` - rule name, `rule_type` - rule type, `severity` - severity, `cooldown_seconds` - cooldown, `webhook` - webhook URL.
/// Returns: validation result.
fn validate_rule_values(
    name: &str,
    rule_type: &str,
    severity: &str,
    cooldown_seconds: i64,
    webhook: Option<&str>,
    request_id: &str,
) -> Result<(), ApiError> {
    if name.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Rule name cannot be empty",
        )
        .with_request_id(request_id));
    }
    if !RULE_TYPES.contains(&rule_type) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Invalid rule_type",
        )
        .with_request_id(request_id));
    }
    if !SEVERITIES.contains(&severity) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Invalid severity",
        )
        .with_request_id(request_id));
    }
    if !(0..=86_400).contains(&cooldown_seconds) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "cooldown_seconds must be in 0..=86400",
        )
        .with_request_id(request_id));
    }
    if let Some(url) = webhook {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "action_webhook_url must start with http:// or https://",
            )
            .with_request_id(request_id));
        }
    }
    Ok(())
}

/// Maps DB row into alert rule DTO.
///
/// Parameters: `row` - SQLx row.
/// Returns: parsed alert rule.
fn map_rule_row(row: &sqlx::sqlite::SqliteRow) -> AlertRuleRecord {
    AlertRuleRecord {
        id: row.try_get("id").unwrap_or(0),
        name: row.try_get("name").unwrap_or_default(),
        enabled: row.try_get("enabled").unwrap_or(false),
        rule_type: row.try_get("rule_type").unwrap_or_default(),
        severity: row
            .try_get("severity")
            .unwrap_or_else(|_| "warning".to_string()),
        conditions: row.try_get("conditions").ok(),
        action_webhook_url: row.try_get("action_webhook_url").ok(),
        action_webhook_headers: row.try_get("action_webhook_headers").ok(),
        action_log: row.try_get("action_log").unwrap_or(true),
        cooldown_seconds: row.try_get("cooldown_seconds").unwrap_or(300),
        channels: Vec::new(),
        created_at: row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        updated_at: row.try_get("updated_at").unwrap_or_else(|_| Utc::now()),
    }
}

/// Loads notification channel links for one or more rule IDs.
///
/// Parameters: `db` - database handle, `rule_ids` - list of rule IDs.
/// Returns: map of `rule_id -> channels`.
async fn load_rule_channels(
    db: &trueid_common::db::Db,
    rule_ids: &[i64],
) -> Result<HashMap<i64, Vec<RuleChannelInfo>>, sqlx::Error> {
    if rule_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = std::iter::repeat_n("?", rule_ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT arc.rule_id, nc.id, nc.name, nc.channel_type
         FROM alert_rule_channels arc
         JOIN notification_channels nc ON nc.id = arc.channel_id
         WHERE arc.rule_id IN ({placeholders})
         ORDER BY nc.name ASC"
    );
    let mut q = sqlx::query(&sql);
    for id in rule_ids {
        q = q.bind(*id);
    }
    let rows = q.fetch_all(db.pool()).await?;
    let mut out: HashMap<i64, Vec<RuleChannelInfo>> = HashMap::new();
    for row in rows {
        let rid: i64 = row.try_get("rule_id").unwrap_or_default();
        out.entry(rid).or_default().push(RuleChannelInfo {
            id: row.try_get("id").unwrap_or_default(),
            name: row.try_get("name").unwrap_or_default(),
            channel_type: row.try_get("channel_type").unwrap_or_default(),
        });
    }
    Ok(out)
}

/// Replaces rule-to-channel links with the provided channel IDs.
///
/// Parameters: `db` - database handle, `rule_id` - alert rule id, `channel_ids` - selected channels, `request_id` - request id.
/// Returns: success or API error on invalid channel ID.
async fn set_rule_channels(
    db: &trueid_common::db::Db,
    rule_id: i64,
    channel_ids: &[i64],
    request_id: &str,
) -> Result<(), ApiError> {
    let unique_ids = channel_ids
        .iter()
        .copied()
        .filter(|id| *id > 0)
        .collect::<HashSet<_>>();
    let mut tx = db.pool().begin().await.map_err(|e| {
        warn!(error = %e, rule_id, "Failed to start rule-channel transaction");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to save alert rule channels",
        )
        .with_request_id(request_id)
    })?;
    sqlx::query("DELETE FROM alert_rule_channels WHERE rule_id = ?")
        .bind(rule_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            warn!(error = %e, rule_id, "Failed to clear rule channels");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to save alert rule channels",
            )
            .with_request_id(request_id)
        })?;
    for channel_id in unique_ids {
        let exists: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM notification_channels WHERE id = ?")
                .bind(channel_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| {
                    warn!(error = %e, channel_id, "Failed to validate notification channel");
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        error::INTERNAL_ERROR,
                        "Failed to save alert rule channels",
                    )
                    .with_request_id(request_id)
                })?;
        if exists == 0 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "One or more channel_ids do not exist",
            )
            .with_request_id(request_id));
        }
        sqlx::query("INSERT INTO alert_rule_channels (rule_id, channel_id) VALUES (?, ?)")
            .bind(rule_id)
            .bind(channel_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                warn!(error = %e, rule_id, channel_id, "Failed to insert alert rule channel");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to save alert rule channels",
                )
                .with_request_id(request_id)
            })?;
    }
    tx.commit().await.map_err(|e| {
        warn!(error = %e, rule_id, "Failed to commit rule-channel transaction");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to save alert rule channels",
        )
        .with_request_id(request_id)
    })?;
    Ok(())
}

/// Lists all alert rules.
///
/// Parameters: `auth` - authenticated admin, `state` - app state.
/// Returns: rule list response.
pub async fn list_rules(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let rows = sqlx::query(
        "SELECT id, name, enabled, rule_type, severity, conditions,
                action_webhook_url, action_webhook_headers, action_log,
                cooldown_seconds, created_at, updated_at
         FROM alert_rules
         ORDER BY id ASC",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to list alert rules");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list alert rules",
        )
        .with_request_id(&auth.request_id)
    })?;

    let mut rules: Vec<AlertRuleRecord> = rows.iter().map(map_rule_row).collect();
    let rule_ids = rules.iter().map(|r| r.id).collect::<Vec<_>>();
    let channels_map = load_rule_channels(db, &rule_ids).await.map_err(|e| {
        warn!(error = %e, "Failed to load alert rule channels");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list alert rules",
        )
        .with_request_id(&auth.request_id)
    })?;
    for rule in &mut rules {
        rule.channels = channels_map.get(&rule.id).cloned().unwrap_or_default();
    }
    Ok(Json(RulesResponse { rules }))
}

/// Creates a new alert rule.
///
/// Parameters: `auth` - authenticated admin, `state` - app state, `body` - create payload.
/// Returns: created rule record.
pub async fn create_rule(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<CreateRuleRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    validate_rule_values(
        &body.name,
        &body.rule_type,
        &body.severity,
        body.cooldown_seconds,
        body.action_webhook_url.as_deref(),
        &auth.request_id,
    )?;

    let insert = sqlx::query(
        "INSERT INTO alert_rules (
            name, enabled, rule_type, severity, conditions, action_webhook_url,
            action_webhook_headers, action_log, cooldown_seconds
        ) VALUES (?, true, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(body.name.trim())
    .bind(&body.rule_type)
    .bind(&body.severity)
    .bind(body.conditions.clone())
    .bind(body.action_webhook_url.clone())
    .bind(body.action_webhook_headers.clone())
    .bind(body.action_log)
    .bind(body.cooldown_seconds)
    .execute(db.pool())
    .await;

    let result = match insert {
        Ok(r) => r,
        Err(e) => {
            let message = e.to_string();
            if message.contains("UNIQUE") || message.contains("unique") {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    error::CONFLICT,
                    "Rule name already exists",
                )
                .with_request_id(&auth.request_id));
            }
            warn!(error = %e, "Failed to create alert rule");
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to create alert rule",
            )
            .with_request_id(&auth.request_id));
        }
    };

    let id = result.last_insert_rowid();
    set_rule_channels(
        db,
        id,
        body.channel_ids.as_deref().unwrap_or(&[]),
        &auth.request_id,
    )
    .await?;
    let row = sqlx::query(
        "SELECT id, name, enabled, rule_type, severity, conditions,
                action_webhook_url, action_webhook_headers, action_log,
                cooldown_seconds, created_at, updated_at
         FROM alert_rules
         WHERE id = ?",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, rule_id = id, "Failed to fetch created alert rule");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to create alert rule",
        )
        .with_request_id(&auth.request_id)
    })?;
    let mut created = map_rule_row(&row);
    let channels_map = load_rule_channels(db, &[id]).await.map_err(|e| {
        warn!(error = %e, rule_id = id, "Failed to load created rule channels");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to create alert rule",
        )
        .with_request_id(&auth.request_id)
    })?;
    created.channels = channels_map.get(&id).cloned().unwrap_or_default();

    let target_id = id.to_string();
    let details = format!(
        "rule_type={}, severity={}",
        created.rule_type, created.severity
    );
    helpers::audit(
        db,
        &auth,
        "create_alert_rule",
        Some(&target_id),
        Some(&details),
    )
    .await;

    Ok((StatusCode::CREATED, Json(created)))
}

/// Updates an existing alert rule.
///
/// Parameters: `auth` - authenticated admin, `id` - rule ID, `state` - app state, `body` - partial update payload.
/// Returns: updated rule record.
pub async fn update_rule(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(body): Json<UpdateRuleRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let requested_channel_ids = body.channel_ids.clone();

    let existing = sqlx::query(
        "SELECT id, name, enabled, rule_type, severity, conditions,
                action_webhook_url, action_webhook_headers, action_log,
                cooldown_seconds, created_at, updated_at
         FROM alert_rules
         WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, rule_id = id, "Failed to query alert rule for update");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to update alert rule",
        )
        .with_request_id(&auth.request_id)
    })?;
    let Some(existing_row) = existing else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "Alert rule not found",
        )
        .with_request_id(&auth.request_id));
    };

    let current_name: String = existing_row.try_get("name").unwrap_or_default();
    let current_rule_type: String = existing_row.try_get("rule_type").unwrap_or_default();
    let current_severity: String = existing_row
        .try_get("severity")
        .unwrap_or_else(|_| "warning".to_string());
    let current_cooldown: i64 = existing_row.try_get("cooldown_seconds").unwrap_or(300);
    let current_webhook: Option<String> = existing_row.try_get("action_webhook_url").ok();

    let next_name = body
        .name
        .as_deref()
        .unwrap_or(current_name.as_str())
        .to_string();
    let next_rule_type = body
        .rule_type
        .as_deref()
        .unwrap_or(current_rule_type.as_str())
        .to_string();
    let next_severity = body
        .severity
        .as_deref()
        .unwrap_or(current_severity.as_str())
        .to_string();
    let next_cooldown = body.cooldown_seconds.unwrap_or(current_cooldown);
    let next_webhook = body
        .action_webhook_url
        .as_deref()
        .map(|v| v.to_string())
        .or(current_webhook.clone());

    validate_rule_values(
        &next_name,
        &next_rule_type,
        &next_severity,
        next_cooldown,
        next_webhook.as_deref(),
        &auth.request_id,
    )?;

    let mut sets = Vec::<String>::new();
    let mut binds = Vec::<BindParam>::new();

    if let Some(v) = body.name {
        sets.push("name = ?".to_string());
        binds.push(BindParam::Text(v));
    }
    if let Some(v) = body.enabled {
        sets.push("enabled = ?".to_string());
        binds.push(BindParam::Bool(v));
    }
    if let Some(v) = body.rule_type {
        sets.push("rule_type = ?".to_string());
        binds.push(BindParam::Text(v));
    }
    if let Some(v) = body.severity {
        sets.push("severity = ?".to_string());
        binds.push(BindParam::Text(v));
    }
    if let Some(v) = body.conditions {
        sets.push("conditions = ?".to_string());
        binds.push(BindParam::Text(v));
    }
    if let Some(v) = body.action_webhook_url {
        sets.push("action_webhook_url = ?".to_string());
        binds.push(BindParam::Text(v));
    }
    if let Some(v) = body.action_webhook_headers {
        sets.push("action_webhook_headers = ?".to_string());
        binds.push(BindParam::Text(v));
    }
    if let Some(v) = body.action_log {
        sets.push("action_log = ?".to_string());
        binds.push(BindParam::Bool(v));
    }
    if let Some(v) = body.cooldown_seconds {
        sets.push("cooldown_seconds = ?".to_string());
        binds.push(BindParam::I64(v));
    }
    sets.push("updated_at = datetime('now')".to_string());

    if sets.len() == 1 && requested_channel_ids.is_none() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "No fields to update",
        )
        .with_request_id(&auth.request_id));
    }

    let sql = format!("UPDATE alert_rules SET {} WHERE id = ?", sets.join(", "));
    binds.push(BindParam::I64(id));
    apply_binds(sqlx::query(&sql), &binds)
        .execute(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, rule_id = id, "Failed to update alert rule");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to update alert rule",
            )
            .with_request_id(&auth.request_id)
        })?;
    if let Some(channel_ids) = requested_channel_ids {
        set_rule_channels(db, id, &channel_ids, &auth.request_id).await?;
    }

    let row = sqlx::query(
        "SELECT id, name, enabled, rule_type, severity, conditions,
                action_webhook_url, action_webhook_headers, action_log,
                cooldown_seconds, created_at, updated_at
         FROM alert_rules
         WHERE id = ?",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, rule_id = id, "Failed to fetch updated alert rule");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to update alert rule",
        )
        .with_request_id(&auth.request_id)
    })?;
    let mut updated = map_rule_row(&row);
    let channels_map = load_rule_channels(db, &[id]).await.map_err(|e| {
        warn!(error = %e, rule_id = id, "Failed to load updated rule channels");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to update alert rule",
        )
        .with_request_id(&auth.request_id)
    })?;
    updated.channels = channels_map.get(&id).cloned().unwrap_or_default();

    let target_id = id.to_string();
    helpers::audit(
        db,
        &auth,
        "update_alert_rule",
        Some(&target_id),
        Some("rule updated"),
    )
    .await;

    Ok(Json(updated))
}

/// Deletes an alert rule by ID.
///
/// Parameters: `auth` - authenticated admin, `id` - rule ID, `state` - app state.
/// Returns: empty success body.
pub async fn delete_rule(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let res = sqlx::query("DELETE FROM alert_rules WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, rule_id = id, "Failed to delete alert rule");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to delete alert rule",
            )
            .with_request_id(&auth.request_id)
        })?;
    if res.rows_affected() == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            error::NOT_FOUND,
            "Alert rule not found",
        )
        .with_request_id(&auth.request_id));
    }

    let target_id = id.to_string();
    helpers::audit(db, &auth, "delete_alert_rule", Some(&target_id), None).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Lists alert firing history with pagination and filters.
///
/// Parameters: `auth` - authenticated principal, `q` - history query, `state` - app state.
/// Returns: paginated history records.
pub async fn alert_history(
    auth: AuthUser,
    Query(q): Query<AlertHistoryQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let from_dt = parse_datetime_param(&q.from_ts, "from", &auth.request_id)?;
    let to_dt = parse_datetime_param(&q.to_ts, "to", &auth.request_id)?;
    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = i64::from((page - 1) * limit);

    let mut conditions = Vec::<String>::new();
    let mut binds = Vec::<BindParam>::new();
    if let Some(rule_id) = q.rule_id {
        conditions.push("rule_id = ?".to_string());
        binds.push(BindParam::I64(rule_id));
    }
    if let Some(severity) = &q.severity {
        conditions.push("severity = ?".to_string());
        binds.push(BindParam::Text(severity.clone()));
    }
    if let Some(rule_type) = &q.rule_type {
        conditions.push("rule_type = ?".to_string());
        binds.push(BindParam::Text(rule_type.clone()));
    }
    if let Some(ip) = &q.ip {
        conditions.push("ip = ?".to_string());
        binds.push(BindParam::Text(ip.clone()));
    }
    if let Some(from) = from_dt {
        conditions.push("fired_at >= ?".to_string());
        binds.push(BindParam::DateTime(from));
    }
    if let Some(to) = to_dt {
        conditions.push("fired_at <= ?".to_string());
        binds.push(BindParam::DateTime(to));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };
    let count_sql = format!("SELECT COUNT(*) as c FROM alert_history {where_clause}");
    let total_row = apply_binds(sqlx::query(&count_sql), &binds)
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to count alert history");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to query alert history",
            )
            .with_request_id(&auth.request_id)
        })?;
    let total: i64 = total_row.try_get("c").unwrap_or(0);

    let mut data_binds = binds.clone();
    data_binds.push(BindParam::I64(i64::from(limit)));
    data_binds.push(BindParam::I64(offset));
    let data_sql = format!(
        "SELECT id, rule_id, rule_name, rule_type, severity, ip, mac, user_name, source,
                details, webhook_status, webhook_response, fired_at
         FROM alert_history
         {where_clause}
         ORDER BY fired_at DESC
         LIMIT ? OFFSET ?"
    );
    let rows = apply_binds(sqlx::query(&data_sql), &data_binds)
        .fetch_all(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to list alert history");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to query alert history",
            )
            .with_request_id(&auth.request_id)
        })?;

    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        data.push(AlertHistoryRecord {
            id: row.try_get("id").unwrap_or(0),
            rule_id: row.try_get("rule_id").unwrap_or(0),
            rule_name: row.try_get("rule_name").unwrap_or_default(),
            rule_type: row.try_get("rule_type").unwrap_or_default(),
            severity: row.try_get("severity").unwrap_or_default(),
            ip: row.try_get("ip").ok(),
            mac: row.try_get("mac").ok(),
            user_name: row.try_get("user_name").ok(),
            source: row.try_get("source").ok(),
            details: row.try_get("details").ok(),
            webhook_status: row.try_get("webhook_status").ok(),
            webhook_response: row.try_get("webhook_response").ok(),
            fired_at: row.try_get("fired_at").unwrap_or_else(|_| Utc::now()),
        });
    }

    Ok(Json(AlertHistoryResponse {
        data,
        total,
        page,
        limit,
    }))
}

/// Returns alert summary statistics for the last 24h.
///
/// Parameters: `auth` - authenticated principal, `state` - app state.
/// Returns: alert statistics payload.
pub async fn alert_stats(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let total_rules: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alert_rules")
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to query alert stats total_rules");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to query alert stats",
            )
            .with_request_id(&auth.request_id)
        })?;
    let enabled_rules: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM alert_rules WHERE enabled = true")
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to query alert stats enabled_rules");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to query alert stats",
                )
                .with_request_id(&auth.request_id)
            })?;
    let total_fired_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alert_history WHERE fired_at > datetime('now', '-24 hours')",
    )
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to query alert stats total_fired_24h");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query alert stats",
        )
        .with_request_id(&auth.request_id)
    })?;

    let severity_rows = sqlx::query(
        "SELECT severity, COUNT(*) as c
         FROM alert_history
         WHERE fired_at > datetime('now', '-24 hours')
         GROUP BY severity",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to query alert stats by severity");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query alert stats",
        )
        .with_request_id(&auth.request_id)
    })?;
    let mut by_severity_24h = HashMap::new();
    for row in severity_rows {
        let key: String = row.try_get("severity").unwrap_or_default();
        let value: i64 = row.try_get("c").unwrap_or(0);
        by_severity_24h.insert(key, value);
    }

    let type_rows = sqlx::query(
        "SELECT rule_type, COUNT(*) as c
         FROM alert_history
         WHERE fired_at > datetime('now', '-24 hours')
         GROUP BY rule_type",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to query alert stats by type");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query alert stats",
        )
        .with_request_id(&auth.request_id)
    })?;
    let mut by_type_24h = HashMap::new();
    for row in type_rows {
        let key: String = row.try_get("rule_type").unwrap_or_default();
        let value: i64 = row.try_get("c").unwrap_or(0);
        by_type_24h.insert(key, value);
    }

    let webhook_stats_row = sqlx::query(
        "SELECT
            SUM(CASE WHEN webhook_status = 'sent' THEN 1 ELSE 0 END) as sent_count,
            SUM(CASE WHEN webhook_status = 'failed' THEN 1 ELSE 0 END) as failed_count
         FROM alert_history
         WHERE fired_at > datetime('now', '-24 hours')",
    )
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to query alert stats webhook success");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to query alert stats",
        )
        .with_request_id(&auth.request_id)
    })?;
    let sent_count: i64 = webhook_stats_row.try_get("sent_count").unwrap_or(0);
    let failed_count: i64 = webhook_stats_row.try_get("failed_count").unwrap_or(0);
    let total_webhook_attempts = sent_count + failed_count;
    let webhook_success_rate_24h = if total_webhook_attempts > 0 {
        sent_count as f64 / total_webhook_attempts as f64
    } else {
        0.0
    };

    Ok(Json(AlertStatsResponse {
        total_rules,
        enabled_rules,
        total_fired_24h,
        by_severity_24h,
        by_type_24h,
        webhook_success_rate_24h,
    }))
}
