//! Firewall target management and manual User-ID push endpoints.

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashSet;
use std::time::Instant;
use tracing::warn;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;

/// API response for firewall target (without credentials).
#[derive(Serialize)]
pub(crate) struct FirewallTargetResponse {
    id: i64,
    name: String,
    firewall_type: String,
    host: String,
    port: i64,
    username: Option<String>,
    verify_tls: bool,
    enabled: bool,
    push_interval_secs: i64,
    subnet_filter: Option<String>,
    last_push_at: Option<DateTime<Utc>>,
    last_push_status: Option<String>,
    last_push_count: i64,
    last_push_error: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Create request payload for firewall target.
#[derive(Deserialize)]
pub(crate) struct CreateFirewallTargetRequest {
    name: String,
    firewall_type: String,
    host: String,
    port: Option<i64>,
    username: Option<String>,
    password: String,
    verify_tls: Option<bool>,
    push_interval_secs: Option<i64>,
    subnet_filter: Option<String>,
}

/// Update request payload for firewall target.
#[derive(Deserialize)]
pub(crate) struct UpdateFirewallTargetRequest {
    name: Option<String>,
    host: Option<String>,
    port: Option<i64>,
    username: Option<String>,
    password: Option<String>,
    verify_tls: Option<bool>,
    enabled: Option<bool>,
    push_interval_secs: Option<i64>,
    subnet_filter: Option<String>,
}

/// Push history row returned by API.
#[derive(Serialize)]
pub(crate) struct PushHistoryEntry {
    id: i64,
    target_id: i64,
    pushed_at: DateTime<Utc>,
    mapping_count: i64,
    status: String,
    error_message: Option<String>,
    duration_ms: Option<i64>,
}

/// Aggregate firewall push statistics.
#[derive(Serialize)]
pub(crate) struct FirewallStatsResponse {
    total_targets: i64,
    enabled_targets: i64,
    panos_targets: i64,
    fortigate_targets: i64,
    total_pushes_24h: i64,
    failed_pushes_24h: i64,
}

/// Pagination query for history endpoint.
#[derive(Deserialize)]
pub(crate) struct HistoryQuery {
    page: Option<i64>,
    limit: Option<i64>,
}

/// Paginated push history response.
#[derive(Serialize)]
struct PaginatedHistory {
    data: Vec<PushHistoryEntry>,
    total: i64,
    page: i64,
    limit: i64,
}

/// Internal firewall type discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FirewallType {
    PanOs,
    FortiGate,
}

/// Decrypted firewall target used for connectivity/push operations.
#[derive(Clone, Debug)]
struct FirewallTargetInternal {
    name: String,
    firewall_type: FirewallType,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    verify_tls: bool,
    push_interval_secs: i64,
    subnet_filter: Option<Vec<i64>>,
}

/// Push entry derived from active mappings.
#[derive(Clone, Debug)]
struct PushEntry {
    ip: String,
    user: String,
    timeout_secs: u32,
}

/// Response for manual push action.
#[derive(Serialize)]
struct ForcePushResponse {
    target_id: i64,
    target_name: String,
    pushed_count: i64,
    status: String,
    duration_ms: i64,
}

/// Response for connectivity test.
#[derive(Serialize)]
struct TestResponse {
    status: String,
    message: Option<String>,
}

/// Parses firewall type value from API/database string.
///
/// Parameters: `raw` - requested firewall type string.
/// Returns: parsed firewall type.
fn parse_firewall_type(raw: &str) -> Result<FirewallType> {
    match raw {
        "panos" => Ok(FirewallType::PanOs),
        "fortigate" => Ok(FirewallType::FortiGate),
        other => Err(anyhow!("Unsupported firewall_type: {other}")),
    }
}

/// Converts firewall type enum to stable API string.
///
/// Parameters: `firewall_type` - internal enum value.
/// Returns: normalized type string.
fn firewall_type_str(firewall_type: FirewallType) -> &'static str {
    match firewall_type {
        FirewallType::PanOs => "panos",
        FirewallType::FortiGate => "fortigate",
    }
}

/// Parses optional CSV subnet filter.
///
/// Parameters: `raw` - optional comma-separated subnet ids.
/// Returns: parsed subnet ids.
fn parse_subnet_filter(raw: Option<String>) -> Option<Vec<i64>> {
    let value = raw?;
    let ids = value
        .split(',')
        .filter_map(|s| s.trim().parse::<i64>().ok())
        .collect::<Vec<_>>();
    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

/// Validates firewall create/update payload fields.
///
/// Parameters: `firewall_type` - selected type, `username` - optional username, `password_present` - whether password/token is provided, `port` - optional port, `interval` - optional push interval, `request_id` - request correlation id.
/// Returns: validation success or API error.
fn validate_payload(
    firewall_type: &str,
    username: Option<&str>,
    password_present: bool,
    port: Option<i64>,
    interval: Option<i64>,
    request_id: &str,
) -> Result<(), ApiError> {
    if parse_firewall_type(firewall_type).is_err() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "firewall_type must be 'panos' or 'fortigate'",
        )
        .with_request_id(request_id));
    }
    if matches!(parse_firewall_type(firewall_type), Ok(FirewallType::PanOs))
        && (username.unwrap_or("").trim().is_empty() || !password_present)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "PAN-OS requires username and password",
        )
        .with_request_id(request_id));
    }
    if matches!(parse_firewall_type(firewall_type), Ok(FirewallType::FortiGate)) && !password_present {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "FortiGate requires API token in password field",
        )
        .with_request_id(request_id));
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
    if let Some(interval) = interval {
        if interval < 10 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "push_interval_secs must be >= 10",
            )
            .with_request_id(request_id));
        }
    }
    Ok(())
}

/// Validates that all subnet IDs in filter exist.
///
/// Parameters: `db` - database handle, `filter` - optional csv subnet ids, `request_id` - request correlation id.
/// Returns: validated/normalized filter string.
async fn validate_subnet_filter(
    db: &trueid_common::db::Db,
    filter: Option<&str>,
    request_id: &str,
) -> Result<Option<String>, ApiError> {
    let Some(raw) = filter else {
        return Ok(None);
    };
    let ids = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<i64>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "subnet_filter must be comma-separated integer IDs",
            )
            .with_request_id(request_id)
        })?;
    if ids.is_empty() {
        return Ok(None);
    }

    for id in &ids {
        let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM subnets WHERE id = ?")
            .bind(id)
            .fetch_optional(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, subnet_id = id, "Failed validating subnet_filter");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to validate subnet_filter",
                )
                .with_request_id(request_id)
            })?;
        if exists.is_none() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                &format!("subnet id {id} does not exist"),
            )
            .with_request_id(request_id));
        }
    }
    Ok(Some(
        ids.into_iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(","),
    ))
}

/// Converts DB row to API target response.
///
/// Parameters: `row` - sql row.
/// Returns: response DTO without credentials.
fn map_target_row(row: &sqlx::sqlite::SqliteRow) -> FirewallTargetResponse {
    FirewallTargetResponse {
        id: row.try_get("id").unwrap_or_default(),
        name: row.try_get("name").unwrap_or_default(),
        firewall_type: row.try_get("firewall_type").unwrap_or_default(),
        host: row.try_get("host").unwrap_or_default(),
        port: row.try_get("port").unwrap_or(443),
        username: row.try_get("username").ok(),
        verify_tls: row.try_get("verify_tls").unwrap_or(false),
        enabled: row.try_get("enabled").unwrap_or(true),
        push_interval_secs: row.try_get("push_interval_secs").unwrap_or(60),
        subnet_filter: row.try_get("subnet_filter").ok(),
        last_push_at: row.try_get("last_push_at").ok(),
        last_push_status: row.try_get("last_push_status").ok(),
        last_push_count: row.try_get("last_push_count").unwrap_or(0),
        last_push_error: row.try_get("last_push_error").ok(),
        created_at: row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        updated_at: row.try_get("updated_at").unwrap_or_else(|_| Utc::now()),
    }
}

/// Loads single decrypted target for push/test operations.
///
/// Parameters: `db` - database handle, `id` - target id.
/// Returns: decrypted target or None.
async fn load_target_internal(
    db: &trueid_common::db::Db,
    id: i64,
) -> Result<Option<FirewallTargetInternal>> {
    let row = sqlx::query(
        "SELECT id, name, firewall_type, host, port, username, password_enc, verify_tls,
                push_interval_secs, subnet_filter
         FROM firewall_targets
         WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    let firewall_type_raw: String = row.try_get("firewall_type")?;
    let firewall_type = parse_firewall_type(&firewall_type_raw)?;
    let enc: Option<String> = row.try_get("password_enc").ok();
    let password = match enc {
        Some(v) if !v.is_empty() => Some(db.decrypt_config_value(&v)?),
        _ => None,
    };

    Ok(Some(FirewallTargetInternal {
        name: row.try_get("name")?,
        firewall_type,
        host: row.try_get("host")?,
        port: u16::try_from(row.try_get::<i64, _>("port").unwrap_or(443)).unwrap_or(443),
        username: row.try_get("username").ok(),
        password,
        verify_tls: row.try_get("verify_tls").unwrap_or(false),
        push_interval_secs: row.try_get("push_interval_secs").unwrap_or(60).max(10),
        subnet_filter: parse_subnet_filter(row.try_get("subnet_filter").ok()),
    }))
}

/// Builds dedicated HTTP client for target TLS policy.
///
/// Parameters: `verify_tls` - if true, verifies certificates.
/// Returns: configured reqwest client.
fn build_client(verify_tls: bool) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(!verify_tls)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("Failed to build HTTP client")
}

/// Performs PAN-OS keygen request.
///
/// Parameters: `client` - HTTP client, `target` - target config.
/// Returns: API key string.
async fn panos_keygen(client: &reqwest::Client, target: &FirewallTargetInternal) -> Result<String> {
    let username = target
        .username
        .as_deref()
        .ok_or_else(|| anyhow!("PAN-OS username is required"))?;
    let password = target
        .password
        .as_deref()
        .ok_or_else(|| anyhow!("PAN-OS password is required"))?;
    let url = format!("https://{}:{}/api/", target.host, target.port);
    let resp = client
        .post(url)
        .query(&[
            ("type", "keygen"),
            ("user", username),
            ("password", password),
        ])
        .send()
        .await?;
    let body = resp.text().await?;
    if !body.contains("status=\"success\"") {
        return Err(anyhow!("PAN-OS keygen failed"));
    }
    let start = body
        .find("<key>")
        .ok_or_else(|| anyhow!("PAN-OS keygen response missing <key>"))?;
    let end = body
        .find("</key>")
        .ok_or_else(|| anyhow!("PAN-OS keygen response missing </key>"))?;
    Ok(body[start + 5..end].to_string())
}

/// Creates PAN-OS XML payload for a push chunk.
///
/// Parameters: `entries` - entries to include.
/// Returns: XML payload string.
fn panos_payload(entries: &[PushEntry]) -> String {
    let mut xml = String::from("<uid-message><version>2.0</version><type>update</type><payload><login>");
    for entry in entries {
        xml.push_str(&format!(
            "<entry name=\"{}\" ip=\"{}\" timeout=\"{}\"/>",
            entry.user, entry.ip, entry.timeout_secs
        ));
    }
    xml.push_str("</login></payload></uid-message>");
    xml
}

/// Pushes mappings to PAN-OS in chunks.
///
/// Parameters: `client` - HTTP client, `target` - target config, `entries` - mappings.
/// Returns: pushed entry count.
async fn push_panos(
    client: &reqwest::Client,
    target: &FirewallTargetInternal,
    entries: &[PushEntry],
) -> Result<u32> {
    if entries.is_empty() {
        return Ok(0);
    }
    let key = panos_keygen(client, target).await?;
    let url = format!("https://{}:{}/api/", target.host, target.port);
    let mut pushed = 0u32;
    for chunk in entries.chunks(1000) {
        let resp = client
            .post(&url)
            .query(&[("type", "user-id"), ("action", "set"), ("key", key.as_str())])
            .form(&[("cmd", panos_payload(chunk))])
            .send()
            .await?;
        let body = resp.text().await.unwrap_or_default();
        if !body.contains("status=\"success\"") {
            return Err(anyhow!("PAN-OS push failed"));
        }
        pushed = pushed.saturating_add(chunk.len() as u32);
    }
    Ok(pushed)
}

/// Pushes mappings to FortiGate sequentially.
///
/// Parameters: `client` - HTTP client, `target` - target config, `entries` - mappings.
/// Returns: pushed entry count.
async fn push_fortigate(
    client: &reqwest::Client,
    target: &FirewallTargetInternal,
    entries: &[PushEntry],
) -> Result<u32> {
    let token = target
        .password
        .as_deref()
        .ok_or_else(|| anyhow!("FortiGate API token is required"))?;
    let url = format!(
        "https://{}:{}/api/v2/monitor/user/firewall/login",
        target.host, target.port
    );
    let mut pushed = 0u32;
    for entry in entries {
        let resp = client
            .post(&url)
            .bearer_auth(token)
            .json(&serde_json::json!({
                "ip_address": entry.ip,
                "username": entry.user,
                "server": "TrueID"
            }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("FortiGate push failed"));
        }
        pushed = pushed.saturating_add(1);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Ok(pushed)
}

/// Tests target authentication/connectivity without pushing mappings.
///
/// Parameters: `target` - decrypted target config.
/// Returns: success when auth check passes.
async fn test_target_connection(target: &FirewallTargetInternal) -> Result<()> {
    let client = build_client(target.verify_tls)?;
    match target.firewall_type {
        FirewallType::PanOs => {
            let _ = panos_keygen(&client, target).await?;
        }
        FirewallType::FortiGate => {
            let token = target
                .password
                .as_deref()
                .ok_or_else(|| anyhow!("FortiGate API token is required"))?;
            let url = format!(
                "https://{}:{}/api/v2/monitor/system/status",
                target.host, target.port
            );
            let resp = client.get(url).bearer_auth(token).send().await?;
            if !resp.status().is_success() {
                return Err(anyhow!("FortiGate test connection failed"));
            }
        }
    }
    Ok(())
}

/// Loads active mappings and expands them to push entries.
///
/// Parameters: `db` - database handle, `target` - target config.
/// Returns: deduplicated push entries.
async fn load_push_entries(
    db: &trueid_common::db::Db,
    target: &FirewallTargetInternal,
) -> Result<Vec<PushEntry>> {
    let rows = sqlx::query(
        "SELECT m.ip, COALESCE(sess.user, m.user) as user, m.subnet_id
         FROM mappings m
         LEFT JOIN ip_sessions sess ON sess.ip = m.ip AND sess.is_active = 1
         WHERE m.is_active = 1",
    )
    .fetch_all(db.pool())
    .await?;

    let mut seen = HashSet::<(String, String)>::new();
    let mut entries = Vec::new();
    for row in rows {
        let subnet_id: Option<i64> = row.try_get("subnet_id").ok();
        if let Some(filter) = &target.subnet_filter {
            let Some(id) = subnet_id else {
                continue;
            };
            if !filter.contains(&id) {
                continue;
            }
        }
        let ip: String = row.try_get("ip").unwrap_or_default();
        let user: String = row.try_get("user").unwrap_or_default();
        if ip.is_empty() || user.is_empty() {
            continue;
        }
        if !seen.insert((ip.clone(), user.clone())) {
            continue;
        }
        entries.push(PushEntry {
            ip,
            user,
            timeout_secs: (target.push_interval_secs.saturating_mul(2)) as u32,
        });
    }
    Ok(entries)
}

/// Executes manual push and records status/history.
///
/// Parameters: `db` - database handle, `target` - target config.
/// Returns: pushed count and duration in milliseconds.
async fn execute_push(
    db: &trueid_common::db::Db,
    target: &FirewallTargetInternal,
) -> Result<(i64, i64)> {
    let started = Instant::now();
    let client = build_client(target.verify_tls)?;
    let entries = load_push_entries(db, target).await?;
    let count = match target.firewall_type {
        FirewallType::PanOs => push_panos(&client, target, &entries).await?,
        FirewallType::FortiGate => push_fortigate(&client, target, &entries).await?,
    };
    let duration_ms = started.elapsed().as_millis() as i64;
    Ok((i64::from(count), duration_ms))
}

/// Inserts push history row.
///
/// Parameters: `db` - database handle, `target_id` - target id, `count` - pushed count, `status` - status value, `error_message` - optional error, `duration_ms` - elapsed time.
/// Returns: success or sql error.
async fn write_history(
    db: &trueid_common::db::Db,
    target_id: i64,
    count: i64,
    status: &str,
    error_message: Option<&str>,
    duration_ms: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO firewall_push_history (target_id, mapping_count, status, error_message, duration_ms)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(target_id)
    .bind(count)
    .bind(status)
    .bind(error_message)
    .bind(duration_ms)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Updates cached status fields on firewall target.
///
/// Parameters: `db` - database handle, `target_id` - target id, `status` - status value, `count` - pushed count, `error_message` - optional error.
/// Returns: success or sql error.
async fn update_target_status(
    db: &trueid_common::db::Db,
    target_id: i64,
    status: &str,
    count: i64,
    error_message: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE firewall_targets
         SET last_push_at = datetime('now'),
             last_push_status = ?,
             last_push_count = ?,
             last_push_error = ?,
             updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(status)
    .bind(count)
    .bind(error_message)
    .bind(target_id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Returns all firewall targets without credentials.
///
/// Parameters: `auth` - authenticated user, `state` - app state.
/// Returns: list of targets.
pub(crate) async fn list_targets(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let rows = sqlx::query(
        "SELECT id, name, firewall_type, host, port, username, verify_tls, enabled,
                push_interval_secs, subnet_filter, last_push_at, last_push_status,
                last_push_count, last_push_error, created_at, updated_at
         FROM firewall_targets
         ORDER BY name ASC",
    )
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to list firewall targets");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to list firewall targets",
        )
        .with_request_id(&auth.request_id)
    })?;
    Ok(Json(rows.iter().map(map_target_row).collect::<Vec<_>>()))
}

/// Returns single firewall target without credentials.
///
/// Parameters: `auth` - authenticated user, `id` - target id, `state` - app state.
/// Returns: target details.
pub(crate) async fn get_target(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let row = sqlx::query(
        "SELECT id, name, firewall_type, host, port, username, verify_tls, enabled,
                push_interval_secs, subnet_filter, last_push_at, last_push_status,
                last_push_count, last_push_error, created_at, updated_at
         FROM firewall_targets WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, target_id = id, "Failed to fetch firewall target");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to get firewall target",
        )
        .with_request_id(&auth.request_id)
    })?;
    match row {
        Some(row) => Ok(Json(map_target_row(&row)).into_response()),
        None => Err(
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "Firewall target not found")
                .with_request_id(&auth.request_id),
        ),
    }
}

/// Creates a firewall target with encrypted credential.
///
/// Parameters: `auth` - authenticated admin, `state` - app state, `req` - create payload.
/// Returns: created target.
pub(crate) async fn create_target(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateFirewallTargetRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    validate_payload(
        req.firewall_type.trim(),
        req.username.as_deref(),
        !req.password.trim().is_empty(),
        req.port,
        req.push_interval_secs,
        &auth.request_id,
    )?;
    let subnet_filter =
        validate_subnet_filter(db, req.subnet_filter.as_deref(), &auth.request_id).await?;
    let encrypted = db.encrypt_config_value(req.password.trim()).map_err(|e| {
        warn!(error = %e, "Failed to encrypt firewall credential");
        ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Cannot encrypt credential. Check CONFIG_ENCRYPTION_KEY",
        )
        .with_request_id(&auth.request_id)
    })?;

    let result = sqlx::query(
        "INSERT INTO firewall_targets
         (name, firewall_type, host, port, username, password_enc, verify_tls, enabled, push_interval_secs, subnet_filter)
         VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
    )
    .bind(req.name.trim())
    .bind(req.firewall_type.trim())
    .bind(req.host.trim())
    .bind(req.port.unwrap_or(443))
    .bind(req.username.as_deref().map(str::trim))
    .bind(encrypted)
    .bind(req.verify_tls.unwrap_or(false))
    .bind(req.push_interval_secs.unwrap_or(60))
    .bind(subnet_filter)
    .execute(db.pool())
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("UNIQUE constraint failed") {
            ApiError::new(
                StatusCode::CONFLICT,
                error::CONFLICT,
                "Target with this host and port already exists",
            )
            .with_request_id(&auth.request_id)
        } else {
            warn!(error = %e, "Failed to create firewall target");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to create firewall target",
            )
            .with_request_id(&auth.request_id)
        }
    })?;
    let target_id = result.last_insert_rowid();

    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "firewall_target_create",
            Some(&target_id.to_string()),
            Some(req.name.trim()),
            None,
            Some(&auth.request_id),
        )
        .await;

    get_target(auth, Path(target_id), State(state)).await
}

/// Updates mutable firewall target fields.
///
/// Parameters: `auth` - authenticated admin, `id` - target id, `state` - app state, `req` - update payload.
/// Returns: updated target.
pub(crate) async fn update_target(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(req): Json<UpdateFirewallTargetRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let existing = load_target_internal(db, id).await.map_err(|e| {
        warn!(error = %e, target_id = id, "Failed to load firewall target for update");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to update firewall target",
        )
        .with_request_id(&auth.request_id)
    })?;
    let Some(existing_target) = existing else {
        return Err(
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "Firewall target not found")
                .with_request_id(&auth.request_id),
        );
    };

    let final_type = firewall_type_str(existing_target.firewall_type);
    let username_for_validation = req.username.as_deref().or(existing_target.username.as_deref());
    let password_present = req
        .password
        .as_deref()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(existing_target.password.as_ref().is_some());
    validate_payload(
        final_type,
        username_for_validation,
        password_present,
        req.port,
        req.push_interval_secs,
        &auth.request_id,
    )?;
    let subnet_filter = match req.subnet_filter.as_ref() {
        Some(v) => validate_subnet_filter(db, Some(v.as_str()), &auth.request_id).await?,
        None => None,
    };
    let encrypted_password = match req.password.as_deref() {
        Some(value) if !value.trim().is_empty() => Some(db.encrypt_config_value(value.trim()).map_err(|e| {
            warn!(error = %e, "Failed to encrypt firewall credential");
            ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "Cannot encrypt credential. Check CONFIG_ENCRYPTION_KEY",
            )
            .with_request_id(&auth.request_id)
        })?),
        _ => None,
    };

    sqlx::query(
        "UPDATE firewall_targets
         SET name = COALESCE(?, name),
             host = COALESCE(?, host),
             port = COALESCE(?, port),
             username = COALESCE(?, username),
             password_enc = COALESCE(?, password_enc),
             verify_tls = COALESCE(?, verify_tls),
             enabled = COALESCE(?, enabled),
             push_interval_secs = COALESCE(?, push_interval_secs),
             subnet_filter = COALESCE(?, subnet_filter),
             updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(req.name.as_deref().map(str::trim))
    .bind(req.host.as_deref().map(str::trim))
    .bind(req.port)
    .bind(req.username.as_deref().map(str::trim))
    .bind(encrypted_password)
    .bind(req.verify_tls)
    .bind(req.enabled)
    .bind(req.push_interval_secs)
    .bind(subnet_filter)
    .bind(id)
    .execute(db.pool())
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("UNIQUE constraint failed") {
            ApiError::new(
                StatusCode::CONFLICT,
                error::CONFLICT,
                "Target with this host and port already exists",
            )
            .with_request_id(&auth.request_id)
        } else {
            warn!(error = %e, target_id = id, "Failed to update firewall target");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to update firewall target",
            )
            .with_request_id(&auth.request_id)
        }
    })?;

    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "firewall_target_update",
            Some(&id.to_string()),
            None,
            None,
            Some(&auth.request_id),
        )
        .await;

    get_target(auth, Path(id), State(state)).await
}

/// Deletes firewall target and cascaded push history.
///
/// Parameters: `auth` - authenticated admin, `id` - target id, `state` - app state.
/// Returns: HTTP 204 on success.
pub(crate) async fn delete_target(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let result = sqlx::query("DELETE FROM firewall_targets WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, target_id = id, "Failed to delete firewall target");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to delete firewall target",
            )
            .with_request_id(&auth.request_id)
        })?;
    if result.rows_affected() == 0 {
        return Err(
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "Firewall target not found")
                .with_request_id(&auth.request_id),
        );
    }
    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "firewall_target_delete",
            Some(&id.to_string()),
            None,
            None,
            Some(&auth.request_id),
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Forces inline push for a target and returns immediate result.
///
/// Parameters: `auth` - authenticated admin, `id` - target id, `state` - app state.
/// Returns: push result payload.
pub(crate) async fn force_push(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let target = load_target_internal(db, id).await.map_err(|e| {
        warn!(error = %e, target_id = id, "Failed to load firewall target for force push");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to force firewall push",
        )
        .with_request_id(&auth.request_id)
    })?;
    let Some(target) = target else {
        return Err(
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "Firewall target not found")
                .with_request_id(&auth.request_id),
        );
    };

    let push_result = execute_push(db, &target).await;
    let (status, count, duration_ms, error_message) = match push_result {
        Ok((count, duration_ms)) => ("ok", count, duration_ms, None),
        Err(e) => ("error", 0, 0, Some(e.to_string())),
    };

    let _ = write_history(db, id, count, status, error_message.as_deref(), duration_ms).await;
    let _ = update_target_status(db, id, status, count, error_message.as_deref()).await;
    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "firewall_target_force_push",
            Some(&id.to_string()),
            Some(status),
            None,
            Some(&auth.request_id),
        )
        .await;

    if let Some(message) = error_message {
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            error::INTERNAL_ERROR,
            &format!("Push failed: {message}"),
        )
        .with_request_id(&auth.request_id));
    }

    Ok(Json(ForcePushResponse {
        target_id: id,
        target_name: target.name,
        pushed_count: count,
        status: status.to_string(),
        duration_ms,
    }))
}

/// Tests target connectivity without performing push.
///
/// Parameters: `auth` - authenticated admin, `id` - target id, `state` - app state.
/// Returns: test status payload.
pub(crate) async fn test_target(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let target = load_target_internal(db, id).await.map_err(|e| {
        warn!(error = %e, target_id = id, "Failed to load firewall target for test");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to test firewall target",
        )
        .with_request_id(&auth.request_id)
    })?;
    let Some(target) = target else {
        return Err(
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "Firewall target not found")
                .with_request_id(&auth.request_id),
        );
    };

    let result = test_target_connection(&target).await;
    let _ = db
        .write_audit_log(
            Some(auth.user_id),
            &auth.username,
            &auth.principal_type,
            "firewall_target_test",
            Some(&id.to_string()),
            Some(if result.is_ok() { "ok" } else { "error" }),
            None,
            Some(&auth.request_id),
        )
        .await;

    match result {
        Ok(()) => Ok(Json(TestResponse {
            status: "ok".to_string(),
            message: None,
        })
        .into_response()),
        Err(e) => Ok((
            StatusCode::BAD_GATEWAY,
            Json(TestResponse {
                status: "error".to_string(),
                message: Some(e.to_string()),
            }),
        )
            .into_response()),
    }
}

/// Returns paginated push history for one target.
///
/// Parameters: `auth` - authenticated user, `id` - target id, `q` - pagination query, `state` - app state.
/// Returns: paginated history payload.
pub(crate) async fn target_history(
    auth: AuthUser,
    Path(id): Path<i64>,
    Query(q): Query<HistoryQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * limit;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM firewall_push_history WHERE target_id = ?",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, target_id = id, "Failed to count firewall push history");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to fetch firewall push history",
        )
        .with_request_id(&auth.request_id)
    })?;

    let rows = sqlx::query(
        "SELECT id, target_id, pushed_at, mapping_count, status, error_message, duration_ms
         FROM firewall_push_history
         WHERE target_id = ?
         ORDER BY pushed_at DESC
         LIMIT ? OFFSET ?",
    )
    .bind(id)
    .bind(limit)
    .bind(offset)
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, target_id = id, "Failed to list firewall push history");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to fetch firewall push history",
        )
        .with_request_id(&auth.request_id)
    })?;

    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        data.push(PushHistoryEntry {
            id: row.try_get("id").unwrap_or_default(),
            target_id: row.try_get("target_id").unwrap_or_default(),
            pushed_at: row.try_get("pushed_at").unwrap_or_else(|_| Utc::now()),
            mapping_count: row.try_get("mapping_count").unwrap_or_default(),
            status: row.try_get("status").unwrap_or_else(|_| "error".to_string()),
            error_message: row.try_get("error_message").ok(),
            duration_ms: row.try_get("duration_ms").ok(),
        });
    }

    Ok(Json(PaginatedHistory {
        data,
        total,
        page,
        limit,
    }))
}

/// Returns aggregate firewall push statistics.
///
/// Parameters: `auth` - authenticated user, `state` - app state.
/// Returns: firewall stats payload.
pub(crate) async fn firewall_stats(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;

    let total_targets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM firewall_targets")
        .fetch_one(db.pool())
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to count firewall targets");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to load firewall stats",
            )
            .with_request_id(&auth.request_id)
        })?;
    let enabled_targets: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM firewall_targets WHERE enabled = 1")
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to count enabled firewall targets");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to load firewall stats",
                )
                .with_request_id(&auth.request_id)
            })?;
    let panos_targets: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM firewall_targets WHERE firewall_type = 'panos'")
            .fetch_one(db.pool())
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to count PAN-OS targets");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error::INTERNAL_ERROR,
                    "Failed to load firewall stats",
                )
                .with_request_id(&auth.request_id)
            })?;
    let fortigate_targets: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM firewall_targets WHERE firewall_type = 'fortigate'",
    )
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to count FortiGate targets");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to load firewall stats",
        )
        .with_request_id(&auth.request_id)
    })?;
    let total_pushes_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM firewall_push_history WHERE pushed_at > datetime('now', '-24 hours')",
    )
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to count pushes in 24h");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to load firewall stats",
        )
        .with_request_id(&auth.request_id)
    })?;
    let failed_pushes_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM firewall_push_history
         WHERE pushed_at > datetime('now', '-24 hours') AND status = 'error'",
    )
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        warn!(error = %e, "Failed to count failed pushes in 24h");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to load firewall stats",
        )
        .with_request_id(&auth.request_id)
    })?;

    Ok(Json(FirewallStatsResponse {
        total_targets,
        enabled_targets,
        panos_targets,
        fortigate_targets,
        total_pushes_24h,
        failed_pushes_24h,
    }))
}
