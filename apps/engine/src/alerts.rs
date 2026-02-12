//! Alert rule evaluation and webhook delivery.

use anyhow::Result;
use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;
use tokio::time::{timeout, Duration};
use tracing::warn;
use trueid_common::model::IdentityEvent;

use crate::conflicts::ConflictRecord;

/// Alert rule loaded from the `alert_rules` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
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
}

/// Alert instance prepared for delivery and history insert.
#[derive(Debug, Clone)]
pub struct AlertFiring {
    pub rule_id: i64,
    pub rule_name: String,
    pub rule_type: String,
    pub severity: String,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub user_name: Option<String>,
    pub source: String,
    pub details: String,
    pub webhook_url: Option<String>,
    pub webhook_headers: Option<String>,
    pub action_log: bool,
    pub cooldown_seconds: i64,
}

/// Alert history row payload.
#[derive(Debug, Clone)]
struct AlertHistoryInsert {
    rule_id: i64,
    rule_name: String,
    rule_type: String,
    severity: String,
    ip: Option<String>,
    mac: Option<String>,
    user_name: Option<String>,
    source: String,
    details: String,
    webhook_status: String,
    webhook_response: Option<String>,
}

/// Loads enabled alert rules from the database.
///
/// Parameters: `pool` - SQLite pool used for query execution.
/// Returns: enabled rule list.
pub async fn load_rules(pool: &SqlitePool) -> Result<Vec<AlertRule>> {
    let rows = sqlx::query(
        "SELECT id, name, enabled, rule_type, severity, conditions,
                action_webhook_url, action_webhook_headers, action_log, cooldown_seconds
         FROM alert_rules
         WHERE enabled = true
         ORDER BY id ASC",
    )
    .fetch_all(pool)
    .await?;

    let mut rules = Vec::with_capacity(rows.len());
    for row in rows {
        rules.push(AlertRule {
            id: row.try_get("id").unwrap_or(0),
            name: row.try_get("name").unwrap_or_default(),
            enabled: row.try_get("enabled").unwrap_or(false),
            rule_type: row.try_get("rule_type").unwrap_or_default(),
            severity: row.try_get("severity").unwrap_or_else(|_| "warning".to_string()),
            conditions: row.try_get("conditions").ok(),
            action_webhook_url: row.try_get("action_webhook_url").ok(),
            action_webhook_headers: row.try_get("action_webhook_headers").ok(),
            action_log: row.try_get("action_log").unwrap_or(true),
            cooldown_seconds: row.try_get("cooldown_seconds").unwrap_or(300),
        });
    }
    Ok(rules)
}

/// Evaluates a single event against all rules and returns firings.
///
/// Parameters: `pool` - SQLite pool, `event` - incoming event,
/// `conflicts` - conflicts detected for this event, `rules` - enabled rules.
/// Returns: list of firings that should be processed.
pub async fn evaluate_event(
    pool: &SqlitePool,
    event: &IdentityEvent,
    conflicts: &[ConflictRecord],
    rules: &[AlertRule],
) -> Vec<AlertFiring> {
    let mut firings = Vec::new();
    let ip = event.ip.to_string();
    let source = format!("{:?}", event.source);

    let current_user = match sqlx::query("SELECT user FROM mappings WHERE ip = ?")
        .bind(&ip)
        .fetch_optional(pool)
        .await
    {
        Ok(Some(row)) => row.try_get::<String, _>("user").ok(),
        Ok(None) => None,
        Err(e) => {
            warn!(error = %e, ip = %ip, "Alert evaluate: failed to read current mapping");
            None
        }
    };

    let active_mac_count = if let Some(mac) = event.mac.as_ref() {
        match sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM mappings WHERE mac = ? AND is_active = true",
        )
        .bind(mac)
        .fetch_one(pool)
        .await
        {
            Ok(v) => Some(v),
            Err(e) => {
                warn!(error = %e, mac = %mac, "Alert evaluate: failed to count active MAC mappings");
                None
            }
        }
    } else {
        None
    };

    let mut subnet_is_new = None;
    if let std::net::IpAddr::V4(v4) = event.ip {
        let octets = v4.octets();
        let prefix = format!("{}.{}.{}.%", octets[0], octets[1], octets[2]);
        subnet_is_new = match sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM mappings WHERE ip LIKE ?")
            .bind(prefix)
            .fetch_one(pool)
            .await
        {
            Ok(v) => Some(v == 0),
            Err(e) => {
                warn!(error = %e, ip = %ip, "Alert evaluate: failed subnet query");
                None
            }
        };
    }

    for rule in rules {
        let should_fire = match rule.rule_type.as_str() {
            "new_mac" => event.mac.is_some() && active_mac_count.unwrap_or(1) == 0,
            "ip_conflict" => conflicts
                .iter()
                .any(|c| c.conflict_type == "ip_user_change" || c.conflict_type == "duplicate_mac"),
            "user_change" => current_user
                .as_ref()
                .map(|u| u != &event.user)
                .unwrap_or(false),
            "new_subnet" => subnet_is_new.unwrap_or(false),
            "source_down" => {
                // TODO: implement source_down via background health check.
                false
            }
            _ => false,
        };

        if !should_fire {
            continue;
        }

        let details = json!({
            "event_timestamp": event.timestamp.to_rfc3339(),
            "event_ip": ip,
            "event_user": event.user,
            "event_mac": event.mac,
            "event_source": source,
            "conflicts": conflicts,
            "conditions": rule.conditions,
        })
        .to_string();

        firings.push(AlertFiring {
            rule_id: rule.id,
            rule_name: rule.name.clone(),
            rule_type: rule.rule_type.clone(),
            severity: rule.severity.clone(),
            ip: Some(event.ip.to_string()),
            mac: event.mac.clone(),
            user_name: Some(event.user.clone()),
            source: format!("{:?}", event.source),
            details,
            webhook_url: rule.action_webhook_url.clone(),
            webhook_headers: rule.action_webhook_headers.clone(),
            action_log: rule.action_log,
            cooldown_seconds: rule.cooldown_seconds.clamp(0, 86_400),
        });
    }

    firings
}

/// Fires a single alert and records history with webhook delivery metadata.
///
/// Parameters: `pool` - SQLite pool, `http_client` - shared HTTP client, `firing` - alert firing payload.
/// Returns: operation result.
pub async fn fire_alert(pool: &SqlitePool, http_client: &reqwest::Client, firing: &AlertFiring) {
    if is_on_cooldown(pool, firing).await {
        if firing.action_log {
            let _ = insert_alert_history(
                pool,
                AlertHistoryInsert {
                    rule_id: firing.rule_id,
                    rule_name: firing.rule_name.clone(),
                    rule_type: firing.rule_type.clone(),
                    severity: firing.severity.clone(),
                    ip: firing.ip.clone(),
                    mac: firing.mac.clone(),
                    user_name: firing.user_name.clone(),
                    source: firing.source.clone(),
                    details: firing.details.clone(),
                    webhook_status: "skipped".to_string(),
                    webhook_response: None,
                },
            )
            .await;
        }
        return;
    }

    let (status, response) = match firing.webhook_url.as_deref() {
        None | Some("") => ("no_webhook".to_string(), None),
        Some(url) => send_webhook(http_client, url, firing).await,
    };

    if firing.action_log {
        let _ = insert_alert_history(
            pool,
            AlertHistoryInsert {
                rule_id: firing.rule_id,
                rule_name: firing.rule_name.clone(),
                rule_type: firing.rule_type.clone(),
                severity: firing.severity.clone(),
                ip: firing.ip.clone(),
                mac: firing.mac.clone(),
                user_name: firing.user_name.clone(),
                source: firing.source.clone(),
                details: firing.details.clone(),
                webhook_status: status,
                webhook_response: response,
            },
        )
        .await;
    }
}

/// Checks whether a rule+IP pair is on cooldown.
///
/// Parameters: `pool` - SQLite pool, `firing` - alert candidate.
/// Returns: `true` when alert should be suppressed.
async fn is_on_cooldown(pool: &SqlitePool, firing: &AlertFiring) -> bool {
    let ip_key = firing.ip.as_deref().unwrap_or("").to_string();
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM alert_history
         WHERE rule_id = ?
           AND COALESCE(ip, '') = ?
           AND fired_at > datetime('now', '-' || ? || ' seconds')",
    )
    .bind(firing.rule_id)
    .bind(ip_key)
    .bind(firing.cooldown_seconds.clamp(0, 86_400))
    .fetch_one(pool)
    .await;

    match count {
        Ok(v) => v > 0,
        Err(e) => {
            warn!(error = %e, rule_id = firing.rule_id, "Alert cooldown check failed");
            false
        }
    }
}

/// Sends webhook for a single firing with a strict 5-second timeout.
///
/// Parameters: `client` - HTTP client, `url` - webhook URL, `firing` - alert data.
/// Returns: `(webhook_status, webhook_response)` for history storage.
async fn send_webhook(
    client: &reqwest::Client,
    url: &str,
    firing: &AlertFiring,
) -> (String, Option<String>) {
    let details_json = serde_json::from_str::<Value>(&firing.details)
        .unwrap_or_else(|_| json!({ "raw": firing.details }));
    let payload = json!({
        "alert": firing.rule_name,
        "type": firing.rule_type,
        "severity": firing.severity,
        "ip": firing.ip,
        "user": firing.user_name,
        "mac": firing.mac,
        "source": firing.source,
        "details": details_json,
        "timestamp": Utc::now().to_rfc3339(),
    });

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Some(extra) = build_extra_headers(firing.webhook_headers.as_deref()) {
        for (key, value) in extra {
            headers.insert(key, value);
        }
    }

    let request = client.post(url).headers(headers).json(&payload);
    let response = timeout(Duration::from_secs(5), request.send()).await;

    match response {
        Ok(Ok(resp)) => {
            let body = match timeout(Duration::from_secs(5), resp.text()).await {
                Ok(Ok(text)) => truncate_response(text),
                Ok(Err(e)) => {
                    warn!(error = %e, url = %url, "Alert webhook response read failed");
                    None
                }
                Err(_) => {
                    warn!(url = %url, "Alert webhook response timeout");
                    None
                }
            };
            ("sent".to_string(), body)
        }
        Ok(Err(e)) => {
            warn!(error = %e, url = %url, "Alert webhook send failed");
            ("failed".to_string(), Some(truncate_to_500(e.to_string())))
        }
        Err(_) => {
            warn!(url = %url, "Alert webhook timeout");
            ("failed".to_string(), Some("timeout".to_string()))
        }
    }
}

/// Parses optional JSON header map for webhook requests.
///
/// Parameters: `raw` - optional JSON object string.
/// Returns: parsed header entries or `None` on invalid input.
fn build_extra_headers(raw: Option<&str>) -> Option<Vec<(HeaderName, HeaderValue)>> {
    let Some(raw_json) = raw else {
        return Some(Vec::new());
    };
    let value = serde_json::from_str::<Value>(raw_json).ok()?;
    let map = value.as_object()?;
    let mut headers = Vec::new();
    for (k, v) in map {
        let Some(vs) = v.as_str() else {
            continue;
        };
        let Ok(name) = HeaderName::from_str(k) else {
            continue;
        };
        let Ok(val) = HeaderValue::from_str(vs) else {
            continue;
        };
        headers.push((name, val));
    }
    Some(headers)
}

/// Inserts one alert history row.
///
/// Parameters: `pool` - SQLite pool, `entry` - history payload.
/// Returns: insert result.
async fn insert_alert_history(pool: &SqlitePool, entry: AlertHistoryInsert) -> Result<()> {
    sqlx::query(
        "INSERT INTO alert_history (
            rule_id, rule_name, rule_type, severity,
            ip, mac, user_name, source, details,
            webhook_status, webhook_response
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(entry.rule_id)
    .bind(entry.rule_name)
    .bind(entry.rule_type)
    .bind(entry.severity)
    .bind(entry.ip)
    .bind(entry.mac)
    .bind(entry.user_name)
    .bind(entry.source)
    .bind(entry.details)
    .bind(entry.webhook_status)
    .bind(entry.webhook_response)
    .execute(pool)
    .await?;
    Ok(())
}

/// Truncates response body text to 500 characters for DB storage.
///
/// Parameters: `text` - raw response body.
/// Returns: optional truncated body.
fn truncate_response(text: String) -> Option<String> {
    if text.is_empty() {
        None
    } else {
        Some(truncate_to_500(text))
    }
}

/// Truncates string to max 500 UTF-8 characters.
///
/// Parameters: `text` - source text.
/// Returns: truncated text.
fn truncate_to_500(text: String) -> String {
    text.chars().take(500).collect()
}
