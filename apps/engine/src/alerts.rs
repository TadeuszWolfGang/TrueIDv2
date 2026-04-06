//! Alert rule evaluation and webhook delivery.

use anyhow::Result;
use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, HOST};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Row, SqlitePool};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tokio::net::lookup_host;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};
use trueid_common::db::Db;
use trueid_common::model::{AdapterStatus, IdentityEvent};

use crate::conflicts::ConflictRecord;
use crate::notifications::{AlertPayload, NotificationDispatcher};

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

/// Resolved webhook endpoint with DNS pinning metadata.
struct ResolvedWebhookTarget {
    host: String,
    addrs: Vec<SocketAddr>,
    requires_dns_pinning: bool,
}

const SOURCE_DOWN_ADAPTERS: [&str; 6] = [
    "RADIUS",
    "AD Syslog",
    "DHCP Syslog",
    "VPN Syslog",
    "AD TLS",
    "DHCP TLS",
];
const DEFAULT_SOURCE_DOWN_SILENCE_SECONDS: i64 = 300;
const MIN_SOURCE_DOWN_SILENCE_SECONDS: i64 = 60;
const MAX_SOURCE_DOWN_SILENCE_SECONDS: i64 = 3600;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SourceDownConditions {
    source: String,
    #[serde(default = "default_source_down_silence_seconds")]
    silence_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceDownRuleState {
    adapter_name: String,
    state: SourceDownState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceDownState {
    Unknown,
    Up,
    Down,
}

fn default_source_down_silence_seconds() -> i64 {
    DEFAULT_SOURCE_DOWN_SILENCE_SECONDS
}

fn parse_source_down_conditions(raw: Option<&str>) -> Result<SourceDownConditions, String> {
    let value = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "source_down rule requires JSON conditions".to_string())?;
    let mut parsed: SourceDownConditions = serde_json::from_str(value)
        .map_err(|_| "source_down conditions must be valid JSON".to_string())?;
    parsed.source = parsed.source.trim().to_string();
    if !SOURCE_DOWN_ADAPTERS.contains(&parsed.source.as_str()) {
        return Err("source_down conditions.source must be a supported adapter name".to_string());
    }
    if !(MIN_SOURCE_DOWN_SILENCE_SECONDS..=MAX_SOURCE_DOWN_SILENCE_SECONDS)
        .contains(&parsed.silence_seconds)
    {
        return Err("source_down conditions.silence_seconds must be in 60..=3600".to_string());
    }
    Ok(parsed)
}

fn build_source_down_details(
    adapter: &AdapterStatus,
    silence_seconds: i64,
    observed_silence_seconds: i64,
    now: DateTime<Utc>,
) -> String {
    json!({
        "adapter_name": adapter.name,
        "adapter_protocol": adapter.protocol,
        "adapter_bind": adapter.bind,
        "adapter_status": adapter.status,
        "last_event_at": adapter.last_event_at.map(|ts| ts.to_rfc3339()),
        "silence_seconds": silence_seconds,
        "observed_silence_seconds": observed_silence_seconds,
        "evaluated_at": now.to_rfc3339(),
    })
    .to_string()
}

/// Evaluates source_down rules against adapter activity snapshots.
///
/// Rules are edge-triggered per rule ID. The first observed stale transition after activity
/// generates one alert. Recovery only resets state and logs an info line in v1.
pub(crate) fn evaluate_source_down_rules(
    adapter_stats: &[AdapterStatus],
    rules: &[AlertRule],
    state: &mut HashMap<i64, SourceDownRuleState>,
    now: DateTime<Utc>,
) -> Vec<AlertFiring> {
    let active_rule_ids = rules
        .iter()
        .filter(|rule| rule.rule_type == "source_down")
        .map(|rule| rule.id)
        .collect::<HashSet<_>>();
    state.retain(|rule_id, _| active_rule_ids.contains(rule_id));

    let mut firings = Vec::new();

    for rule in rules.iter().filter(|rule| rule.rule_type == "source_down") {
        let conditions = match parse_source_down_conditions(rule.conditions.as_deref()) {
            Ok(parsed) => parsed,
            Err(err) => {
                warn!(rule_id = rule.id, error = %err, "Skipping invalid source_down rule");
                state.remove(&rule.id);
                continue;
            }
        };

        let Some(adapter) = adapter_stats
            .iter()
            .find(|adapter| adapter.name == conditions.source)
        else {
            warn!(
                rule_id = rule.id,
                source = %conditions.source,
                "Skipping source_down rule for unknown adapter"
            );
            state.remove(&rule.id);
            continue;
        };

        let entry = state.entry(rule.id).or_insert_with(|| SourceDownRuleState {
            adapter_name: conditions.source.clone(),
            state: SourceDownState::Unknown,
        });
        if entry.adapter_name != conditions.source {
            *entry = SourceDownRuleState {
                adapter_name: conditions.source.clone(),
                state: SourceDownState::Unknown,
            };
        }

        let Some(last_event_at) = adapter.last_event_at else {
            entry.state = SourceDownState::Unknown;
            continue;
        };

        let observed_silence_seconds = (now - last_event_at).num_seconds().max(0);
        let next_state = if observed_silence_seconds >= conditions.silence_seconds {
            SourceDownState::Down
        } else {
            SourceDownState::Up
        };

        match (entry.state, next_state) {
            (SourceDownState::Unknown, SourceDownState::Up)
            | (SourceDownState::Up, SourceDownState::Up) => {
                entry.state = SourceDownState::Up;
            }
            (SourceDownState::Unknown, SourceDownState::Down)
            | (SourceDownState::Up, SourceDownState::Down) => {
                entry.state = SourceDownState::Down;
                firings.push(AlertFiring {
                    rule_id: rule.id,
                    rule_name: rule.name.clone(),
                    rule_type: rule.rule_type.clone(),
                    severity: rule.severity.clone(),
                    ip: None,
                    mac: None,
                    user_name: None,
                    source: adapter.name.clone(),
                    details: build_source_down_details(
                        adapter,
                        conditions.silence_seconds,
                        observed_silence_seconds,
                        now,
                    ),
                    webhook_url: rule.action_webhook_url.clone(),
                    webhook_headers: rule.action_webhook_headers.clone(),
                    action_log: rule.action_log,
                    cooldown_seconds: rule.cooldown_seconds.clamp(0, 86_400),
                });
            }
            (SourceDownState::Down, SourceDownState::Down) => {}
            (SourceDownState::Down, SourceDownState::Up) => {
                entry.state = SourceDownState::Up;
                info!(
                    rule_id = rule.id,
                    source = %adapter.name,
                    last_event_at = %last_event_at.to_rfc3339(),
                    "source_down recovery detected"
                );
            }
            (_, SourceDownState::Unknown) => {}
        }
    }

    firings
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
            severity: row
                .try_get("severity")
                .unwrap_or_else(|_| "warning".to_string()),
            conditions: row
                .try_get::<Option<String>, _>("conditions")
                .unwrap_or(None),
            action_webhook_url: row
                .try_get::<Option<String>, _>("action_webhook_url")
                .unwrap_or(None),
            action_webhook_headers: row
                .try_get::<Option<String>, _>("action_webhook_headers")
                .unwrap_or(None),
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

    let subnet_prefix = match event.ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{}.{}.{}.%", octets[0], octets[1], octets[2])
        }
        std::net::IpAddr::V6(v6) => {
            let seg = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}:%", seg[0], seg[1], seg[2], seg[3])
        }
    };
    let subnet_is_new =
        match sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM mappings WHERE ip LIKE ?")
            .bind(subnet_prefix)
            .fetch_one(pool)
            .await
        {
            Ok(v) => Some(v == 0),
            Err(e) => {
                warn!(error = %e, ip = %ip, "Alert evaluate: failed subnet query");
                None
            }
        };

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
/// Parameters: `db` - database handle, `http_client` - shared HTTP client, `dispatcher` - notification dispatcher, `firing` - alert firing payload.
/// Returns: operation result.
pub async fn fire_alert(
    db: &Db,
    http_client: &reqwest::Client,
    dispatcher: &NotificationDispatcher,
    firing: &AlertFiring,
) {
    if is_on_cooldown(db.pool(), firing).await {
        if firing.action_log {
            let _ = insert_alert_history(
                db.pool(),
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

    let history_id = if firing.action_log {
        insert_alert_history(
            db.pool(),
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
        .await
        .ok()
    } else {
        None
    };
    let payload = AlertPayload {
        rule_name: firing.rule_name.clone(),
        rule_type: firing.rule_type.clone(),
        severity: firing.severity.clone(),
        ip: firing.ip.clone(),
        user: firing.user_name.clone(),
        details: firing.details.clone(),
        timestamp: Utc::now(),
    };
    for result in dispatcher
        .dispatch_alert(firing.rule_id, &payload, history_id)
        .await
    {
        if let Err(err) = result.outcome {
            warn!(
                channel = %result.channel_name,
                error = %err,
                "Notification delivery failed"
            );
        }
    }
}

/// Checks whether a rule+IP pair is on cooldown.
///
/// Parameters: `pool` - SQLite pool, `firing` - alert candidate.
/// Returns: `true` when alert should be suppressed.
async fn is_on_cooldown(pool: &SqlitePool, firing: &AlertFiring) -> bool {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM alert_history
         WHERE rule_id = ?
           AND COALESCE(ip, '') = ?
           AND COALESCE(mac, '') = ?
           AND COALESCE(user_name, '') = ?
           AND COALESCE(source, '') = ?
           AND fired_at > datetime('now', '-' || ? || ' seconds')",
    )
    .bind(firing.rule_id)
    .bind(firing.ip.as_deref().unwrap_or(""))
    .bind(firing.mac.as_deref().unwrap_or(""))
    .bind(firing.user_name.as_deref().unwrap_or(""))
    .bind(&firing.source)
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
    let resolved_target = match resolve_webhook_target(url).await {
        Ok(target) => target,
        Err(err) => {
            warn!(url = %url, error = %err, "Alert webhook destination rejected");
            return ("failed".to_string(), Some(truncate_to_500(err)));
        }
    };
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

    let pinned_client = if resolved_target.requires_dns_pinning {
        match reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .resolve_to_addrs(&resolved_target.host, &resolved_target.addrs)
            .build()
        {
            Ok(pinned) => Some(pinned),
            Err(err) => {
                warn!(url = %url, error = %err, "Alert webhook pinned client build failed");
                return (
                    "failed".to_string(),
                    Some(truncate_to_500(format!(
                        "webhook client initialization failed: {err}"
                    ))),
                );
            }
        }
    } else {
        None
    };
    let request = pinned_client
        .as_ref()
        .unwrap_or(client)
        .post(url)
        .headers(headers)
        .json(&payload);
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
        if name == HOST {
            continue;
        }
        let Ok(val) = HeaderValue::from_str(vs) else {
            continue;
        };
        headers.push((name, val));
    }
    Some(headers)
}

/// Resolves a webhook URL and rejects loopback/private/link-local destinations.
async fn resolve_webhook_target(url: &str) -> std::result::Result<ResolvedWebhookTarget, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid webhook URL: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!(
            "unsupported webhook URL scheme: {}",
            parsed.scheme()
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "webhook URL is missing host".to_string())?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "webhook URL is missing port".to_string())?;

    let requires_dns_pinning = host.parse::<IpAddr>().is_err();
    let addrs = if requires_dns_pinning {
        lookup_host((host.as_str(), port))
            .await
            .map_err(|e| format!("webhook host resolution failed: {e}"))?
            .collect::<Vec<_>>()
    } else {
        vec![SocketAddr::new(
            host.parse::<IpAddr>()
                .map_err(|e| format!("invalid webhook host IP: {e}"))?,
            port,
        )]
    };

    if addrs.is_empty() {
        return Err(format!(
            "webhook host resolution returned no addresses for {host}"
        ));
    }
    validate_webhook_addresses(&host, &addrs)?;

    Ok(ResolvedWebhookTarget {
        host,
        addrs,
        requires_dns_pinning,
    })
}

/// Validates that all resolved webhook targets are public routable addresses.
fn validate_webhook_addresses(host: &str, addrs: &[SocketAddr]) -> std::result::Result<(), String> {
    if let Some(blocked) = addrs
        .iter()
        .find(|addr| is_forbidden_webhook_ip(addr.ip()))
        .map(|addr| addr.ip())
    {
        return Err(format!(
            "blocked webhook destination: {host} resolved to disallowed address {blocked}"
        ));
    }
    Ok(())
}

/// Returns `true` for local-only addresses that should never receive webhook traffic.
fn is_forbidden_webhook_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            let is_ula = (seg0 & 0xfe00) == 0xfc00;
            let is_link_local = (seg0 & 0xffc0) == 0xfe80;
            is_ula || is_link_local || v6.is_loopback() || v6.is_unspecified()
        }
    }
}

/// Inserts one alert history row.
///
/// Parameters: `pool` - SQLite pool, `entry` - history payload.
/// Returns: inserted history ID.
async fn insert_alert_history(pool: &SqlitePool, entry: AlertHistoryInsert) -> Result<i64> {
    let result = sqlx::query(
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
    Ok(result.last_insert_rowid())
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

#[cfg(test)]
mod tests {
    use super::*;
    use trueid_common::db::init_db;

    fn sample_firing() -> AlertFiring {
        AlertFiring {
            rule_id: 1,
            rule_name: "test-rule".to_string(),
            rule_type: "new_mac".to_string(),
            severity: "warning".to_string(),
            ip: None,
            mac: Some("AA:BB:CC:DD:EE:FF".to_string()),
            user_name: Some("alice".to_string()),
            source: "AdLog".to_string(),
            details: "{\"ok\":true}".to_string(),
            webhook_url: Some("https://example.com/hook".to_string()),
            webhook_headers: None,
            action_log: true,
            cooldown_seconds: 300,
        }
    }

    #[test]
    fn test_build_extra_headers_drops_host_header() {
        let headers = build_extra_headers(Some(r#"{"Host":"internal.local","X-Test":"ok"}"#))
            .expect("headers should parse");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, HeaderName::from_static("x-test"));
        assert_eq!(headers[0].1, HeaderValue::from_static("ok"));
    }

    #[tokio::test]
    async fn test_send_webhook_blocks_loopback_destination() {
        let client = reqwest::Client::builder()
            .build()
            .expect("build client failed");
        let firing = sample_firing();
        let (status, response) =
            send_webhook(&client, "http://127.0.0.1:18080/hook", &firing).await;

        assert_eq!(status, "failed");
        assert!(
            response
                .unwrap_or_default()
                .contains("blocked webhook destination"),
            "expected loopback block response"
        );
    }

    #[tokio::test]
    async fn test_cooldown_key_uses_user_mac_and_source() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        sqlx::query(
            "INSERT INTO alert_rules (id, name, enabled, rule_type, severity, action_log, cooldown_seconds)
             VALUES (1, 'test-rule', 1, 'new_mac', 'warning', 1, 300)",
        )
        .execute(db.pool())
        .await
        .expect("insert alert rule failed");
        sqlx::query(
            "INSERT INTO alert_history (
                rule_id, rule_name, rule_type, severity, ip, mac, user_name, source, details, webhook_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(1_i64)
        .bind("test-rule")
        .bind("new_mac")
        .bind("warning")
        .bind("")
        .bind("AA:BB:CC:DD:EE:FF")
        .bind("alice")
        .bind("AdLog")
        .bind("{}")
        .bind("sent")
        .execute(db.pool())
        .await
        .expect("insert alert history failed");

        let mut firing = sample_firing();
        firing.user_name = Some("bob".to_string());
        assert!(
            !is_on_cooldown(db.pool(), &firing).await,
            "different user should not share cooldown bucket"
        );

        firing.user_name = Some("alice".to_string());
        assert!(
            is_on_cooldown(db.pool(), &firing).await,
            "same rule/user/mac/source should stay on cooldown"
        );
    }

    // ── Phase 1: evaluate_event rule type coverage ──

    fn test_event(ip: &str, user: &str, mac: Option<&str>) -> IdentityEvent {
        IdentityEvent {
            source: trueid_common::model::SourceType::AdLog,
            ip: ip.parse::<std::net::IpAddr>().expect("ip parse failed"),
            user: user.to_string(),
            timestamp: chrono::Utc::now(),
            raw_data: format!("test event for {ip}"),
            mac: mac.map(|m| m.to_string()),
            confidence_score: 90,
        }
    }

    fn make_rule(id: i64, name: &str, rule_type: &str) -> AlertRule {
        AlertRule {
            id,
            name: name.to_string(),
            enabled: true,
            rule_type: rule_type.to_string(),
            severity: "warning".to_string(),
            conditions: None,
            action_webhook_url: None,
            action_webhook_headers: None,
            action_log: true,
            cooldown_seconds: 300,
        }
    }

    fn make_source_down_rule(
        id: i64,
        name: &str,
        adapter_name: &str,
        silence_seconds: i64,
    ) -> AlertRule {
        let mut rule = make_rule(id, name, "source_down");
        rule.conditions = Some(
            json!({
                "source": adapter_name,
                "silence_seconds": silence_seconds,
            })
            .to_string(),
        );
        rule
    }

    fn adapter_status(
        name: &str,
        last_event_at: Option<DateTime<Utc>>,
        status: &str,
    ) -> AdapterStatus {
        AdapterStatus {
            name: name.to_string(),
            protocol: "UDP".to_string(),
            bind: "0.0.0.0:0".to_string(),
            status: status.to_string(),
            last_event_at,
            events_total: 0,
        }
    }

    #[tokio::test]
    async fn test_new_mac_fires_when_mac_unseen() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        let event = test_event("10.0.0.1", "alice", Some("AA:BB:CC:DD:EE:01"));
        let rules = vec![make_rule(1, "new-mac-rule", "new_mac")];

        let firings = evaluate_event(db.pool(), &event, &[], &rules).await;

        assert_eq!(firings.len(), 1);
        assert_eq!(firings[0].rule_type, "new_mac");
        assert_eq!(firings[0].rule_name, "new-mac-rule");
    }

    #[tokio::test]
    async fn test_new_mac_does_not_fire_when_mac_exists() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        db.upsert_mapping(
            test_event("10.0.0.1", "alice", Some("AA:BB:CC:DD:EE:01")),
            None,
        )
        .await
        .unwrap();

        let event = test_event("10.0.0.2", "bob", Some("AA:BB:CC:DD:EE:01"));
        let rules = vec![make_rule(1, "new-mac-rule", "new_mac")];

        let firings = evaluate_event(db.pool(), &event, &[], &rules).await;

        assert!(
            firings.is_empty(),
            "existing active MAC should not trigger new_mac"
        );
    }

    #[tokio::test]
    async fn test_new_mac_does_not_fire_without_mac() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        let event = test_event("10.0.0.1", "alice", None);
        let rules = vec![make_rule(1, "new-mac-rule", "new_mac")];

        let firings = evaluate_event(db.pool(), &event, &[], &rules).await;

        assert!(
            firings.is_empty(),
            "event without MAC should not trigger new_mac"
        );
    }

    #[tokio::test]
    async fn test_ip_conflict_fires_on_ip_user_change() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        let event = test_event("10.0.0.1", "alice", Some("AA:BB:CC:DD:EE:01"));
        let rules = vec![make_rule(1, "conflict-rule", "ip_conflict")];

        let conflicts = vec![ConflictRecord {
            id: 1,
            conflict_type: "ip_user_change".to_string(),
            severity: "warning".to_string(),
            ip: Some("10.0.0.1".to_string()),
            mac: None,
            user_old: Some("bob".to_string()),
            user_new: Some("alice".to_string()),
            source: "AdLog".to_string(),
            details: None,
            detected_at: chrono::Utc::now(),
            resolved_at: None,
            resolved_by: None,
        }];

        let firings = evaluate_event(db.pool(), &event, &conflicts, &rules).await;

        assert_eq!(firings.len(), 1);
        assert_eq!(firings[0].rule_type, "ip_conflict");
    }

    #[tokio::test]
    async fn test_ip_conflict_fires_on_duplicate_mac() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        let event = test_event("10.0.0.1", "alice", Some("AA:BB:CC:DD:EE:01"));
        let rules = vec![make_rule(1, "conflict-rule", "ip_conflict")];

        let conflicts = vec![ConflictRecord {
            id: 1,
            conflict_type: "duplicate_mac".to_string(),
            severity: "critical".to_string(),
            ip: Some("10.0.0.1".to_string()),
            mac: Some("AA:BB:CC:DD:EE:01".to_string()),
            user_old: None,
            user_new: Some("alice".to_string()),
            source: "AdLog".to_string(),
            details: None,
            detected_at: chrono::Utc::now(),
            resolved_at: None,
            resolved_by: None,
        }];

        let firings = evaluate_event(db.pool(), &event, &conflicts, &rules).await;

        assert_eq!(firings.len(), 1);
        assert_eq!(firings[0].rule_type, "ip_conflict");
    }

    #[tokio::test]
    async fn test_ip_conflict_ignores_mac_ip_conflict_type() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        let event = test_event("10.0.0.1", "alice", Some("AA:BB:CC:DD:EE:01"));
        let rules = vec![make_rule(1, "conflict-rule", "ip_conflict")];

        let conflicts = vec![ConflictRecord {
            id: 1,
            conflict_type: "mac_ip_conflict".to_string(),
            severity: "info".to_string(),
            ip: Some("10.0.0.1".to_string()),
            mac: Some("AA:BB:CC:DD:EE:01".to_string()),
            user_old: None,
            user_new: Some("alice".to_string()),
            source: "AdLog".to_string(),
            details: None,
            detected_at: chrono::Utc::now(),
            resolved_at: None,
            resolved_by: None,
        }];

        let firings = evaluate_event(db.pool(), &event, &conflicts, &rules).await;

        assert!(
            firings.is_empty(),
            "mac_ip_conflict (info) alone should not trigger ip_conflict rule"
        );
    }

    #[tokio::test]
    async fn test_user_change_fires_when_user_differs_from_mapping() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        db.upsert_mapping(
            test_event("10.0.0.1", "alice", Some("AA:BB:CC:DD:EE:01")),
            None,
        )
        .await
        .unwrap();

        let event = test_event("10.0.0.1", "bob", Some("AA:BB:CC:DD:EE:01"));
        let rules = vec![make_rule(1, "user-change-rule", "user_change")];

        let firings = evaluate_event(db.pool(), &event, &[], &rules).await;

        assert_eq!(firings.len(), 1);
        assert_eq!(firings[0].rule_type, "user_change");
    }

    #[tokio::test]
    async fn test_user_change_does_not_fire_for_same_user() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        db.upsert_mapping(
            test_event("10.0.0.1", "alice", Some("AA:BB:CC:DD:EE:01")),
            None,
        )
        .await
        .unwrap();

        let event = test_event("10.0.0.1", "alice", Some("AA:BB:CC:DD:EE:01"));
        let rules = vec![make_rule(1, "user-change-rule", "user_change")];

        let firings = evaluate_event(db.pool(), &event, &[], &rules).await;

        assert!(
            firings.is_empty(),
            "same user should not trigger user_change"
        );
    }

    #[tokio::test]
    async fn test_user_change_does_not_fire_for_unknown_ip() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        let event = test_event("10.0.0.99", "alice", Some("AA:BB:CC:DD:EE:01"));
        let rules = vec![make_rule(1, "user-change-rule", "user_change")];

        let firings = evaluate_event(db.pool(), &event, &[], &rules).await;

        assert!(
            firings.is_empty(),
            "unmapped IP should not trigger user_change"
        );
    }

    #[tokio::test]
    async fn test_new_subnet_fires_for_empty_subnet() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        let event = test_event("192.168.1.50", "alice", Some("AA:BB:CC:DD:EE:01"));
        let rules = vec![make_rule(1, "new-subnet-rule", "new_subnet")];

        let firings = evaluate_event(db.pool(), &event, &[], &rules).await;

        assert_eq!(firings.len(), 1);
        assert_eq!(firings[0].rule_type, "new_subnet");
    }

    #[tokio::test]
    async fn test_new_subnet_does_not_fire_when_subnet_has_mappings() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        db.upsert_mapping(
            test_event("192.168.1.10", "existing-user", Some("BB:CC:DD:EE:FF:01")),
            None,
        )
        .await
        .unwrap();

        let event = test_event("192.168.1.50", "alice", Some("AA:BB:CC:DD:EE:01"));
        let rules = vec![make_rule(1, "new-subnet-rule", "new_subnet")];

        let firings = evaluate_event(db.pool(), &event, &[], &rules).await;

        assert!(
            firings.is_empty(),
            "subnet with existing mappings should not trigger new_subnet"
        );
    }

    #[test]
    fn test_source_down_never_fires_for_never_seen_adapter() {
        let now = Utc::now();
        let rules = vec![make_source_down_rule(1, "source-down-rule", "AD TLS", 300)];
        let adapters = vec![adapter_status("AD TLS", None, "idle")];
        let mut state = HashMap::new();

        let firings = evaluate_source_down_rules(&adapters, &rules, &mut state, now);

        assert!(firings.is_empty());
        assert_eq!(state.get(&1).unwrap().state, SourceDownState::Unknown);
    }

    #[test]
    fn test_source_down_fires_once_after_silence_threshold() {
        let now = Utc::now();
        let rules = vec![make_source_down_rule(1, "source-down-rule", "AD TLS", 300)];
        let adapters = vec![adapter_status(
            "AD TLS",
            Some(now - chrono::Duration::seconds(301)),
            "idle",
        )];
        let mut state = HashMap::new();

        let first = evaluate_source_down_rules(&adapters, &rules, &mut state, now);
        let second = evaluate_source_down_rules(&adapters, &rules, &mut state, now);

        assert_eq!(first.len(), 1);
        assert_eq!(first[0].source, "AD TLS");
        assert_eq!(first[0].rule_type, "source_down");
        assert!(first[0].ip.is_none());
        assert_eq!(state.get(&1).unwrap().state, SourceDownState::Down);
        assert!(
            second.is_empty(),
            "down adapter should not retrigger without recovery"
        );
    }

    #[test]
    fn test_source_down_recovers_and_rearms_after_new_activity() {
        let now = Utc::now();
        let rules = vec![make_source_down_rule(
            1,
            "source-down-rule",
            "DHCP TLS",
            300,
        )];
        let mut state = HashMap::new();

        let down_snapshot = vec![adapter_status(
            "DHCP TLS",
            Some(now - chrono::Duration::seconds(305)),
            "idle",
        )];
        let recovery_snapshot = vec![adapter_status(
            "DHCP TLS",
            Some(now - chrono::Duration::seconds(5)),
            "active",
        )];
        let down_again_snapshot = vec![adapter_status(
            "DHCP TLS",
            Some(now - chrono::Duration::seconds(400)),
            "idle",
        )];

        let first = evaluate_source_down_rules(&down_snapshot, &rules, &mut state, now);
        let recovery = evaluate_source_down_rules(
            &recovery_snapshot,
            &rules,
            &mut state,
            now + chrono::Duration::seconds(10),
        );
        let second = evaluate_source_down_rules(
            &down_again_snapshot,
            &rules,
            &mut state,
            now + chrono::Duration::seconds(500),
        );

        assert_eq!(first.len(), 1);
        assert!(recovery.is_empty(), "recovery only resets state in v1");
        assert_eq!(state.get(&1).unwrap().state, SourceDownState::Down);
        assert_eq!(second.len(), 1, "adapter should rearm after recovery");
    }

    #[test]
    fn test_source_down_rule_source_change_resets_state_for_new_adapter() {
        let now = Utc::now();
        let stale_ad_snapshot = vec![
            adapter_status("AD TLS", Some(now - chrono::Duration::seconds(305)), "idle"),
            adapter_status(
                "DHCP TLS",
                Some(now - chrono::Duration::seconds(5)),
                "active",
            ),
        ];
        let stale_dhcp_snapshot = vec![
            adapter_status("AD TLS", Some(now - chrono::Duration::seconds(305)), "idle"),
            adapter_status(
                "DHCP TLS",
                Some(now - chrono::Duration::seconds(400)),
                "idle",
            ),
        ];
        let mut state = HashMap::new();

        let initial_rule = vec![make_source_down_rule(1, "source-down-rule", "AD TLS", 300)];
        let initial =
            evaluate_source_down_rules(&stale_ad_snapshot, &initial_rule, &mut state, now);

        let switched_rule = vec![make_source_down_rule(
            1,
            "source-down-rule",
            "DHCP TLS",
            300,
        )];
        let after_switch = evaluate_source_down_rules(
            &stale_ad_snapshot,
            &switched_rule,
            &mut state,
            now + chrono::Duration::seconds(10),
        );

        assert_eq!(initial.len(), 1, "initial stale adapter should fire once");
        assert!(
            after_switch.is_empty(),
            "switch to active adapter should reset state"
        );
        assert_eq!(state.get(&1).unwrap().adapter_name, "DHCP TLS");
        assert_eq!(state.get(&1).unwrap().state, SourceDownState::Up);

        let after_new_silence = evaluate_source_down_rules(
            &stale_dhcp_snapshot,
            &switched_rule,
            &mut state,
            now + chrono::Duration::seconds(500),
        );

        assert_eq!(
            after_new_silence.len(),
            1,
            "new adapter should be able to fire after becoming stale"
        );
        assert_eq!(after_new_silence[0].source, "DHCP TLS");
        assert_eq!(state.get(&1).unwrap().state, SourceDownState::Down);
    }

    #[test]
    fn test_source_down_invalid_conditions_are_skipped() {
        let now = Utc::now();
        let mut bad_rule = make_rule(1, "bad-source-down", "source_down");
        bad_rule.conditions = Some("{\"source\":\"Unknown Adapter\"}".to_string());
        let adapters = vec![adapter_status(
            "AD TLS",
            Some(now - chrono::Duration::seconds(600)),
            "idle",
        )];
        let mut state = HashMap::new();

        let firings = evaluate_source_down_rules(&adapters, &[bad_rule], &mut state, now);

        assert!(firings.is_empty());
        assert!(state.is_empty());
    }

    #[tokio::test]
    async fn test_unknown_rule_type_never_fires() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        let event = test_event("10.0.0.1", "alice", Some("AA:BB:CC:DD:EE:01"));
        let rules = vec![make_rule(1, "bogus-rule", "nonexistent_type")];

        let firings = evaluate_event(db.pool(), &event, &[], &rules).await;

        assert!(firings.is_empty(), "unknown rule type should never fire");
    }

    // ── Phase 1: multiple rules fire independently ──

    #[tokio::test]
    async fn test_multiple_rules_fire_independently() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        db.upsert_mapping(
            test_event("10.0.0.1", "alice", Some("AA:BB:CC:DD:EE:01")),
            None,
        )
        .await
        .unwrap();

        let event = test_event("10.0.0.1", "bob", Some("FF:EE:DD:CC:BB:AA"));
        let conflicts = vec![ConflictRecord {
            id: 1,
            conflict_type: "ip_user_change".to_string(),
            severity: "warning".to_string(),
            ip: Some("10.0.0.1".to_string()),
            mac: None,
            user_old: Some("alice".to_string()),
            user_new: Some("bob".to_string()),
            source: "AdLog".to_string(),
            details: None,
            detected_at: chrono::Utc::now(),
            resolved_at: None,
            resolved_by: None,
        }];
        let rules = vec![
            make_rule(1, "new-mac-rule", "new_mac"),
            make_rule(2, "conflict-rule", "ip_conflict"),
            make_rule(3, "user-change-rule", "user_change"),
        ];

        let firings = evaluate_event(db.pool(), &event, &conflicts, &rules).await;

        let types: Vec<&str> = firings.iter().map(|f| f.rule_type.as_str()).collect();
        assert!(
            types.contains(&"new_mac"),
            "new_mac should fire for unseen MAC"
        );
        assert!(
            types.contains(&"ip_conflict"),
            "ip_conflict should fire for ip_user_change"
        );
        assert!(
            types.contains(&"user_change"),
            "user_change should fire for different user"
        );
    }

    // ── Phase 1: firing details and metadata ──

    #[tokio::test]
    async fn test_firing_metadata_correctness() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        let event = test_event("10.0.0.1", "alice", Some("AA:BB:CC:DD:EE:01"));
        let mut rule = make_rule(42, "test-meta", "new_mac");
        rule.severity = "critical".to_string();
        rule.cooldown_seconds = 120;
        let rules = vec![rule];

        let firings = evaluate_event(db.pool(), &event, &[], &rules).await;

        assert_eq!(firings.len(), 1);
        let f = &firings[0];
        assert_eq!(f.rule_id, 42);
        assert_eq!(f.rule_name, "test-meta");
        assert_eq!(f.severity, "critical");
        assert_eq!(f.ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(f.mac.as_deref(), Some("AA:BB:CC:DD:EE:01"));
        assert_eq!(f.user_name.as_deref(), Some("alice"));
        assert_eq!(f.cooldown_seconds, 120);

        let details: serde_json::Value = serde_json::from_str(&f.details).unwrap();
        assert_eq!(details["event_ip"], "10.0.0.1");
        assert_eq!(details["event_user"], "alice");
    }

    // ── Phase 1: cooldown edge cases ──

    #[tokio::test]
    async fn test_cooldown_different_source_not_shared() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        sqlx::query(
            "INSERT INTO alert_rules (id, name, enabled, rule_type, severity, action_log, cooldown_seconds)
             VALUES (1, 'test-rule', 1, 'new_mac', 'warning', 1, 300)",
        )
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO alert_history (
                rule_id, rule_name, rule_type, severity, ip, mac, user_name, source, details, webhook_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(1_i64)
        .bind("test-rule")
        .bind("new_mac")
        .bind("warning")
        .bind("")
        .bind("AA:BB:CC:DD:EE:FF")
        .bind("alice")
        .bind("AdLog")
        .bind("{}")
        .bind("sent")
        .execute(db.pool())
        .await
        .unwrap();

        let mut firing = sample_firing();
        firing.source = "Radius".to_string();
        assert!(
            !is_on_cooldown(db.pool(), &firing).await,
            "different source should not share cooldown bucket"
        );
    }

    #[tokio::test]
    async fn test_cooldown_different_mac_not_shared() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        sqlx::query(
            "INSERT INTO alert_rules (id, name, enabled, rule_type, severity, action_log, cooldown_seconds)
             VALUES (1, 'test-rule', 1, 'new_mac', 'warning', 1, 300)",
        )
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO alert_history (
                rule_id, rule_name, rule_type, severity, ip, mac, user_name, source, details, webhook_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(1_i64)
        .bind("test-rule")
        .bind("new_mac")
        .bind("warning")
        .bind("")
        .bind("AA:BB:CC:DD:EE:FF")
        .bind("alice")
        .bind("AdLog")
        .bind("{}")
        .bind("sent")
        .execute(db.pool())
        .await
        .unwrap();

        let mut firing = sample_firing();
        firing.mac = Some("11:22:33:44:55:66".to_string());
        assert!(
            !is_on_cooldown(db.pool(), &firing).await,
            "different MAC should not share cooldown bucket"
        );
    }

    // ── Phase 1: webhook security ──

    #[test]
    fn test_is_forbidden_webhook_ip_private_ranges() {
        assert!(is_forbidden_webhook_ip("10.0.0.1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("172.16.0.1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("192.168.1.1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("127.0.0.1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("169.254.1.1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn test_is_forbidden_webhook_ip_ipv6() {
        assert!(is_forbidden_webhook_ip("::1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("fe80::1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("fc00::1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("::".parse().unwrap()));
    }

    #[test]
    fn test_is_forbidden_webhook_ip_allows_public() {
        assert!(!is_forbidden_webhook_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_forbidden_webhook_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_forbidden_webhook_ip(
            "2607:f8b0:4004:800::200e".parse().unwrap()
        ));
    }

    // ── Phase 1: build_extra_headers edge cases ──

    #[test]
    fn test_build_extra_headers_none_input() {
        let headers = build_extra_headers(None);
        assert!(headers.is_some());
        assert!(headers.unwrap().is_empty());
    }

    #[test]
    fn test_build_extra_headers_invalid_json() {
        let headers = build_extra_headers(Some("not json"));
        assert!(headers.is_none());
    }

    #[test]
    fn test_build_extra_headers_skips_non_string_values() {
        let headers =
            build_extra_headers(Some(r#"{"X-Valid":"ok","X-Num":42}"#)).expect("should parse");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0.as_str(), "x-valid");
    }

    // ── Phase 1: load_rules from database ──

    #[tokio::test]
    async fn test_load_rules_returns_only_enabled() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        sqlx::query(
            "INSERT INTO alert_rules (name, enabled, rule_type, severity, action_log, cooldown_seconds)
             VALUES ('enabled-rule', 1, 'new_mac', 'warning', 1, 300)",
        )
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO alert_rules (name, enabled, rule_type, severity, action_log, cooldown_seconds)
             VALUES ('disabled-rule', 0, 'new_mac', 'warning', 1, 300)",
        )
        .execute(db.pool())
        .await
        .unwrap();

        let rules = load_rules(db.pool()).await.unwrap();

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "enabled-rule");
    }

    #[tokio::test]
    async fn test_load_rules_empty_table() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");

        let rules = load_rules(db.pool()).await.unwrap();

        assert!(rules.is_empty());
    }
}
