//! Notification dispatcher for alert channels.

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::json;
use sqlx::Row;
use std::collections::HashMap;
use std::sync::Arc;
use trueid_common::db::Db;
use trueid_common::notification::ChannelConfig;

/// Normalized alert payload used by notification integrations.
#[derive(Debug, Clone)]
pub struct AlertPayload {
    pub rule_name: String,
    pub rule_type: String,
    pub severity: String,
    pub ip: Option<String>,
    pub user: Option<String>,
    pub details: String,
    pub timestamp: DateTime<Utc>,
}

/// Delivery result for one notification channel.
#[derive(Debug, Clone)]
pub struct DeliveryResult {
    pub channel_name: String,
    pub outcome: std::result::Result<(), String>,
}

#[derive(Debug, Clone)]
struct NotificationChannel {
    id: i64,
    name: String,
    channel_type: String,
    config: ChannelConfig,
}

/// Notification dispatcher reading channels from DB and delivering alerts.
#[derive(Clone)]
pub struct NotificationDispatcher {
    db: Arc<Db>,
    http_client: reqwest::Client,
}

impl NotificationDispatcher {
    /// Creates a dispatcher bound to shared DB and HTTP client.
    ///
    /// Parameters: `db` - shared DB handle, `http_client` - shared HTTP client.
    /// Returns: initialized dispatcher.
    pub fn new(db: Arc<Db>, http_client: reqwest::Client) -> Self {
        Self { db, http_client }
    }

    /// Sends alert to all channels linked to the given rule.
    ///
    /// Parameters: `rule_id` - alert rule id, `alert` - alert payload, `alert_history_id` - optional history reference.
    /// Returns: per-channel delivery results.
    pub async fn dispatch_alert(
        &self,
        rule_id: i64,
        alert: &AlertPayload,
        alert_history_id: Option<i64>,
    ) -> Vec<DeliveryResult> {
        let channels = match self.load_channels_for_rule(rule_id).await {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let mut results = Vec::with_capacity(channels.len());
        for channel in channels {
            let outcome = self.dispatch_channel(&channel, alert).await;
            let status = if outcome.is_ok() { "sent" } else { "failed" };
            let error_message = outcome.as_ref().err().map(|e| e.to_string());
            let _ = self
                .record_delivery(
                    channel.id,
                    alert_history_id,
                    status,
                    error_message.as_deref(),
                )
                .await;
            results.push(DeliveryResult {
                channel_name: channel.name.clone(),
                outcome: outcome.map_err(|e| e.to_string()),
            });
        }
        results
    }

    /// Sends a test notification for a single channel.
    ///
    /// Parameters: `channel_id` - channel id.
    /// Returns: success when test message is delivered.
    pub async fn send_test_channel(&self, channel_id: i64) -> Result<()> {
        let channel = self
            .load_channel_by_id(channel_id)
            .await?
            .ok_or_else(|| anyhow!("Notification channel not found"))?;
        let payload = AlertPayload {
            rule_name: "TrueID Test".to_string(),
            rule_type: "test".to_string(),
            severity: "info".to_string(),
            ip: None,
            user: None,
            details: "Notification channel configured successfully".to_string(),
            timestamp: Utc::now(),
        };
        self.dispatch_channel(&channel, &payload).await
    }

    /// Loads all enabled channels linked to a rule.
    ///
    /// Parameters: `rule_id` - alert rule id.
    /// Returns: decrypted channel definitions.
    async fn load_channels_for_rule(&self, rule_id: i64) -> Result<Vec<NotificationChannel>> {
        let rows = sqlx::query(
            "SELECT nc.id, nc.name, nc.channel_type, nc.config_enc
             FROM alert_rule_channels arc
             JOIN notification_channels nc ON nc.id = arc.channel_id
             WHERE arc.rule_id = ? AND nc.enabled = 1
             ORDER BY nc.id ASC",
        )
        .bind(rule_id)
        .fetch_all(self.db.pool())
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let cfg_enc: String = row.try_get("config_enc").unwrap_or_default();
            let raw = self.db.decrypt_config_value(&cfg_enc)?;
            let cfg: ChannelConfig = serde_json::from_str(&raw)?;
            out.push(NotificationChannel {
                id: row.try_get("id").unwrap_or_default(),
                name: row.try_get("name").unwrap_or_default(),
                channel_type: row.try_get("channel_type").unwrap_or_default(),
                config: cfg,
            });
        }
        Ok(out)
    }

    /// Loads one channel by id (enabled or disabled).
    ///
    /// Parameters: `channel_id` - channel id.
    /// Returns: optional decrypted channel.
    async fn load_channel_by_id(&self, channel_id: i64) -> Result<Option<NotificationChannel>> {
        let row = sqlx::query(
            "SELECT id, name, channel_type, config_enc
             FROM notification_channels
             WHERE id = ?",
        )
        .bind(channel_id)
        .fetch_optional(self.db.pool())
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let cfg_enc: String = row.try_get("config_enc").unwrap_or_default();
        let raw = self.db.decrypt_config_value(&cfg_enc)?;
        let cfg: ChannelConfig = serde_json::from_str(&raw)?;
        Ok(Some(NotificationChannel {
            id: row.try_get("id").unwrap_or_default(),
            name: row.try_get("name").unwrap_or_default(),
            channel_type: row.try_get("channel_type").unwrap_or_default(),
            config: cfg,
        }))
    }

    /// Records one notification delivery in database.
    ///
    /// Parameters: `channel_id` - channel id, `alert_history_id` - optional alert history id, `status` - sent/failed/skipped, `error_message` - optional error.
    /// Returns: insert result.
    async fn record_delivery(
        &self,
        channel_id: i64,
        alert_history_id: Option<i64>,
        status: &str,
        error_message: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO notification_deliveries (channel_id, alert_history_id, status, error_message)
             VALUES (?, ?, ?, ?)",
        )
        .bind(channel_id)
        .bind(alert_history_id)
        .bind(status)
        .bind(error_message)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// Dispatches a payload to one channel by config variant.
    ///
    /// Parameters: `channel` - target channel, `alert` - alert payload.
    /// Returns: delivery result.
    async fn dispatch_channel(&self, channel: &NotificationChannel, alert: &AlertPayload) -> Result<()> {
        match (&channel.channel_type[..], &channel.config) {
            ("email", ChannelConfig::Email { .. }) => self.send_email(&channel.config, alert).await,
            ("slack", ChannelConfig::Slack { .. }) => self.send_slack(&channel.config, alert).await,
            ("teams", ChannelConfig::Teams { .. }) => self.send_teams(&channel.config, alert).await,
            ("webhook", ChannelConfig::Webhook { .. }) => {
                self.send_generic_webhook(&channel.config, alert).await
            }
            _ => Err(anyhow!("Notification channel type/config mismatch")),
        }
    }

    /// Sends alert as HTML email via SMTP.
    ///
    /// Parameters: `config` - typed channel config, `alert` - alert payload.
    /// Returns: SMTP send result.
    async fn send_email(&self, config: &ChannelConfig, alert: &AlertPayload) -> Result<()> {
        let ChannelConfig::Email {
            smtp_host,
            smtp_port,
            smtp_tls,
            smtp_user,
            smtp_pass,
            from_address,
            to_addresses,
            subject_prefix,
        } = config
        else {
            return Err(anyhow!("Invalid email channel config"));
        };

        let mut builder = Message::builder()
            .from(from_address.parse().context("invalid from_address")?)
            .subject(format!(
                "{} {} - {}",
                subject_prefix.as_deref().unwrap_or("[TrueID]"),
                alert.severity.to_uppercase(),
                alert.rule_name
            ))
            .header(ContentType::TEXT_HTML);
        for recipient in to_addresses {
            builder = builder.to(recipient.parse().context("invalid recipient")?);
        }
        let message = builder
            .body(format_email_body(alert))
            .context("failed to build email message")?;

        let mut transport_builder = if *smtp_tls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(smtp_host)
                .context("failed to create STARTTLS SMTP transport")?
                .port(*smtp_port)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(smtp_host).port(*smtp_port)
        };
        if let (Some(user), Some(pass)) = (smtp_user.as_ref(), smtp_pass.as_ref()) {
            transport_builder =
                transport_builder.credentials(Credentials::new(user.clone(), pass.clone()));
        }
        transport_builder
            .build()
            .send(message)
            .await
            .context("SMTP send failed")?;
        Ok(())
    }

    /// Sends alert to Slack webhook endpoint.
    ///
    /// Parameters: `config` - typed channel config, `alert` - alert payload.
    /// Returns: HTTP send result.
    async fn send_slack(&self, config: &ChannelConfig, alert: &AlertPayload) -> Result<()> {
        let ChannelConfig::Slack {
            webhook_url,
            channel,
            username,
            icon_emoji,
        } = config
        else {
            return Err(anyhow!("Invalid Slack channel config"));
        };
        let color = match alert.severity.as_str() {
            "critical" => "#ef4444",
            "warning" => "#f59e0b",
            _ => "#3b82f6",
        };
        let payload = json!({
            "channel": channel,
            "username": username.as_deref().unwrap_or("TrueID"),
            "icon_emoji": icon_emoji.as_deref().unwrap_or(":shield:"),
            "attachments": [{
                "color": color,
                "title": format!("{} Alert: {}", alert.severity.to_uppercase(), alert.rule_name),
                "fields": [
                    {"title": "Type", "value": alert.rule_type, "short": true},
                    {"title": "Severity", "value": alert.severity, "short": true},
                    {"title": "IP", "value": alert.ip.clone().unwrap_or_else(|| "-".to_string()), "short": true},
                    {"title": "User", "value": alert.user.clone().unwrap_or_else(|| "-".to_string()), "short": true}
                ],
                "footer": "TrueID Identity Correlation Engine",
                "ts": alert.timestamp.timestamp(),
            }]
        });
        let resp = self.http_client.post(webhook_url).json(&payload).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Slack webhook returned HTTP {}", resp.status()));
        }
        Ok(())
    }

    /// Sends alert to Teams webhook endpoint as adaptive card.
    ///
    /// Parameters: `config` - typed channel config, `alert` - alert payload.
    /// Returns: HTTP send result.
    async fn send_teams(&self, config: &ChannelConfig, alert: &AlertPayload) -> Result<()> {
        let ChannelConfig::Teams { webhook_url } = config else {
            return Err(anyhow!("Invalid Teams channel config"));
        };
        let color = match alert.severity.as_str() {
            "critical" => "attention",
            "warning" => "warning",
            _ => "accent",
        };
        let payload = json!({
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "text": format!("TrueID Alert: {}", alert.rule_name), "weight": "Bolder", "size": "Medium", "color": color},
                        {"type": "FactSet", "facts": [
                            {"title": "Severity", "value": alert.severity},
                            {"title": "Type", "value": alert.rule_type},
                            {"title": "IP", "value": alert.ip.clone().unwrap_or_else(|| "-".to_string())},
                            {"title": "User", "value": alert.user.clone().unwrap_or_else(|| "-".to_string())},
                            {"title": "Time", "value": alert.timestamp.to_rfc3339()},
                        ]}
                    ]
                }
            }]
        });
        let resp = self.http_client.post(webhook_url).json(&payload).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Teams webhook returned HTTP {}", resp.status()));
        }
        Ok(())
    }

    /// Sends alert to generic webhook with configurable method and headers.
    ///
    /// Parameters: `config` - typed webhook channel config, `alert` - alert payload.
    /// Returns: HTTP send result.
    async fn send_generic_webhook(&self, config: &ChannelConfig, alert: &AlertPayload) -> Result<()> {
        let ChannelConfig::Webhook {
            url,
            headers,
            method,
        } = config
        else {
            return Err(anyhow!("Invalid webhook channel config"));
        };
        let method_norm = method
            .as_deref()
            .unwrap_or("POST")
            .trim()
            .to_uppercase();
        let req_method = if method_norm == "PUT" {
            reqwest::Method::PUT
        } else {
            reqwest::Method::POST
        };
        let payload = json!({
            "type": "alert",
            "rule_name": alert.rule_name,
            "rule_type": alert.rule_type,
            "severity": alert.severity,
            "ip": alert.ip,
            "user": alert.user,
            "details": alert.details,
            "timestamp": alert.timestamp.to_rfc3339(),
        });
        let mut req = self.http_client.request(req_method, url).json(&payload);
        if let Some(map) = headers {
            for (k, v) in map {
                req = req.header(k, v);
            }
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Webhook returned HTTP {}", resp.status()));
        }
        Ok(())
    }
}

/// Renders a compact HTML email body for alert notifications.
///
/// Parameters: `alert` - alert payload.
/// Returns: HTML email body string.
fn format_email_body(alert: &AlertPayload) -> String {
    let mut rows = HashMap::new();
    rows.insert("Rule", alert.rule_name.clone());
    rows.insert("Type", alert.rule_type.clone());
    rows.insert("Severity", alert.severity.clone());
    rows.insert(
        "IP",
        alert.ip.clone().unwrap_or_else(|| "-".to_string()),
    );
    rows.insert(
        "User",
        alert.user.clone().unwrap_or_else(|| "-".to_string()),
    );
    rows.insert("Time", alert.timestamp.to_rfc3339());
    let details = alert.details.replace('<', "&lt;").replace('>', "&gt;");
    let mut fields_html = String::new();
    for (k, v) in rows {
        fields_html.push_str(&format!(
            "<tr><td style=\"padding:6px 10px;border:1px solid #d9e0e6;font-weight:600;\">{k}</td>\
             <td style=\"padding:6px 10px;border:1px solid #d9e0e6;\">{v}</td></tr>"
        ));
    }
    format!(
        "<html><body style=\"font-family:Arial,Helvetica,sans-serif;color:#111;\">\
         <h2 style=\"margin:0 0 12px;\">TrueID Alert Notification</h2>\
         <table style=\"border-collapse:collapse;\">{fields_html}</table>\
         <p style=\"margin-top:12px;\"><strong>Details:</strong></p>\
         <pre style=\"background:#f5f7fa;padding:10px;border:1px solid #d9e0e6;\">{details}</pre>\
         </body></html>"
    )
}
