//! Notification channel models shared between web and engine.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Channel-specific configuration stored as encrypted JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChannelConfig {
    /// SMTP email notifications.
    Email {
        smtp_host: String,
        smtp_port: u16,
        smtp_tls: bool,
        smtp_user: Option<String>,
        smtp_pass: Option<String>,
        from_address: String,
        to_addresses: Vec<String>,
        subject_prefix: Option<String>,
    },
    /// Slack incoming webhook notifications.
    Slack {
        webhook_url: String,
        channel: Option<String>,
        username: Option<String>,
        icon_emoji: Option<String>,
    },
    /// Microsoft Teams incoming webhook notifications.
    Teams { webhook_url: String },
    /// Generic webhook notifications.
    Webhook {
        url: String,
        headers: Option<HashMap<String, String>>,
        method: Option<String>,
    },
}

impl ChannelConfig {
    /// Builds a secret-safe summary string for API responses.
    ///
    /// Parameters: none.
    /// Returns: human-readable config summary.
    pub fn summary(&self) -> String {
        match self {
            Self::Email {
                smtp_host,
                smtp_port,
                to_addresses,
                ..
            } => {
                let recipients = if to_addresses.is_empty() {
                    "-".to_string()
                } else {
                    to_addresses.join(", ")
                };
                format!("smtp://{smtp_host}:{smtp_port} -> {recipients}")
            }
            Self::Slack { channel, .. } => channel
                .as_deref()
                .map(|v| format!("Slack {v}"))
                .unwrap_or_else(|| "Slack default channel".to_string()),
            Self::Teams { .. } => "Teams webhook configured".to_string(),
            Self::Webhook { method, url, .. } => {
                let m = method
                    .as_deref()
                    .filter(|v| !v.trim().is_empty())
                    .unwrap_or("POST")
                    .to_uppercase();
                format!("{m} {url}")
            }
        }
    }
}

/// API response for channel (never includes secrets).
#[derive(Debug, Clone, Serialize)]
pub struct ChannelResponse {
    pub id: i64,
    pub name: String,
    pub channel_type: String,
    pub enabled: bool,
    pub config_summary: String,
    pub created_at: String,
    pub updated_at: String,
}
