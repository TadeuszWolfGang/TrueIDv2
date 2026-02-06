//! Agent configuration loaded from `config.toml`.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Top-level agent configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    pub target: TargetConfig,
    pub tls: TlsConfig,
    pub agent: AgentSection,
    #[serde(default)]
    pub connection: ConnectionConfig,
}

/// Server address and ports.
#[derive(Debug, Clone, Deserialize)]
pub struct TargetConfig {
    pub server: String,
    #[serde(default = "default_ad_port")]
    pub ad_port: u16,
    #[serde(default = "default_dhcp_port")]
    pub dhcp_port: u16,
}

/// TLS certificate paths.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub ca_cert: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
}

/// Agent behaviour settings.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentSection {
    #[serde(default = "default_mode")]
    pub mode: AgentMode,
    pub hostname: Option<String>,
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

/// Connection resilience settings.
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionConfig {
    #[serde(default = "default_reconnect_secs")]
    pub reconnect_interval_secs: u64,
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            reconnect_interval_secs: default_reconnect_secs(),
            keepalive_secs: default_keepalive_secs(),
        }
    }
}

/// Operating mode of the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentMode {
    Ad,
    Dhcp,
    Both,
}

/// Loads and parses agent configuration from a TOML file.
///
/// Parameters: `path` - filesystem path to config.toml.
/// Returns: parsed `AgentConfig` or an error.
pub fn load_config(path: &Path) -> Result<AgentConfig> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file: {}", path.display()))?;
    let config: AgentConfig =
        toml::from_str(&contents).with_context(|| "parsing config.toml")?;
    Ok(config)
}

/// Returns the system hostname or a fallback.
///
/// Parameters: `override_name` - optional user-configured hostname.
/// Returns: resolved hostname string.
pub fn resolve_hostname(override_name: Option<&str>) -> String {
    if let Some(name) = override_name {
        return name.to_string();
    }
    hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

fn default_ad_port() -> u16 { 5615 }
fn default_dhcp_port() -> u16 { 5617 }
fn default_mode() -> AgentMode { AgentMode::Ad }
fn default_buffer_size() -> usize { 1000 }
fn default_reconnect_secs() -> u64 { 5 }
fn default_keepalive_secs() -> u64 { 30 }
