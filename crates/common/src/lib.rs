//! Shared types, database access, and helpers for TrueID.

pub mod db;
pub mod model;

use anyhow::Result;
use std::env;
use std::net::SocketAddr;

/// Reads an environment variable or returns the default.
///
/// Parameters: `key` - environment variable name, `default_value` - fallback.
/// Returns: resolved string value.
pub fn env_or_default(key: &str, default_value: &str) -> String {
    env::var(key).unwrap_or_else(|_| default_value.to_string())
}

/// Parses a socket address from a string, falling back to a default.
///
/// Parameters: `value` - value to parse, `default_value` - fallback string.
/// Returns: parsed `SocketAddr` or an error.
pub fn parse_socket_addr(value: &str, default_value: &str) -> Result<SocketAddr> {
    let resolved = if value.is_empty() { default_value } else { value };
    Ok(resolved.parse()?)
}
