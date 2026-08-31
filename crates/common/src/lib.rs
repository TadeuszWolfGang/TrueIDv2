//! Shared types, database access, and helpers for TrueID.

pub mod app_config;
pub mod auth_provider;
pub mod db;
pub mod db_analytics;
pub mod db_auth;
pub mod live_event;
pub mod model;
pub mod notification;
pub mod pagination;

use anyhow::Result;
use std::env;
use std::net::SocketAddr;
use subtle::ConstantTimeEq;

/// Compares two byte strings in constant time (timing-attack resistant).
///
/// Parameters: `a` - first value, `b` - second value.
/// Returns: true when equal; length mismatch always returns false.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

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
    let resolved = if value.is_empty() {
        default_value
    } else {
        value
    };
    Ok(resolved.parse()?)
}
