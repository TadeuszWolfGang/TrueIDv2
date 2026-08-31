//! Shared outbound-webhook SSRF guard.
//!
//! Validates webhook destinations before dispatch: scheme allowlist, DNS
//! resolution, rejection of private/loopback/link-local/ULA addresses, and
//! DNS pinning metadata so callers can build rebinding-resistant clients.
//! Used by both the legacy alert-rule webhook path and the notification
//! channel dispatcher.

use std::net::{IpAddr, SocketAddr};
use tokio::net::lookup_host;

/// Resolved webhook endpoint with DNS pinning metadata.
#[derive(Debug)]
pub struct ResolvedWebhookTarget {
    pub host: String,
    pub addrs: Vec<SocketAddr>,
    pub requires_dns_pinning: bool,
}

/// Resolves a webhook URL and rejects loopback/private/link-local destinations.
///
/// Parameters: `url` - target webhook URL.
/// Returns: resolved target with pinned addresses or a rejection reason.
pub async fn resolve_webhook_target(
    url: &str,
) -> std::result::Result<ResolvedWebhookTarget, String> {
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
pub fn is_forbidden_webhook_ip(ip: IpAddr) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ranges_are_forbidden() {
        assert!(is_forbidden_webhook_ip("10.0.0.1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("172.16.0.1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("192.168.1.1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("127.0.0.1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("169.254.1.1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn ipv6_local_ranges_are_forbidden() {
        assert!(is_forbidden_webhook_ip("::1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("fe80::1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("fc00::1".parse().unwrap()));
        assert!(is_forbidden_webhook_ip("::".parse().unwrap()));
    }

    #[test]
    fn public_addresses_are_allowed() {
        assert!(!is_forbidden_webhook_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_forbidden_webhook_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_forbidden_webhook_ip(
            "2606:4700:4700::1111".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn literal_loopback_url_is_rejected() {
        let err = resolve_webhook_target("http://127.0.0.1:8080/engine/mappings")
            .await
            .unwrap_err();
        assert!(err.contains("disallowed address"), "{err}");
    }

    #[tokio::test]
    async fn literal_link_local_url_is_rejected() {
        let err = resolve_webhook_target("http://169.254.169.254/latest/meta-data/")
            .await
            .unwrap_err();
        assert!(err.contains("disallowed address"), "{err}");
    }

    #[tokio::test]
    async fn non_http_scheme_is_rejected() {
        let err = resolve_webhook_target("file:///etc/passwd")
            .await
            .unwrap_err();
        assert!(err.contains("unsupported webhook URL scheme"), "{err}");
    }

    #[tokio::test]
    async fn unresolvable_host_is_rejected() {
        let err = resolve_webhook_target("https://this-host-must-not-exist.invalid.hook")
            .await
            .unwrap_err();
        assert!(err.contains("host resolution failed"), "{err}");
    }
}
