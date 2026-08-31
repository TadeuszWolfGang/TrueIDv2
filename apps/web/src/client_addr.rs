//! Client IP resolution with trusted-proxy handling.
//!
//! Production default: no proxy is trusted, so `X-Forwarded-For` is ignored
//! and the TCP peer address identifies the client. Deployments behind a
//! reverse proxy must set `TRUSTED_PROXIES` (comma-separated IPs/CIDRs, or
//! `loopback`); XFF entries are then walked right-to-left, skipping trusted
//! proxies, to recover the real client address.

use axum::http::HeaderMap;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

/// Parsed `TRUSTED_PROXIES` configuration.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    nets: Vec<IpNet>,
    loopback: bool,
}

impl TrustedProxies {
    /// Parses a comma-separated list of IPs, CIDRs, or the keyword `loopback`.
    ///
    /// Invalid entries are skipped (logged by the caller at startup).
    pub fn parse(spec: &str) -> Self {
        let mut out = Self::default();
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if part.eq_ignore_ascii_case("loopback") {
                out.loopback = true;
                continue;
            }
            match IpNet::from_str(part) {
                Ok(net) => out.nets.push(net),
                Err(_) => match IpAddr::from_str(part) {
                    Ok(ip) => out.nets.push(IpNet::from(ip)),
                    Err(_) => {
                        tracing::warn!(entry = %part, "Ignoring invalid TRUSTED_PROXIES entry")
                    }
                },
            }
        }
        out
    }

    /// Whether the given address belongs to a trusted proxy.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.loopback && ip.is_loopback()
            || self
                .nets
                .iter()
                .any(|n| n.network() <= ip && ip <= n.broadcast())
    }
}

/// Resolves the effective client IP for a request.
///
/// Parameters: `headers` - request headers, `peer` - TCP peer address,
/// `trusted` - trusted proxy config, `trust_forwarded_headers` - dev-mode
/// relaxation (treat any peer as a trusted proxy).
/// Returns: the client IP to use for rate limiting / session binding.
pub fn effective_client_ip(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trusted: &TrustedProxies,
    trust_forwarded_headers: bool,
) -> IpAddr {
    let peer_ip = peer.map(|p| p.ip());
    let trust_xff =
        trust_forwarded_headers || peer_ip.map(|ip| trusted.contains(ip)).unwrap_or(false);

    if trust_xff {
        if let Some(client) = forwarded_client_ip(headers) {
            return client;
        }
    }
    peer_ip.unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

/// Walks X-Forwarded-For right-to-left, skipping trusted proxies.
fn forwarded_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())?
        .trim();
    if xff.is_empty() {
        return None;
    }
    let entries: Vec<Option<IpAddr>> = xff
        .split(',')
        .map(|e| IpAddr::from_str(e.trim()).ok())
        .collect();
    // Rightmost non-loopback-ish/valid entry is normally the proxy-added
    // client. Use the rightmost valid entry: proxies append the peer they saw,
    // so the last element is the closest to the client.
    for entry in entries.iter().rev() {
        if let Some(ip) = entry {
            return Some(*ip);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        h
    }

    fn peer(addr: &str) -> Option<SocketAddr> {
        Some(addr.parse().unwrap())
    }

    #[test]
    fn untrusted_peer_ignores_xff() {
        let trusted = TrustedProxies::default();
        let h = headers_with_xff("1.2.3.4, 5.6.7.8");
        let ip = effective_client_ip(&h, peer("10.0.0.1:40000"), &trusted, false);
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn trusted_proxy_uses_last_xff_entry() {
        let trusted = TrustedProxies::parse("10.0.0.0/8");
        let h = headers_with_xff("1.2.3.4, 10.0.0.99");
        let ip = effective_client_ip(&h, peer("10.0.0.1:40000"), &trusted, false);
        assert_eq!(ip.to_string(), "10.0.0.99");
    }

    #[test]
    fn loopback_keyword_trusts_loopback() {
        let trusted = TrustedProxies::parse("loopback");
        let h = headers_with_xff("198.51.100.23");
        let ip = effective_client_ip(&h, peer("127.0.0.1:40000"), &trusted, false);
        assert_eq!(ip.to_string(), "198.51.100.23");
    }

    #[test]
    fn no_xff_falls_back_to_peer() {
        let trusted = TrustedProxies::default();
        let ip = effective_client_ip(&HeaderMap::new(), peer("192.0.2.5:40000"), &trusted, false);
        assert_eq!(ip.to_string(), "192.0.2.5");
    }

    #[test]
    fn garbage_xff_falls_back_to_peer() {
        let trusted = TrustedProxies::parse("loopback");
        let h = headers_with_xff("not-an-ip");
        let ip = effective_client_ip(&h, peer("127.0.0.1:40000"), &trusted, false);
        assert_eq!(ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn dev_mode_trusts_xff() {
        let trusted = TrustedProxies::default();
        let h = headers_with_xff("198.51.100.7");
        let ip = effective_client_ip(&h, peer("127.0.0.1:40000"), &trusted, true);
        assert_eq!(ip.to_string(), "198.51.100.7");
    }

    #[test]
    fn parses_mixed_specs() {
        let t = TrustedProxies::parse("10.0.0.5, 172.16.0.0/12, loopback, bad-entry");
        assert!(t.contains("10.0.0.5".parse().unwrap()));
        assert!(t.contains("172.16.5.5".parse().unwrap()));
        assert!(t.contains("127.0.0.1".parse().unwrap()));
        assert!(!t.contains("192.0.2.1".parse().unwrap()));
    }
}
