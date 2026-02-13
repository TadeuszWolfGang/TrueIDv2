//! In-memory adapter status helpers.

use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use trueid_common::model::AdapterStatus;

/// Builds initial adapter status list for admin monitoring.
///
/// Parameters: bind addresses and TLS-enabled flag.
/// Returns: prefilled adapter status entries.
pub(crate) fn build_initial_adapter_stats(
    radius_addr: &str,
    ad_addr: &str,
    dhcp_addr: &str,
    ad_tls_addr: &str,
    dhcp_tls_addr: &str,
    tls_enabled: bool,
) -> Vec<AdapterStatus> {
    let tls_status = if tls_enabled { "idle" } else { "disabled" };
    vec![
        AdapterStatus {
            name: "RADIUS".into(),
            protocol: "UDP".into(),
            bind: radius_addr.into(),
            status: "idle".into(),
            last_event_at: None,
            events_total: 0,
        },
        AdapterStatus {
            name: "AD Syslog".into(),
            protocol: "UDP".into(),
            bind: ad_addr.into(),
            status: "idle".into(),
            last_event_at: None,
            events_total: 0,
        },
        AdapterStatus {
            name: "DHCP Syslog".into(),
            protocol: "UDP".into(),
            bind: dhcp_addr.into(),
            status: "idle".into(),
            last_event_at: None,
            events_total: 0,
        },
        AdapterStatus {
            name: "AD TLS".into(),
            protocol: "TCP+TLS".into(),
            bind: ad_tls_addr.into(),
            status: tls_status.into(),
            last_event_at: None,
            events_total: 0,
        },
        AdapterStatus {
            name: "DHCP TLS".into(),
            protocol: "TCP+TLS".into(),
            bind: dhcp_tls_addr.into(),
            status: tls_status.into(),
            last_event_at: None,
            events_total: 0,
        },
    ]
}

/// Starts periodic adapter status recomputation task.
///
/// Parameters: `adapter_stats` - shared in-memory adapter statuses.
/// Returns: nothing.
pub(crate) fn start_adapter_status_updater(adapter_stats: Arc<RwLock<Vec<AdapterStatus>>>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let now = Utc::now();
            let mut stats = adapter_stats.write().await;
            for adapter in stats.iter_mut() {
                if adapter.status == "disabled" {
                    continue;
                }
                adapter.status = match adapter.last_event_at {
                    Some(ts) if (now - ts).num_minutes() < 5 => "active".into(),
                    Some(_) => "idle".into(),
                    None => "idle".into(),
                };
            }
        }
    });
}
