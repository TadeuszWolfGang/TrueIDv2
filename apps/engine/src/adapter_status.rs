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
    vpn_addr: &str,
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
            name: "VPN Syslog".into(),
            protocol: "UDP".into(),
            bind: vpn_addr.into(),
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

/// Records adapter activity at the current time.
///
/// Parameters: `adapter_stats` - shared adapter status list, `adapter_name` - monitored adapter
/// name, `count_event` - whether to increment the processed events counter.
pub(crate) async fn record_activity(
    adapter_stats: &Arc<RwLock<Vec<AdapterStatus>>>,
    adapter_name: &str,
    count_event: bool,
) {
    record_activity_at(adapter_stats, adapter_name, count_event, Utc::now()).await;
}

/// Records adapter activity at a specific timestamp.
///
/// This helper exists so tests can drive deterministic timestamps.
pub(crate) async fn record_activity_at(
    adapter_stats: &Arc<RwLock<Vec<AdapterStatus>>>,
    adapter_name: &str,
    count_event: bool,
    observed_at: chrono::DateTime<Utc>,
) {
    let mut stats = adapter_stats.write().await;
    if let Some(adapter) = stats
        .iter_mut()
        .find(|adapter| adapter.name == adapter_name)
    {
        if count_event {
            adapter.events_total += 1;
        }
        adapter.last_event_at = Some(observed_at);
        adapter.status = "active".to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_record_activity_updates_status_without_counting_heartbeat() {
        let stats = Arc::new(RwLock::new(build_initial_adapter_stats(
            "0.0.0.0:1813",
            "0.0.0.0:5514",
            "0.0.0.0:5516",
            "0.0.0.0:5518",
            "0.0.0.0:5615",
            "0.0.0.0:5617",
            true,
        )));
        let observed_at = Utc::now();

        record_activity_at(&stats, "AD TLS", false, observed_at).await;

        let stats = stats.read().await;
        let adapter = stats
            .iter()
            .find(|adapter| adapter.name == "AD TLS")
            .unwrap();
        assert_eq!(adapter.events_total, 0);
        assert_eq!(adapter.last_event_at, Some(observed_at));
        assert_eq!(adapter.status, "active");
    }

    #[tokio::test]
    async fn test_record_activity_increments_events_for_real_traffic() {
        let stats = Arc::new(RwLock::new(build_initial_adapter_stats(
            "0.0.0.0:1813",
            "0.0.0.0:5514",
            "0.0.0.0:5516",
            "0.0.0.0:5518",
            "0.0.0.0:5615",
            "0.0.0.0:5617",
            true,
        )));

        record_activity(&stats, "RADIUS", true).await;
        record_activity(&stats, "RADIUS", true).await;

        let stats = stats.read().await;
        let adapter = stats
            .iter()
            .find(|adapter| adapter.name == "RADIUS")
            .unwrap();
        assert_eq!(adapter.events_total, 2);
        assert_eq!(adapter.status, "active");
        assert!(adapter.last_event_at.is_some());
    }
}
