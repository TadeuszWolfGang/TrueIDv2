//! Periodic heartbeat task — sends a syslog HEARTBEAT every 60 seconds.

use crate::transport::syslog;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::info;

/// Spawns a heartbeat loop that sends periodic status messages.
///
/// Parameters: `hostname` - agent hostname, `tx` - framed message channel,
/// `stats` - shared sender counters, `interval` - heartbeat period.
pub async fn run_heartbeat(
    hostname: String,
    tx: mpsc::Sender<Vec<u8>>,
    stats: &crate::transport::tls_sender::SenderStats,
    interval: Duration,
) {
    let start = Instant::now();
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        let uptime = start.elapsed().as_secs();
        let sent = stats.events_sent.load(Ordering::Relaxed);
        let dropped = stats.events_dropped.load(Ordering::Relaxed);
        let payload = syslog::format_heartbeat(&hostname, uptime, sent, dropped);
        let frame = syslog::frame_octet_counting(&payload);
        info!(uptime, sent, dropped, "Sending heartbeat");
        if tx.send(frame).await.is_err() {
            break; // Channel closed.
        }
    }
}
