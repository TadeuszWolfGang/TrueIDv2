//! Shared live-event broadcaster for engine modules.

use std::sync::OnceLock;
use tokio::sync::broadcast;
use trueid_common::live_event::LiveEvent;

static LIVE_TX: OnceLock<broadcast::Sender<LiveEvent>> = OnceLock::new();

/// Registers the process-wide live event sender.
///
/// Parameters: `sender` - broadcast sender used for all SSE events.
/// Returns: nothing.
pub fn set_sender(sender: broadcast::Sender<LiveEvent>) {
    let _ = LIVE_TX.set(sender);
}

/// Broadcasts one live event if sender is initialized.
///
/// Parameters: `event` - event payload to publish.
/// Returns: nothing.
pub fn send(event: LiveEvent) {
    if let Some(tx) = LIVE_TX.get() {
        let _ = tx.send(event);
    }
}
