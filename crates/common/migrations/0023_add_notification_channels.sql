-- Notification channel definitions for alert delivery.
CREATE TABLE IF NOT EXISTS notification_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    channel_type TEXT NOT NULL CHECK (channel_type IN ('email', 'slack', 'teams', 'webhook')),
    enabled INTEGER NOT NULL DEFAULT 1,
    config_enc TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Many-to-many: alert rules -> notification channels.
CREATE TABLE IF NOT EXISTS alert_rule_channels (
    rule_id INTEGER NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    channel_id INTEGER NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, channel_id)
);

-- Delivery log for debugging.
CREATE TABLE IF NOT EXISTS notification_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id INTEGER NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    alert_history_id INTEGER REFERENCES alert_history(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (status IN ('sent', 'failed', 'skipped')),
    error_message TEXT,
    delivered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_notification_deliveries_channel
    ON notification_deliveries(channel_id, delivered_at DESC);
