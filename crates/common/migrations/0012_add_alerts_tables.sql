-- Alert rule definitions (what to watch for)
CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rule_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'warning',
    conditions TEXT,
    action_webhook_url TEXT,
    action_webhook_headers TEXT,
    action_log BOOLEAN NOT NULL DEFAULT TRUE,
    cooldown_seconds INTEGER NOT NULL DEFAULT 300,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- Alert firing history
CREATE TABLE IF NOT EXISTS alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES alert_rules(id),
    rule_name TEXT NOT NULL,
    rule_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    ip TEXT,
    mac TEXT,
    user_name TEXT,
    source TEXT,
    details TEXT,
    webhook_status TEXT,
    webhook_response TEXT,
    fired_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_alert_history_fired_at ON alert_history (fired_at);
CREATE INDEX IF NOT EXISTS idx_alert_history_rule_id ON alert_history (rule_id);
CREATE INDEX IF NOT EXISTS idx_alert_history_severity ON alert_history (severity);
