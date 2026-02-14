CREATE TABLE IF NOT EXISTS retention_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL UNIQUE,
    retention_days INTEGER NOT NULL DEFAULT 90,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run_at TEXT,
    last_deleted_count INTEGER DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Seed default policies.
INSERT OR IGNORE INTO retention_policies (table_name, retention_days, enabled) VALUES
    ('events', 90, 1),
    ('conflicts', 180, 1),
    ('alert_history', 90, 1),
    ('audit_log', 365, 1),
    ('notification_deliveries', 30, 1),
    ('firewall_push_history', 30, 1),
    ('report_snapshots', 90, 1),
    ('dns_cache', 7, 1);
