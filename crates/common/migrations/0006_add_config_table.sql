CREATE TABLE IF NOT EXISTS config (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at DATETIME DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO config (key, value) VALUES
    ('stale_ttl_minutes', '5'),
    ('janitor_interval_secs', '60'),
    ('source_priority_radius', '3'),
    ('source_priority_adlog', '2'),
    ('source_priority_dhcplease', '1'),
    ('source_priority_manual', '0'),
    ('default_confidence_radius', '100'),
    ('default_confidence_adlog', '90'),
    ('default_confidence_dhcplease', '60'),
    ('default_confidence_manual', '100');
