CREATE TABLE IF NOT EXISTS report_schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    report_type TEXT NOT NULL CHECK (report_type IN ('daily', 'weekly', 'compliance')),
    schedule_cron TEXT NOT NULL DEFAULT '0 8 * * 1',
    enabled INTEGER NOT NULL DEFAULT 1,
    channel_ids TEXT NOT NULL DEFAULT '[]',
    include_sections TEXT NOT NULL DEFAULT '["summary","conflicts","alerts"]',
    last_sent_at TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
