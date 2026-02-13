-- Firewall targets for User-ID push.
CREATE TABLE IF NOT EXISTS firewall_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    firewall_type TEXT NOT NULL CHECK(firewall_type IN ('panos', 'fortigate')),
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    -- Credentials (encrypted at rest).
    username TEXT,
    password_enc TEXT,
    verify_tls INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    push_interval_secs INTEGER NOT NULL DEFAULT 60,
    -- Optional: only push mappings from specific subnets (comma-separated subnet IDs, NULL = all).
    subnet_filter TEXT,
    -- Push status tracking.
    last_push_at DATETIME,
    last_push_status TEXT,
    last_push_count INTEGER DEFAULT 0,
    last_push_error TEXT,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_fw_targets_host ON firewall_targets (host, port);

-- Push history log.
CREATE TABLE IF NOT EXISTS firewall_push_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES firewall_targets(id) ON DELETE CASCADE,
    pushed_at DATETIME NOT NULL DEFAULT (datetime('now')),
    mapping_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    error_message TEXT,
    duration_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_fw_push_hist_target ON firewall_push_history (target_id, pushed_at DESC);
