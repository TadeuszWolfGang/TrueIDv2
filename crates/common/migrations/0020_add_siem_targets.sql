-- SIEM forwarding targets.
CREATE TABLE IF NOT EXISTS siem_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    format TEXT NOT NULL CHECK(format IN ('cef', 'leef', 'json')),
    transport TEXT NOT NULL CHECK(transport IN ('udp', 'tcp')),
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    -- What to forward.
    forward_mappings INTEGER NOT NULL DEFAULT 1,
    forward_conflicts INTEGER NOT NULL DEFAULT 1,
    forward_alerts INTEGER NOT NULL DEFAULT 1,
    -- Status.
    last_forward_at DATETIME,
    last_error TEXT,
    events_forwarded INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_siem_host_port ON siem_targets (host, port);
