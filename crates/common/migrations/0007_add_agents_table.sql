CREATE TABLE IF NOT EXISTS agents (
    hostname       TEXT PRIMARY KEY,
    last_heartbeat DATETIME NOT NULL,
    uptime_secs    INTEGER NOT NULL DEFAULT 0,
    events_sent    INTEGER NOT NULL DEFAULT 0,
    events_dropped INTEGER NOT NULL DEFAULT 0,
    transport      TEXT NOT NULL DEFAULT 'tls',
    updated_at     DATETIME DEFAULT (datetime('now'))
);
