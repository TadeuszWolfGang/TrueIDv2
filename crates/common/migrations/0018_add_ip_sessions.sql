-- Active sessions per IP (multi-user / terminal server support).
CREATE TABLE IF NOT EXISTS ip_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    user TEXT NOT NULL,
    source TEXT NOT NULL,
    mac TEXT,
    session_start DATETIME NOT NULL DEFAULT (datetime('now')),
    last_seen DATETIME NOT NULL DEFAULT (datetime('now')),
    is_active INTEGER NOT NULL DEFAULT 1,
    UNIQUE(ip, user, source)
);

CREATE INDEX IF NOT EXISTS idx_ip_sessions_ip ON ip_sessions (ip, is_active);
CREATE INDEX IF NOT EXISTS idx_ip_sessions_user ON ip_sessions (user);
CREATE INDEX IF NOT EXISTS idx_ip_sessions_last_seen ON ip_sessions (last_seen);

-- Add multi_user flag to mappings for quick filtering.
ALTER TABLE mappings ADD COLUMN multi_user INTEGER NOT NULL DEFAULT 0;
