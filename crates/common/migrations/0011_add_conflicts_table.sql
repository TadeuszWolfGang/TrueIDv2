CREATE TABLE IF NOT EXISTS conflicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conflict_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'warning',
    ip TEXT,
    mac TEXT,
    user_old TEXT,
    user_new TEXT,
    source TEXT NOT NULL,
    details TEXT,
    detected_at DATETIME NOT NULL DEFAULT (datetime('now')),
    resolved_at DATETIME,
    resolved_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_conflicts_type ON conflicts (conflict_type);
CREATE INDEX IF NOT EXISTS idx_conflicts_severity ON conflicts (severity);
CREATE INDEX IF NOT EXISTS idx_conflicts_detected_at ON conflicts (detected_at);
CREATE INDEX IF NOT EXISTS idx_conflicts_ip ON conflicts (ip);
CREATE INDEX IF NOT EXISTS idx_conflicts_resolved ON conflicts (resolved_at);
