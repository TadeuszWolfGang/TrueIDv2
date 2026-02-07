CREATE TABLE IF NOT EXISTS sync_status (
    integration    TEXT PRIMARY KEY,
    last_run_at    DATETIME,
    status         TEXT,
    message        TEXT,
    records_synced INTEGER DEFAULT 0
);
