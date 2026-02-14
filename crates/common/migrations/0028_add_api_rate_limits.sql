-- Per-key rate limit overrides.
ALTER TABLE api_keys ADD COLUMN rate_limit_rpm INTEGER NOT NULL DEFAULT 100;
ALTER TABLE api_keys ADD COLUMN rate_limit_burst INTEGER NOT NULL DEFAULT 20;

-- API usage hourly rollup.
CREATE TABLE IF NOT EXISTS api_usage_hourly (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key_id INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    hour TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(api_key_id, hour)
);

CREATE INDEX IF NOT EXISTS idx_api_usage_key_hour
    ON api_usage_hourly(api_key_id, hour DESC);
