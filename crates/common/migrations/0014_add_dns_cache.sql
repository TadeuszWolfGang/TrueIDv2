-- DNS reverse lookup cache with change history.
CREATE TABLE IF NOT EXISTS dns_cache (
    ip TEXT PRIMARY KEY,                -- the IP address (matches mappings.ip)
    hostname TEXT,                      -- current PTR result (NULL if resolution failed)
    previous_hostname TEXT,             -- last known different hostname (for change tracking)
    resolved_at DATETIME,               -- when current hostname was resolved
    expires_at DATETIME,                -- when this entry should be re-resolved
    first_seen DATETIME NOT NULL DEFAULT (datetime('now')),
    last_error TEXT,                    -- last resolution error message (NULL on success)
    resolve_count INTEGER NOT NULL DEFAULT 0  -- total number of resolutions attempted
);

CREATE INDEX IF NOT EXISTS idx_dns_cache_expires ON dns_cache (expires_at);
CREATE INDEX IF NOT EXISTS idx_dns_cache_hostname ON dns_cache (hostname);
