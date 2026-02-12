-- Speed up text search and time-range queries
CREATE INDEX IF NOT EXISTS idx_events_ip ON events (ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON events (user);
CREATE INDEX IF NOT EXISTS idx_events_source ON events (source);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_mappings_user ON mappings (user);
CREATE INDEX IF NOT EXISTS idx_mappings_source ON mappings (source);
CREATE INDEX IF NOT EXISTS idx_mappings_mac ON mappings (mac);
CREATE INDEX IF NOT EXISTS idx_mappings_last_seen ON mappings (last_seen);
