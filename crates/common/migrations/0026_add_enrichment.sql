-- GeoIP cache for IP-level network context enrichment.
CREATE TABLE IF NOT EXISTS ip_geo_cache (
    ip TEXT PRIMARY KEY,
    country_code TEXT,
    country_name TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL,
    asn INTEGER,
    as_org TEXT,
    is_private INTEGER NOT NULL DEFAULT 0,
    resolved_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_ip_geo_cache_resolved ON ip_geo_cache(resolved_at);

-- Passive subnet discovery from observed traffic.
CREATE TABLE IF NOT EXISTS discovered_subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL UNIQUE,
    ip_count INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    promoted INTEGER NOT NULL DEFAULT 0,
    promoted_subnet_id INTEGER REFERENCES subnets(id)
);
CREATE INDEX IF NOT EXISTS idx_discovered_subnets_count ON discovered_subnets(ip_count DESC);

-- Manual IP tags for contextual classification.
CREATE TABLE IF NOT EXISTS ip_tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    tag TEXT NOT NULL,
    color TEXT DEFAULT '#6b8579',
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(ip, tag)
);
CREATE INDEX IF NOT EXISTS idx_ip_tags_ip ON ip_tags(ip);
CREATE INDEX IF NOT EXISTS idx_ip_tags_tag ON ip_tags(tag);

-- Denormalized geo columns in mappings for faster API projection.
ALTER TABLE mappings ADD COLUMN country_code TEXT;
ALTER TABLE mappings ADD COLUMN city TEXT;
