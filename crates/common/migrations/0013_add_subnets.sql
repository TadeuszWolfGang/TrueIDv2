-- Subnet / VLAN definitions for network topology awareness.
CREATE TABLE IF NOT EXISTS subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL UNIQUE,          -- e.g. "10.1.2.0/24"
    name TEXT NOT NULL,                 -- human label, e.g. "Office Floor 3"
    vlan_id INTEGER,                    -- optional 802.1Q VLAN tag
    location TEXT,                      -- physical location / site
    description TEXT,                   -- free-text notes
    gateway TEXT,                       -- default gateway IP
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_subnets_vlan ON subnets (vlan_id);

-- Add subnet reference to mappings (nullable — not all IPs are in known subnets).
ALTER TABLE mappings ADD COLUMN subnet_id INTEGER REFERENCES subnets(id);
CREATE INDEX IF NOT EXISTS idx_mappings_subnet_id ON mappings (subnet_id);
