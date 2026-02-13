-- SNMP switch configuration.
CREATE TABLE IF NOT EXISTS snmp_switches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,            -- switch management IP
    name TEXT NOT NULL,                 -- human label e.g. "Core Switch Floor 3"
    community_encrypted TEXT NOT NULL,  -- SNMPv2c community string (encrypted with CONFIG_ENCRYPTION_KEY)
    snmp_version TEXT NOT NULL DEFAULT 'v2c',
    port INTEGER NOT NULL DEFAULT 161,  -- SNMP UDP port
    poll_interval_secs INTEGER NOT NULL DEFAULT 300,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    subnet_id INTEGER REFERENCES subnets(id),
    location TEXT,
    last_polled_at DATETIME,
    last_poll_status TEXT,
    last_poll_error TEXT,
    mac_count INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- Discovered MAC -> switch port mappings.
CREATE TABLE IF NOT EXISTS switch_port_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id INTEGER NOT NULL REFERENCES snmp_switches(id) ON DELETE CASCADE,
    mac TEXT NOT NULL,                  -- lowercase colon-separated
    port_index INTEGER NOT NULL,        -- bridge port index from BRIDGE-MIB
    if_index INTEGER,                   -- ifIndex from dot1dBasePortIfIndex
    port_name TEXT,                     -- interface name from ifDescr
    vlan_id INTEGER,                    -- reserved for future enrichment
    first_seen DATETIME NOT NULL DEFAULT (datetime('now')),
    last_seen DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(switch_id, mac)
);

CREATE INDEX IF NOT EXISTS idx_spm_mac ON switch_port_mappings (mac);
CREATE INDEX IF NOT EXISTS idx_spm_switch ON switch_port_mappings (switch_id);
CREATE INDEX IF NOT EXISTS idx_spm_port_name ON switch_port_mappings (port_name);
