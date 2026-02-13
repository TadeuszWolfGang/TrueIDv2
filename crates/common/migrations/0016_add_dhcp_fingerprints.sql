-- DHCP fingerprint reference table (option 55 patterns -> device type).
CREATE TABLE IF NOT EXISTS dhcp_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    device_type TEXT NOT NULL,
    os_family TEXT,
    description TEXT,
    source TEXT NOT NULL DEFAULT 'builtin',
    created_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_dhcp_fp_device_type ON dhcp_fingerprints (device_type);

-- DHCP observations: raw option 55 data captured per MAC.
CREATE TABLE IF NOT EXISTS dhcp_observations (
    mac TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    device_type TEXT,
    hostname TEXT,
    ip TEXT,
    observed_at DATETIME NOT NULL DEFAULT (datetime('now')),
    match_source TEXT
);

CREATE INDEX IF NOT EXISTS idx_dhcp_obs_fingerprint ON dhcp_observations (fingerprint);
CREATE INDEX IF NOT EXISTS idx_dhcp_obs_device_type ON dhcp_observations (device_type);

-- Add device_type to mappings for fast access.
ALTER TABLE mappings ADD COLUMN device_type TEXT;

-- Seed common fingerprints.
INSERT OR IGNORE INTO dhcp_fingerprints (fingerprint, device_type, os_family, description, source) VALUES
    ('1,3,6,15,31,33,43,44,46,47,119,121,249,252', 'Windows 10/11', 'Windows', 'Modern Windows DHCP client', 'builtin'),
    ('1,3,6,15,31,33,43,44,46,47,119,121,249,252,255', 'Windows 10/11', 'Windows', 'Windows 10/11 variant', 'builtin'),
    ('1,15,3,6,44,46,47,31,33,121,249,43,252', 'Windows 7/8', 'Windows', 'Legacy Windows DHCP client', 'builtin'),
    ('1,121,3,6,15,119,252', 'macOS', 'Apple', 'macOS Ventura/Sonoma', 'builtin'),
    ('1,121,3,6,15,119,252,95,44,46', 'macOS', 'Apple', 'macOS older variant', 'builtin'),
    ('1,3,6,15,119,252', 'macOS', 'Apple', 'macOS minimal', 'builtin'),
    ('1,121,3,6,15,119,252,95', 'iPhone/iPad', 'Apple', 'iOS 16+', 'builtin'),
    ('1,3,6,15,119,252,67,52,13', 'iPhone/iPad', 'Apple', 'iOS legacy', 'builtin'),
    ('1,3,6,28,33,121', 'Android', 'Android', 'Android 12+', 'builtin'),
    ('1,3,6,15,26,28,51,58,59', 'Android', 'Android', 'Android legacy', 'builtin'),
    ('1,3,6,15,26,28,51,58,59,43', 'Android', 'Android', 'Android variant', 'builtin'),
    ('1,28,2,3,15,6,12', 'Linux Desktop', 'Linux', 'NetworkManager/dhclient', 'builtin'),
    ('1,3,6,15,26,28,51,58,59,43,176', 'Linux Server', 'Linux', 'ISC dhclient', 'builtin'),
    ('1,3,6,15,44,46,47,57', 'Printer', 'IoT', 'HP/Canon/Epson network printer', 'builtin'),
    ('1,3,6,15,66,67,43,60', 'VoIP Phone', 'IoT', 'Cisco/Polycom VoIP', 'builtin'),
    ('1,3,6,15,66,67', 'VoIP Phone', 'IoT', 'Generic SIP phone', 'builtin'),
    ('1,3,6,12,15,28,42,40,41,26', 'Smart TV', 'IoT', 'Samsung/LG smart TV', 'builtin'),
    ('1,3,6,15,28,51,58,59', 'Generic Device', 'Unknown', 'Common minimal fingerprint', 'builtin'),
    ('1,3,6', 'Embedded/IoT', 'IoT', 'Minimal DHCP stack - microcontroller or IoT', 'builtin'),
    ('1,3,6,15', 'Network Equipment', 'Network', 'Switch/AP/router requesting basics', 'builtin');
