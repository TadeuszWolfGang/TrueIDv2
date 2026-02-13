-- User→group memberships from LDAP sync.
CREATE TABLE IF NOT EXISTS user_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    group_name TEXT NOT NULL,
    display_name TEXT,
    department TEXT,
    synced_at DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(username, group_name)
);

CREATE INDEX IF NOT EXISTS idx_user_groups_username ON user_groups (username);
CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups (group_name);

-- LDAP connection configuration (single row).
CREATE TABLE IF NOT EXISTS ldap_config (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    ldap_url TEXT NOT NULL DEFAULT 'ldap://dc.corp.local:389',
    bind_dn TEXT NOT NULL DEFAULT 'CN=TrueID Service,OU=Service Accounts,DC=corp,DC=local',
    bind_password_enc TEXT,
    base_dn TEXT NOT NULL DEFAULT 'DC=corp,DC=local',
    search_filter TEXT NOT NULL DEFAULT '(&(objectClass=user)(sAMAccountName=*))',
    sync_interval_secs INTEGER NOT NULL DEFAULT 300,
    enabled INTEGER NOT NULL DEFAULT 0,
    last_sync_at DATETIME,
    last_sync_status TEXT,
    last_sync_count INTEGER DEFAULT 0,
    last_sync_error TEXT,
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO ldap_config (id) VALUES (1);
