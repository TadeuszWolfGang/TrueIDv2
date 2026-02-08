-- Auth tables: users, sessions, api_keys, audit_log
-- Required for RBAC and authentication system.

CREATE TABLE IF NOT EXISTS users (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    username              TEXT    NOT NULL UNIQUE,
    password_hash         TEXT    NOT NULL,
    role                  TEXT    NOT NULL DEFAULT 'Viewer'
                                  CHECK(role IN ('Admin', 'Operator', 'Viewer')),
    auth_source           TEXT    NOT NULL DEFAULT 'local',
    external_id           TEXT,
    token_version         INTEGER NOT NULL DEFAULT 0,
    force_password_change BOOLEAN NOT NULL DEFAULT false,
    failed_attempts       INTEGER NOT NULL DEFAULT 0,
    locked_until          DATETIME,
    created_at            DATETIME DEFAULT (datetime('now')),
    updated_at            DATETIME DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    id                 INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id            INTEGER  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT     NOT NULL UNIQUE,
    user_agent         TEXT,
    ip_address         TEXT,
    created_at         DATETIME NOT NULL DEFAULT (datetime('now')),
    expires_at         DATETIME NOT NULL,
    last_used_at       DATETIME NOT NULL DEFAULT (datetime('now')),
    revoked_at         DATETIME
);

CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    key_hash    TEXT     NOT NULL UNIQUE,
    key_prefix  TEXT     NOT NULL,
    description TEXT     NOT NULL,
    role        TEXT     NOT NULL CHECK(role IN ('Admin', 'Operator', 'Viewer')),
    created_by  INTEGER  NOT NULL REFERENCES users(id),
    expires_at  DATETIME,
    last_used_at DATETIME,
    is_active   BOOLEAN  NOT NULL DEFAULT true,
    created_at  DATETIME DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER  PRIMARY KEY AUTOINCREMENT,
    timestamp      DATETIME NOT NULL DEFAULT (datetime('now')),
    user_id        INTEGER,
    username       TEXT     NOT NULL,
    principal_type TEXT     NOT NULL DEFAULT 'user'
                            CHECK(principal_type IN ('user', 'api_key', 'system')),
    action         TEXT     NOT NULL,
    target         TEXT,
    details        TEXT,
    ip_address     TEXT,
    request_id     TEXT
);

-- Auto-update updated_at on users table.
CREATE TRIGGER IF NOT EXISTS trg_users_updated_at
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = datetime('now') WHERE id = OLD.id;
END;

-- Indexes: users
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role     ON users(role);

-- Indexes: sessions
CREATE INDEX IF NOT EXISTS idx_sessions_user_id            ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token_hash ON sessions(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at         ON sessions(expires_at);

-- Indexes: api_keys
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash       ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_active_expires  ON api_keys(is_active, expires_at);

-- Indexes: audit_log
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp  ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id    ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_action     ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_username   ON audit_log(username);
CREATE INDEX IF NOT EXISTS idx_audit_log_request_id ON audit_log(request_id);
