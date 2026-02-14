-- OIDC provider configuration (max one active provider).
CREATE TABLE IF NOT EXISTS oidc_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    provider_name TEXT NOT NULL DEFAULT 'OIDC',
    issuer_url TEXT NOT NULL DEFAULT '',
    client_id TEXT NOT NULL DEFAULT '',
    client_secret_enc TEXT NOT NULL DEFAULT '',
    redirect_uri TEXT NOT NULL DEFAULT '',
    scopes TEXT NOT NULL DEFAULT 'openid profile email',
    auto_create_users INTEGER NOT NULL DEFAULT 1,
    default_role TEXT NOT NULL DEFAULT 'Viewer' CHECK (default_role IN ('Admin','Operator','Viewer')),
    role_claim TEXT DEFAULT '',
    role_mapping TEXT DEFAULT '{}',
    allow_local_login INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT OR IGNORE INTO oidc_config (id) VALUES (1);

-- OIDC identity linkage.
ALTER TABLE users ADD COLUMN oidc_subject TEXT;
ALTER TABLE users ADD COLUMN oidc_provider TEXT;

CREATE INDEX IF NOT EXISTS idx_users_oidc_subject ON users(oidc_subject);
