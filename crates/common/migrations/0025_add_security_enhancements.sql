-- Password history for policy enforcement.
CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id, created_at DESC);

-- TOTP 2FA fields on users.
ALTER TABLE users ADD COLUMN totp_secret_enc TEXT;
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_verified_at TEXT;
ALTER TABLE users ADD COLUMN totp_backup_codes_enc TEXT;

-- Session hardening support.
-- NOTE: sessions.ip_address and sessions.user_agent already exist since migration 0009.
ALTER TABLE sessions ADD COLUMN last_active_at TEXT DEFAULT NULL;

-- Security policy defaults.
INSERT OR IGNORE INTO config (key, value) VALUES
    ('password_min_length', '12'),
    ('password_require_uppercase', 'true'),
    ('password_require_lowercase', 'true'),
    ('password_require_digit', 'true'),
    ('password_require_special', 'false'),
    ('password_history_count', '5'),
    ('password_max_age_days', '0'),
    ('session_max_idle_minutes', '480'),
    ('session_absolute_max_hours', '24'),
    ('totp_required_for_admins', 'false');
