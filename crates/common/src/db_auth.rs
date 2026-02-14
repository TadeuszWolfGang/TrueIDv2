//! Auth-related database operations: users, sessions, API keys, audit log.
//!
//! All methods are `impl Db` blocks extending the core `Db` struct from `db.rs`.
//! Password hashing uses Argon2id with explicit parameters.

use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::Row;
use tracing::info;

use crate::db::Db;
use crate::model::{ApiKeyRecord, ApiKeyUsageHourly, AuditEntry, Session, User, UserPublic, UserRole};

// ── Password hashing (module-level functions) ──────────────

/// Builds an Argon2id hasher with explicit parameters.
///
/// Parameters: `pepper` — optional pepper prepended to password.
/// Returns: configured `Argon2` instance.
fn argon2_hasher(pepper: Option<&str>) -> Argon2<'_> {
    let params = Params::new(19456, 2, 1, Some(32)).expect("valid argon2 params");
    let mut builder = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    if let Some(p) = pepper {
        builder = Argon2::new_with_secret(
            p.as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(19456, 2, 1, Some(32)).expect("valid argon2 params"),
        )
        .expect("valid argon2 secret");
    }
    builder
}

/// Hashes a password with Argon2id.
///
/// Parameters: `password` — plaintext password, `pepper` — optional pepper.
/// Returns: PHC-format hash string.
pub fn hash_password(password: &str, pepper: Option<&str>) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hasher = argon2_hasher(pepper);
    let hash = hasher
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("password hashing failed: {e}"))?;
    Ok(hash.to_string())
}

/// Verifies a password against a stored Argon2id hash.
///
/// Parameters: `password` — plaintext password, `hash` — stored PHC hash,
/// `pepper` — optional pepper.
/// Returns: `true` if password matches.
pub fn verify_password(password: &str, hash: &str, pepper: Option<&str>) -> Result<bool> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| anyhow::anyhow!("invalid password hash format: {e}"))?;
    let hasher = argon2_hasher(pepper);
    Ok(hasher.verify_password(password.as_bytes(), &parsed).is_ok())
}

/// Computes SHA-256 hex digest of the input.
///
/// Parameters: `input` — data to hash.
/// Returns: lowercase hex string.
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ── Helper: parse a User row ───────────────────────────────

/// Extracts a `User` from a sqlx Row.
fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<User> {
    let role_str: String = row.try_get("role")?;
    let role: UserRole = role_str.parse()?;
    Ok(User {
        id: row.try_get("id")?,
        username: row.try_get("username")?,
        password_hash: row.try_get("password_hash")?,
        role,
        auth_source: row.try_get("auth_source")?,
        external_id: row.try_get("external_id")?,
        token_version: row.try_get("token_version")?,
        force_password_change: row.try_get("force_password_change")?,
        totp_enabled: row.try_get("totp_enabled").unwrap_or(false),
        totp_verified_at: row.try_get("totp_verified_at").ok(),
        failed_attempts: row.try_get("failed_attempts")?,
        locked_until: row.try_get("locked_until")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

// ── User methods ───────────────────────────────────────────

impl Db {
    /// Creates a new user with a hashed password.
    ///
    /// Parameters: `username`, `password` (plaintext), `role`.
    /// Returns: created `User`.
    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: UserRole,
    ) -> Result<User> {
        let pw_hash = hash_password(password, self.pepper())?;
        let role_str = role.to_string();
        sqlx::query(
            "INSERT INTO users (username, password_hash, role)
             VALUES (?, ?, ?)",
        )
        .bind(username)
        .bind(&pw_hash)
        .bind(&role_str)
        .execute(self.pool())
        .await?;

        self.get_user_by_username(username)
            .await?
            .context("user not found after insert")
    }

    /// Looks up a user by username.
    ///
    /// Parameters: `username`.
    /// Returns: `Some(User)` if found.
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, username, password_hash, role, auth_source, external_id,
                    token_version, force_password_change, totp_enabled, totp_verified_at, failed_attempts,
                    locked_until, created_at, updated_at
             FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(self.pool())
        .await?;

        match row {
            Some(r) => Ok(Some(user_from_row(&r)?)),
            None => Ok(None),
        }
    }

    /// Looks up a user by ID.
    ///
    /// Parameters: `id` — user primary key.
    /// Returns: `Some(User)` if found.
    pub async fn get_user_by_id(&self, id: i64) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, username, password_hash, role, auth_source, external_id,
                    token_version, force_password_change, totp_enabled, totp_verified_at, failed_attempts,
                    locked_until, created_at, updated_at
             FROM users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await?;

        match row {
            Some(r) => Ok(Some(user_from_row(&r)?)),
            None => Ok(None),
        }
    }

    /// Lists all users (safe projection, no password hashes).
    ///
    /// Returns: list of `UserPublic`.
    pub async fn list_users(&self) -> Result<Vec<UserPublic>> {
        let rows = sqlx::query(
            "SELECT id, username, password_hash, role, auth_source, external_id,
                    token_version, force_password_change, totp_enabled, totp_verified_at, failed_attempts,
                    locked_until, created_at, updated_at
             FROM users ORDER BY id",
        )
        .fetch_all(self.pool())
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(UserPublic::from(user_from_row(&r)?));
        }
        Ok(out)
    }

    /// Updates a user's role and bumps token_version to invalidate JWTs.
    ///
    /// Parameters: `user_id`, `new_role`.
    pub async fn update_user_role(&self, user_id: i64, new_role: UserRole) -> Result<()> {
        sqlx::query(
            "UPDATE users SET role = ?, token_version = token_version + 1
             WHERE id = ?",
        )
        .bind(new_role.to_string())
        .bind(user_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Changes a user's password. Bumps token_version, clears force flag and
    /// failed attempts.
    ///
    /// Parameters: `user_id`, `new_password` (plaintext).
    pub async fn change_password(&self, user_id: i64, new_password: &str) -> Result<()> {
        let pw_hash = hash_password(new_password, self.pepper())?;
        sqlx::query(
            "UPDATE users
             SET password_hash = ?, token_version = token_version + 1,
                 force_password_change = false, failed_attempts = 0
             WHERE id = ?",
        )
        .bind(&pw_hash)
        .bind(user_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Deletes a user by ID.
    ///
    /// Parameters: `user_id`.
    /// Returns: `true` if a row was deleted.
    pub async fn delete_user(&self, user_id: i64) -> Result<bool> {
        let res = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(user_id)
            .execute(self.pool())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Bumps token_version to globally invalidate all JWTs for a user.
    ///
    /// Parameters: `user_id`.
    pub async fn bump_token_version(&self, user_id: i64) -> Result<()> {
        sqlx::query("UPDATE users SET token_version = token_version + 1 WHERE id = ?")
            .bind(user_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Records a failed login attempt. Locks account after 5 failures (30 min).
    ///
    /// Parameters: `username`.
    pub async fn record_failed_login(&self, username: &str) -> Result<()> {
        let lock_until = Utc::now() + Duration::minutes(30);
        sqlx::query(
            "UPDATE users
             SET failed_attempts = failed_attempts + 1,
                 locked_until = CASE
                     WHEN failed_attempts + 1 >= 5 THEN ?
                     ELSE locked_until
                 END
             WHERE username = ?",
        )
        .bind(lock_until)
        .bind(username)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Resets failed login counter for a user.
    ///
    /// Parameters: `user_id`.
    pub async fn reset_failed_attempts(&self, user_id: i64) -> Result<()> {
        sqlx::query("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?")
            .bind(user_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Checks whether an account is currently locked.
    ///
    /// Parameters: `user` — user record.
    /// Returns: `true` if locked_until is in the future.
    pub fn is_account_locked(&self, user: &User) -> bool {
        user.locked_until.map(|t| t > Utc::now()).unwrap_or(false)
    }

    /// Counts total user rows.
    ///
    /// Returns: user count.
    pub async fn count_users(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as c FROM users")
            .fetch_one(self.pool())
            .await?;
        Ok(row.try_get("c")?)
    }

    /// Sets force_password_change flag on a user.
    ///
    /// Parameters: `user_id`, `force` — new flag value.
    pub async fn set_force_password_change(&self, user_id: i64, force: bool) -> Result<()> {
        sqlx::query("UPDATE users SET force_password_change = ? WHERE id = ?")
            .bind(force)
            .bind(user_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Returns encrypted TOTP secret for a user.
    ///
    /// Parameters: `user_id` - user id.
    /// Returns: encrypted secret if present.
    pub async fn get_user_totp_secret_enc(&self, user_id: i64) -> Result<Option<String>> {
        let row = sqlx::query("SELECT totp_secret_enc FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(self.pool())
            .await?;
        Ok(row.and_then(|r| r.try_get("totp_secret_enc").ok()))
    }

    /// Stores encrypted TOTP secret and resets TOTP state.
    ///
    /// Parameters: `user_id` - user id, `secret_enc` - encrypted secret.
    /// Returns: none.
    pub async fn set_user_totp_secret_enc(&self, user_id: i64, secret_enc: &str) -> Result<()> {
        sqlx::query(
            "UPDATE users
             SET totp_secret_enc = ?, totp_enabled = 0, totp_verified_at = NULL, totp_backup_codes_enc = NULL, updated_at = datetime('now')
             WHERE id = ?",
        )
        .bind(secret_enc)
        .bind(user_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Enables TOTP and persists encrypted backup codes.
    ///
    /// Parameters: `user_id` - user id, `backup_codes_enc` - encrypted backup codes JSON.
    /// Returns: none.
    pub async fn enable_user_totp(&self, user_id: i64, backup_codes_enc: &str) -> Result<()> {
        sqlx::query(
            "UPDATE users
             SET totp_enabled = 1, totp_verified_at = datetime('now'), totp_backup_codes_enc = ?, updated_at = datetime('now')
             WHERE id = ?",
        )
        .bind(backup_codes_enc)
        .bind(user_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Disables TOTP for a user and clears related secrets.
    ///
    /// Parameters: `user_id` - user id.
    /// Returns: none.
    pub async fn disable_user_totp(&self, user_id: i64) -> Result<()> {
        sqlx::query(
            "UPDATE users
             SET totp_enabled = 0, totp_secret_enc = NULL, totp_verified_at = NULL, totp_backup_codes_enc = NULL, updated_at = datetime('now')
             WHERE id = ?",
        )
        .bind(user_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Returns encrypted TOTP backup codes for a user.
    ///
    /// Parameters: `user_id` - user id.
    /// Returns: encrypted JSON list or none.
    pub async fn get_user_totp_backup_codes_enc(&self, user_id: i64) -> Result<Option<String>> {
        let row = sqlx::query("SELECT totp_backup_codes_enc FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(self.pool())
            .await?;
        Ok(row.and_then(|r| r.try_get("totp_backup_codes_enc").ok()))
    }

    /// Updates encrypted TOTP backup codes value.
    ///
    /// Parameters: `user_id` - user id, `backup_codes_enc` - encrypted JSON string or null.
    /// Returns: none.
    pub async fn set_user_totp_backup_codes_enc(
        &self,
        user_id: i64,
        backup_codes_enc: Option<&str>,
    ) -> Result<()> {
        sqlx::query("UPDATE users SET totp_backup_codes_enc = ?, updated_at = datetime('now') WHERE id = ?")
            .bind(backup_codes_enc)
            .bind(user_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Adds one password hash to password history.
    ///
    /// Parameters: `user_id` - user id, `password_hash` - PHC hash to store.
    /// Returns: none.
    pub async fn insert_password_history(&self, user_id: i64, password_hash: &str) -> Result<()> {
        sqlx::query("INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)")
            .bind(user_id)
            .bind(password_hash)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Returns most recent password hashes for password history checks.
    ///
    /// Parameters: `user_id` - user id, `limit` - max number of rows.
    /// Returns: list of password hashes.
    pub async fn get_password_history_hashes(&self, user_id: i64, limit: i64) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT password_hash
             FROM password_history
             WHERE user_id = ?
             ORDER BY created_at DESC
             LIMIT ?",
        )
        .bind(user_id)
        .bind(limit.max(0))
        .fetch_all(self.pool())
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(row.try_get("password_hash")?);
        }
        Ok(out)
    }

    /// Counts users with Admin role.
    ///
    /// Returns: admin count.
    pub async fn count_admins(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as c FROM users WHERE role = 'Admin'")
            .fetch_one(self.pool())
            .await?;
        Ok(row.try_get("c")?)
    }
}

// ── Session methods ────────────────────────────────────────

impl Db {
    /// Creates a new refresh-token session.
    ///
    /// Parameters: `user_id`, `refresh_token_hash` (SHA-256), `user_agent`,
    /// `ip`, `expires_at`.
    /// Returns: created `Session`.
    pub async fn create_session(
        &self,
        user_id: i64,
        refresh_token_hash: &str,
        user_agent: Option<&str>,
        ip: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> Result<Session> {
        sqlx::query(
            "INSERT INTO sessions (user_id, refresh_token_hash, user_agent, ip_address, expires_at, last_active_at)
             VALUES (?, ?, ?, ?, ?, datetime('now'))",
        )
        .bind(user_id)
        .bind(refresh_token_hash)
        .bind(user_agent)
        .bind(ip)
        .bind(expires_at)
        .execute(self.pool())
        .await?;

        self.get_session_by_token_hash(refresh_token_hash)
            .await?
            .context("session not found after insert")
    }

    /// Fetches an active (not revoked, not expired) session by token hash.
    ///
    /// Parameters: `hash` — SHA-256 hex of the refresh token.
    /// Returns: `Some(Session)` if valid.
    pub async fn get_session_by_token_hash(&self, hash: &str) -> Result<Option<Session>> {
        let row = sqlx::query(
            "SELECT id, user_id, refresh_token_hash, user_agent, ip_address,
                    created_at, expires_at, last_active_at, last_used_at, revoked_at
             FROM sessions
             WHERE refresh_token_hash = ? AND revoked_at IS NULL AND expires_at > datetime('now')",
        )
        .bind(hash)
        .fetch_optional(self.pool())
        .await?;

        match row {
            Some(r) => Ok(Some(session_from_row(&r)?)),
            None => Ok(None),
        }
    }

    /// Rotates a refresh token: revokes old, creates new in a transaction.
    ///
    /// If old token is already revoked (replay attack), revokes ALL sessions
    /// for the user and returns `None`.
    ///
    /// Parameters: `old_hash`, `new_hash`, `new_expires_at`.
    /// Returns: `Some(Session)` on success, `None` on reuse detection.
    pub async fn rotate_session(
        &self,
        old_hash: &str,
        new_hash: &str,
        new_expires_at: DateTime<Utc>,
    ) -> Result<Option<Session>> {
        let mut tx = self.pool().begin().await?;

        // Find old session (including revoked ones for reuse detection).
        let old_row = sqlx::query(
            "SELECT id, user_id, refresh_token_hash, user_agent, ip_address,
                    created_at, expires_at, last_active_at, last_used_at, revoked_at
             FROM sessions WHERE refresh_token_hash = ?",
        )
        .bind(old_hash)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(old_row) = old_row else {
            return Ok(None);
        };

        let old_session = session_from_row(&old_row)?;

        // Token reuse detection: already revoked → revoke ALL sessions.
        if old_session.revoked_at.is_some() {
            sqlx::query(
                "UPDATE sessions SET revoked_at = datetime('now')
                 WHERE user_id = ? AND revoked_at IS NULL",
            )
            .bind(old_session.user_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(None);
        }

        // Expired check.
        if old_session.expires_at < Utc::now() {
            return Ok(None);
        }

        // Revoke old session.
        sqlx::query("UPDATE sessions SET revoked_at = datetime('now') WHERE id = ?")
            .bind(old_session.id)
            .execute(&mut *tx)
            .await?;

        // Create new session.
        sqlx::query(
            "INSERT INTO sessions (user_id, refresh_token_hash, user_agent, ip_address, expires_at, last_active_at)
             VALUES (?, ?, ?, ?, ?, datetime('now'))",
        )
        .bind(old_session.user_id)
        .bind(new_hash)
        .bind(&old_session.user_agent)
        .bind(&old_session.ip_address)
        .bind(new_expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let new_session = self.get_session_by_token_hash(new_hash).await?;
        Ok(new_session)
    }

    /// Revokes a single session.
    ///
    /// Parameters: `session_id`.
    pub async fn revoke_session(&self, session_id: i64) -> Result<()> {
        sqlx::query("UPDATE sessions SET revoked_at = datetime('now') WHERE id = ?")
            .bind(session_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Revokes all active sessions for a user.
    ///
    /// Parameters: `user_id`.
    /// Returns: number of revoked sessions.
    pub async fn revoke_all_sessions(&self, user_id: i64) -> Result<u64> {
        let res = sqlx::query(
            "UPDATE sessions SET revoked_at = datetime('now')
             WHERE user_id = ? AND revoked_at IS NULL",
        )
        .bind(user_id)
        .execute(self.pool())
        .await?;
        Ok(res.rows_affected())
    }

    /// Lists active (not revoked, not expired) sessions for a user.
    ///
    /// Parameters: `user_id`.
    /// Returns: list of active `Session` records.
    pub async fn list_active_sessions(&self, user_id: i64) -> Result<Vec<Session>> {
        let rows = sqlx::query(
            "SELECT id, user_id, refresh_token_hash, user_agent, ip_address,
                    created_at, expires_at, last_active_at, last_used_at, revoked_at
             FROM sessions
             WHERE user_id = ? AND revoked_at IS NULL AND expires_at > datetime('now')
             ORDER BY last_used_at DESC",
        )
        .bind(user_id)
        .fetch_all(self.pool())
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(session_from_row(&r)?);
        }
        Ok(out)
    }

    /// Deletes sessions expired more than 7 days ago.
    ///
    /// Returns: number of deleted rows.
    pub async fn cleanup_expired_sessions(&self) -> Result<u64> {
        let res = sqlx::query("DELETE FROM sessions WHERE expires_at < datetime('now', '-7 days')")
            .execute(self.pool())
            .await?;
        Ok(res.rows_affected())
    }

    /// Updates session activity timestamps to current time.
    ///
    /// Parameters: `session_id` - session id to touch.
    /// Returns: none.
    pub async fn touch_session_activity(&self, session_id: i64) -> Result<()> {
        sqlx::query(
            "UPDATE sessions
             SET last_used_at = datetime('now'), last_active_at = datetime('now')
             WHERE id = ?",
        )
        .bind(session_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Fetches a non-revoked session by token hash for security checks.
    ///
    /// Parameters: `hash` - refresh token hash.
    /// Returns: session if exists.
    pub async fn get_session_for_security_checks(&self, hash: &str) -> Result<Option<Session>> {
        let row = sqlx::query(
            "SELECT id, user_id, refresh_token_hash, user_agent, ip_address,
                    created_at, expires_at, last_active_at, last_used_at, revoked_at
             FROM sessions
             WHERE refresh_token_hash = ? AND revoked_at IS NULL",
        )
        .bind(hash)
        .fetch_optional(self.pool())
        .await?;
        match row {
            Some(r) => Ok(Some(session_from_row(&r)?)),
            None => Ok(None),
        }
    }

    /// Lists active sessions for all users.
    ///
    /// Returns: `(session, username)` tuples ordered by recent usage.
    pub async fn list_all_active_sessions(&self) -> Result<Vec<(Session, String)>> {
        let rows = sqlx::query(
            "SELECT s.id, s.user_id, s.refresh_token_hash, s.user_agent, s.ip_address,
                    s.created_at, s.expires_at, s.last_active_at, s.last_used_at, s.revoked_at,
                    u.username
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.revoked_at IS NULL AND s.expires_at > datetime('now')
             ORDER BY s.last_used_at DESC",
        )
        .fetch_all(self.pool())
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push((session_from_row(&row)?, row.try_get("username")?));
        }
        Ok(out)
    }
}

// ── API key methods ────────────────────────────────────────

impl Db {
    /// Creates a new API key. Returns the raw key (visible only once) and record.
    ///
    /// Parameters: `description`, `role`, `created_by` (user ID),
    /// `expires_at` (optional).
    /// Returns: `(raw_key, ApiKeyRecord)`.
    pub async fn create_api_key(
        &self,
        description: &str,
        role: UserRole,
        created_by: i64,
        expires_at: Option<DateTime<Utc>>,
        rate_limit_rpm: i64,
        rate_limit_burst: i64,
    ) -> Result<(String, ApiKeyRecord)> {
        let raw_key = generate_api_key();
        let key_hash = sha256_hex(&raw_key);
        let key_prefix = &raw_key[..12]; // "tid_" + 8 chars

        sqlx::query(
            "INSERT INTO api_keys (key_hash, key_prefix, description, role, created_by, expires_at, rate_limit_rpm, rate_limit_burst)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&key_hash)
        .bind(key_prefix)
        .bind(description)
        .bind(role.to_string())
        .bind(created_by)
        .bind(expires_at)
        .bind(rate_limit_rpm)
        .bind(rate_limit_burst)
        .execute(self.pool())
        .await?;

        let record = sqlx::query(
            "SELECT id, key_hash, key_prefix, description, role, created_by,
                    expires_at, last_used_at, is_active, rate_limit_rpm, rate_limit_burst, created_at
             FROM api_keys WHERE key_hash = ?",
        )
        .bind(&key_hash)
        .fetch_one(self.pool())
        .await?;

        Ok((raw_key, api_key_from_row(&record)?))
    }

    /// Validates a raw API key. Updates last_used_at on success.
    ///
    /// Parameters: `raw_key` — the full API key string.
    /// Returns: `Some(ApiKeyRecord)` if valid and active.
    pub async fn validate_api_key(&self, raw_key: &str) -> Result<Option<ApiKeyRecord>> {
        let Some(record) = self.lookup_api_key(raw_key).await? else {
            return Ok(None);
        };

        // Update last_used_at.
        sqlx::query("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?")
            .bind(record.id)
            .execute(self.pool())
            .await?;

        Ok(Some(record))
    }

    /// Looks up and validates a raw API key without updating usage timestamp.
    ///
    /// Parameters: `raw_key` - full API key.
    /// Returns: `Some(ApiKeyRecord)` when active and not expired.
    pub async fn lookup_api_key(&self, raw_key: &str) -> Result<Option<ApiKeyRecord>> {
        let key_hash = sha256_hex(raw_key);
        let row = sqlx::query(
            "SELECT id, key_hash, key_prefix, description, role, created_by,
                    expires_at, last_used_at, is_active, rate_limit_rpm, rate_limit_burst, created_at
             FROM api_keys
             WHERE key_hash = ? AND is_active = true",
        )
        .bind(&key_hash)
        .fetch_optional(self.pool())
        .await?;

        let Some(r) = row else { return Ok(None) };
        let record = api_key_from_row(&r)?;

        // Check expiry.
        if let Some(exp) = record.expires_at {
            if exp < Utc::now() {
                return Ok(None);
            }
        }
        Ok(Some(record))
    }

    /// Lists all API keys (hash never serialized).
    ///
    /// Returns: list of `ApiKeyRecord`.
    pub async fn list_api_keys(&self) -> Result<Vec<ApiKeyRecord>> {
        let rows = sqlx::query(
            "SELECT id, key_hash, key_prefix, description, role, created_by,
                    expires_at, last_used_at, is_active, rate_limit_rpm, rate_limit_burst, created_at
             FROM api_keys ORDER BY created_at DESC",
        )
        .fetch_all(self.pool())
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(api_key_from_row(&r)?);
        }
        Ok(out)
    }

    /// Revokes an API key (soft delete: is_active = false).
    ///
    /// Parameters: `key_id`.
    /// Returns: `true` if a row was updated.
    pub async fn revoke_api_key(&self, key_id: i64) -> Result<bool> {
        let res = sqlx::query("UPDATE api_keys SET is_active = false WHERE id = ?")
            .bind(key_id)
            .execute(self.pool())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Returns one API key by ID.
    ///
    /// Parameters: `key_id` - API key ID.
    /// Returns: optional `ApiKeyRecord` when found.
    pub async fn get_api_key_by_id(&self, key_id: i64) -> Result<Option<ApiKeyRecord>> {
        let row = sqlx::query(
            "SELECT id, key_hash, key_prefix, description, role, created_by,
                    expires_at, last_used_at, is_active, rate_limit_rpm, rate_limit_burst, created_at
             FROM api_keys WHERE id = ?",
        )
        .bind(key_id)
        .fetch_optional(self.pool())
        .await?;
        row.map(|r| api_key_from_row(&r)).transpose()
    }

    /// Updates per-key API rate limits.
    ///
    /// Parameters: `key_id` - API key ID, `rpm` - requests per minute, `burst` - bucket size.
    /// Returns: `true` when a key row was updated.
    pub async fn update_api_key_limits(&self, key_id: i64, rpm: i64, burst: i64) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE api_keys SET rate_limit_rpm = ?, rate_limit_burst = ? WHERE id = ?",
        )
        .bind(rpm)
        .bind(burst)
        .bind(key_id)
        .execute(self.pool())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Increments hourly API usage counters for one key.
    ///
    /// Parameters: `api_key_id` - API key ID, `is_error` - true for 4xx/5xx responses.
    /// Returns: nothing.
    pub async fn record_api_key_usage(&self, api_key_id: i64, is_error: bool) -> Result<()> {
        let err = if is_error { 1 } else { 0 };
        sqlx::query(
            "INSERT INTO api_usage_hourly (api_key_id, hour, request_count, error_count)
             VALUES (?, strftime('%Y-%m-%dT%H:00:00Z', 'now'), 1, ?)
             ON CONFLICT(api_key_id, hour) DO UPDATE SET
                 request_count = request_count + 1,
                 error_count = error_count + ?",
        )
        .bind(api_key_id)
        .bind(err)
        .bind(err)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Lists hourly API usage for a key within the lookback window.
    ///
    /// Parameters: `api_key_id` - API key ID, `days` - lookback period in days.
    /// Returns: hourly rows ordered ascending by hour.
    pub async fn list_api_key_usage_hourly(
        &self,
        api_key_id: i64,
        days: i64,
    ) -> Result<Vec<ApiKeyUsageHourly>> {
        let rows = sqlx::query(
            "SELECT hour, request_count, error_count
             FROM api_usage_hourly
             WHERE api_key_id = ? AND hour >= strftime('%Y-%m-%dT%H:00:00Z', 'now', '-' || ? || ' days')
             ORDER BY hour ASC",
        )
        .bind(api_key_id)
        .bind(days)
        .fetch_all(self.pool())
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(ApiKeyUsageHourly {
                hour: row.try_get("hour")?,
                requests: row.try_get("request_count")?,
                errors: row.try_get("error_count")?,
            });
        }
        Ok(out)
    }

    /// Returns total API usage counters for a key within the lookback window.
    ///
    /// Parameters: `api_key_id` - API key ID, `days` - lookback period in days.
    /// Returns: tuple `(total_requests, total_errors)`.
    pub async fn sum_api_key_usage(&self, api_key_id: i64, days: i64) -> Result<(i64, i64)> {
        let row = sqlx::query(
            "SELECT COALESCE(SUM(request_count), 0) AS requests,
                    COALESCE(SUM(error_count), 0) AS errors
             FROM api_usage_hourly
             WHERE api_key_id = ? AND hour >= strftime('%Y-%m-%dT%H:00:00Z', 'now', '-' || ? || ' days')",
        )
        .bind(api_key_id)
        .bind(days)
        .fetch_one(self.pool())
        .await?;
        Ok((row.try_get("requests")?, row.try_get("errors")?))
    }
}

// ── Audit log methods ──────────────────────────────────────

impl Db {
    /// Appends an entry to the audit log.
    ///
    /// Parameters: all audit fields (most are optional for flexibility).
    #[allow(clippy::too_many_arguments)]
    pub async fn write_audit_log(
        &self,
        user_id: Option<i64>,
        username: &str,
        principal_type: &str,
        action: &str,
        target: Option<&str>,
        details: Option<&str>,
        ip_address: Option<&str>,
        request_id: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_log (user_id, username, principal_type, action, target, details, ip_address, request_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(username)
        .bind(principal_type)
        .bind(action)
        .bind(target)
        .bind(details)
        .bind(ip_address)
        .bind(request_id)
        .execute(self.pool())
        .await?;

        info!(
            request_id = request_id.unwrap_or("-"),
            username,
            principal_type,
            action,
            target = target.unwrap_or("-"),
            ip = ip_address.unwrap_or("-"),
            "AUDIT"
        );

        Ok(())
    }

    /// Queries audit log entries with optional filters and pagination.
    ///
    /// Parameters: `limit`, `offset`, optional `action_filter`, `username_filter`.
    /// Returns: list of `AuditEntry`.
    pub async fn get_audit_logs(
        &self,
        limit: i64,
        offset: i64,
        action_filter: Option<&str>,
        username_filter: Option<&str>,
    ) -> Result<Vec<AuditEntry>> {
        let mut sql = String::from(
            "SELECT id, timestamp, user_id, username, principal_type, action,
                    target, details, ip_address, request_id
             FROM audit_log WHERE 1=1",
        );
        if action_filter.is_some() {
            sql.push_str(" AND action = ?");
        }
        if username_filter.is_some() {
            sql.push_str(" AND username = ?");
        }
        sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");

        let mut q = sqlx::query(&sql);
        if let Some(a) = action_filter {
            q = q.bind(a);
        }
        if let Some(u) = username_filter {
            q = q.bind(u);
        }
        q = q.bind(limit).bind(offset);

        let rows = q.fetch_all(self.pool()).await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(audit_from_row(&r)?);
        }
        Ok(out)
    }

    /// Counts audit log entries with optional filters.
    ///
    /// Parameters: optional `action_filter`, `username_filter`.
    /// Returns: total count.
    pub async fn count_audit_logs(
        &self,
        action_filter: Option<&str>,
        username_filter: Option<&str>,
    ) -> Result<i64> {
        let mut sql = String::from("SELECT COUNT(*) as c FROM audit_log WHERE 1=1");
        if action_filter.is_some() {
            sql.push_str(" AND action = ?");
        }
        if username_filter.is_some() {
            sql.push_str(" AND username = ?");
        }

        let mut q = sqlx::query(&sql);
        if let Some(a) = action_filter {
            q = q.bind(a);
        }
        if let Some(u) = username_filter {
            q = q.bind(u);
        }

        let row = q.fetch_one(self.pool()).await?;
        Ok(row.try_get("c")?)
    }

    /// Queries audit logs with full filter set including time range.
    ///
    /// Parameters: `limit`, `offset`, optional `action`, `username`,
    /// `since`/`until` as ISO-8601 strings.
    /// Returns: matching audit entries ordered by timestamp DESC.
    pub async fn query_audit_logs(
        &self,
        limit: i64,
        offset: i64,
        action: Option<&str>,
        username: Option<&str>,
        since: Option<&str>,
        until: Option<&str>,
    ) -> Result<Vec<AuditEntry>> {
        let mut sql = String::from(
            "SELECT id, timestamp, user_id, username, principal_type, action,
                    target, details, ip_address, request_id
             FROM audit_log WHERE 1=1",
        );
        if action.is_some() {
            sql.push_str(" AND action = ?");
        }
        if username.is_some() {
            sql.push_str(" AND username = ?");
        }
        if since.is_some() {
            sql.push_str(" AND timestamp >= ?");
        }
        if until.is_some() {
            sql.push_str(" AND timestamp <= ?");
        }
        sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");

        let mut q = sqlx::query(&sql);
        if let Some(v) = action {
            q = q.bind(v);
        }
        if let Some(v) = username {
            q = q.bind(v);
        }
        if let Some(v) = since {
            q = q.bind(v);
        }
        if let Some(v) = until {
            q = q.bind(v);
        }
        q = q.bind(limit).bind(offset);

        let rows = q.fetch_all(self.pool()).await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(audit_from_row(&r)?);
        }
        Ok(out)
    }

    /// Counts audit logs with full filter set including time range.
    pub async fn count_audit_logs_filtered(
        &self,
        action: Option<&str>,
        username: Option<&str>,
        since: Option<&str>,
        until: Option<&str>,
    ) -> Result<i64> {
        let mut sql = String::from("SELECT COUNT(*) as c FROM audit_log WHERE 1=1");
        if action.is_some() {
            sql.push_str(" AND action = ?");
        }
        if username.is_some() {
            sql.push_str(" AND username = ?");
        }
        if since.is_some() {
            sql.push_str(" AND timestamp >= ?");
        }
        if until.is_some() {
            sql.push_str(" AND timestamp <= ?");
        }

        let mut q = sqlx::query(&sql);
        if let Some(v) = action {
            q = q.bind(v);
        }
        if let Some(v) = username {
            q = q.bind(v);
        }
        if let Some(v) = since {
            q = q.bind(v);
        }
        if let Some(v) = until {
            q = q.bind(v);
        }

        let row = q.fetch_one(self.pool()).await?;
        Ok(row.try_get("c")?)
    }

    /// Returns audit log statistics.
    ///
    /// Returns: (total, last_24h, last_7d, top_actions).
    pub async fn audit_stats(&self) -> Result<(i64, i64, i64, Vec<(String, i64)>)> {
        let total: i64 = sqlx::query("SELECT COUNT(*) as c FROM audit_log")
            .fetch_one(self.pool())
            .await?
            .try_get("c")?;

        let last_24h: i64 = sqlx::query(
            "SELECT COUNT(*) as c FROM audit_log WHERE timestamp >= datetime('now', '-1 day')",
        )
        .fetch_one(self.pool())
        .await?
        .try_get("c")?;

        let last_7d: i64 = sqlx::query(
            "SELECT COUNT(*) as c FROM audit_log WHERE timestamp >= datetime('now', '-7 days')",
        )
        .fetch_one(self.pool())
        .await?
        .try_get("c")?;

        let rows = sqlx::query(
            "SELECT action, COUNT(*) as c FROM audit_log GROUP BY action ORDER BY c DESC LIMIT 10",
        )
        .fetch_all(self.pool())
        .await?;

        let mut top = Vec::with_capacity(rows.len());
        for r in rows {
            let action: String = r.try_get("action")?;
            let count: i64 = r.try_get("c")?;
            top.push((action, count));
        }

        Ok((total, last_24h, last_7d, top))
    }
}

// ── Row helpers ────────────────────────────────────────────

/// Extracts a `Session` from a sqlx Row.
fn session_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Session> {
    Ok(Session {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        refresh_token_hash: row.try_get("refresh_token_hash")?,
        user_agent: row.try_get("user_agent")?,
        ip_address: row.try_get("ip_address")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        last_active_at: row
            .try_get("last_active_at")
            .or_else(|_| row.try_get("last_used_at"))?,
        last_used_at: row.try_get("last_used_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

/// Extracts an `ApiKeyRecord` from a sqlx Row.
fn api_key_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<ApiKeyRecord> {
    let role_str: String = row.try_get("role")?;
    let role: UserRole = role_str.parse()?;
    Ok(ApiKeyRecord {
        id: row.try_get("id")?,
        key_hash: row.try_get("key_hash")?,
        key_prefix: row.try_get("key_prefix")?,
        description: row.try_get("description")?,
        role,
        created_by: row.try_get("created_by")?,
        expires_at: row.try_get("expires_at")?,
        last_used_at: row.try_get("last_used_at")?,
        is_active: row.try_get("is_active")?,
        rate_limit_rpm: row.try_get("rate_limit_rpm")?,
        rate_limit_burst: row.try_get("rate_limit_burst")?,
        created_at: row.try_get("created_at")?,
    })
}

/// Extracts an `AuditEntry` from a sqlx Row.
fn audit_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<AuditEntry> {
    Ok(AuditEntry {
        id: row.try_get("id")?,
        timestamp: row.try_get("timestamp")?,
        user_id: row.try_get("user_id")?,
        username: row.try_get("username")?,
        principal_type: row.try_get("principal_type")?,
        action: row.try_get("action")?,
        target: row.try_get("target")?,
        details: row.try_get("details")?,
        ip_address: row.try_get("ip_address")?,
        request_id: row.try_get("request_id")?,
    })
}

/// Generates a random API key in format "tid_" + 48 alphanumeric chars.
///
/// Returns: raw API key string.
fn generate_api_key() -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = (0..48)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect();
    format!("tid_{}", chars.into_iter().collect::<String>())
}
