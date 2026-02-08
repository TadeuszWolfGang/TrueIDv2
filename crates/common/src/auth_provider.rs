//! Trait-based authentication abstraction for TrueID.
//!
//! `AuthProvider` trait enables pluggable auth backends (local DB, LDAP/AD).
//! `LocalAuthProvider` wraps existing Db methods.
//! `LdapAuthProvider` is a stub for future LDAP/AD integration.
//! `AuthProviderChain` routes authentication to the correct provider by auth_source.

use async_trait::async_trait;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::sync::Arc;

use crate::db::Db;
use crate::db_auth::verify_password;
use crate::model::User;

// ── AuthResult ──────────────────────────────────────────────

/// Result of an authentication attempt.
pub enum AuthResult {
    /// Credentials valid; contains the authenticated user.
    Success(User),
    /// Wrong username or password.
    InvalidCredentials,
    /// Account locked until the given timestamp.
    AccountLocked { until: DateTime<Utc> },
    /// Internal or provider error.
    Error(String),
}

// ── AuthProvider trait ──────────────────────────────────────

/// Pluggable authentication backend.
///
/// Implementations must be `Send + Sync` for use in async Axum handlers.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Authenticates a user by username and password.
    ///
    /// Parameters: `username`, `password`.
    /// Returns: `AuthResult`.
    async fn authenticate(&self, username: &str, password: &str) -> AuthResult;

    /// The `auth_source` value this provider handles (e.g. "local", "ldap").
    fn handles_source(&self) -> &str;

    /// Whether this provider supports password changes.
    fn supports_password_change(&self) -> bool;

    /// Changes a user's password.
    ///
    /// Parameters: `user_id`, `current` password, `new_pass`.
    /// Returns: `Ok(())` on success.
    async fn change_password(&self, user_id: i64, current: &str, new_pass: &str) -> Result<()>;
}

// ── LocalAuthProvider ──────────────────────────────────────

/// Local database authentication provider.
///
/// Wraps `Db` methods for password verification, lockout, and change.
pub struct LocalAuthProvider {
    db: Arc<Db>,
}

impl LocalAuthProvider {
    /// Creates a new LocalAuthProvider.
    ///
    /// Parameters: `db` — shared database handle.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl AuthProvider for LocalAuthProvider {
    async fn authenticate(&self, username: &str, password: &str) -> AuthResult {
        // 1) Look up user.
        let user = match self.db.get_user_by_username(username).await {
            Ok(Some(u)) => u,
            Ok(None) => return AuthResult::InvalidCredentials,
            Err(e) => return AuthResult::Error(format!("DB error: {e:#}")),
        };

        // 2) Check lockout.
        if self.db.is_account_locked(&user) {
            return AuthResult::AccountLocked {
                until: user.locked_until.unwrap_or_else(Utc::now),
            };
        }

        // 3) Verify password.
        let pepper = self.db.pepper();
        let valid = verify_password(password, &user.password_hash, pepper).unwrap_or(false);
        if !valid {
            let _ = self.db.record_failed_login(username).await;
            return AuthResult::InvalidCredentials;
        }

        // 4) Success — reset failed attempts.
        let _ = self.db.reset_failed_attempts(user.id).await;
        AuthResult::Success(user)
    }

    fn handles_source(&self) -> &str {
        "local"
    }

    fn supports_password_change(&self) -> bool {
        true
    }

    async fn change_password(&self, user_id: i64, current: &str, new_pass: &str) -> Result<()> {
        let user = self.db.get_user_by_id(user_id).await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        let valid = verify_password(current, &user.password_hash, self.db.pepper())
            .unwrap_or(false);
        if !valid {
            anyhow::bail!("Current password is incorrect");
        }

        self.db.change_password(user_id, new_pass).await
    }
}

// ── LdapAuthProvider (stub) ────────────────────────────────

/// Stub LDAP/AD authentication provider for future integration.
pub struct LdapAuthProvider;

#[async_trait]
impl AuthProvider for LdapAuthProvider {
    async fn authenticate(&self, _username: &str, _password: &str) -> AuthResult {
        AuthResult::Error("LDAP authentication is not yet implemented".to_string())
    }

    fn handles_source(&self) -> &str {
        "ldap"
    }

    fn supports_password_change(&self) -> bool {
        false
    }

    async fn change_password(&self, _user_id: i64, _current: &str, _new_pass: &str) -> Result<()> {
        anyhow::bail!("Password changes must be performed in Active Directory")
    }
}

// ── AuthProviderChain ──────────────────────────────────────

/// Routes authentication to the correct provider based on user's `auth_source`.
///
/// On `authenticate()`: looks up the user to determine auth_source,
/// then delegates to the matching provider. Default chain: [LocalAuthProvider].
pub struct AuthProviderChain {
    db: Arc<Db>,
    providers: Vec<Box<dyn AuthProvider>>,
}

impl AuthProviderChain {
    /// Creates a new chain with the given providers.
    ///
    /// Parameters: `db` — for user lookup, `providers` — ordered list.
    pub fn new(db: Arc<Db>, providers: Vec<Box<dyn AuthProvider>>) -> Self {
        Self { db, providers }
    }

    /// Creates the default chain with only LocalAuthProvider.
    ///
    /// Parameters: `db` — shared database handle.
    pub fn default_chain(db: Arc<Db>) -> Self {
        let local = Box::new(LocalAuthProvider::new(db.clone()));
        Self::new(db, vec![local])
    }

    /// Authenticates a user by routing to the correct provider.
    ///
    /// Looks up the user's `auth_source` and delegates to the matching provider.
    /// If no provider matches, returns `AuthResult::Error`.
    pub async fn authenticate(&self, username: &str, password: &str) -> AuthResult {
        // Look up user to find auth_source.
        let auth_source = match self.db.get_user_by_username(username).await {
            Ok(Some(u)) => u.auth_source.clone(),
            Ok(None) => return AuthResult::InvalidCredentials,
            Err(e) => return AuthResult::Error(format!("DB error: {e:#}")),
        };

        for provider in &self.providers {
            if provider.handles_source() == auth_source {
                return provider.authenticate(username, password).await;
            }
        }

        AuthResult::Error(format!("No auth provider for source '{auth_source}'"))
    }

    /// Changes a user's password via the matching provider.
    ///
    /// Parameters: `user_id`, `auth_source`, `current`, `new_pass`.
    /// Returns: `Ok(())` on success, error if provider not found or doesn't support it.
    pub async fn change_password(
        &self,
        user_id: i64,
        auth_source: &str,
        current: &str,
        new_pass: &str,
    ) -> Result<()> {
        for provider in &self.providers {
            if provider.handles_source() == auth_source {
                if !provider.supports_password_change() {
                    anyhow::bail!("Password changes are not supported for '{}' accounts", auth_source);
                }
                return provider.change_password(user_id, current, new_pass).await;
            }
        }
        anyhow::bail!("No auth provider for source '{auth_source}'")
    }

    /// Whether the provider for the given source supports password changes.
    pub fn supports_password_change(&self, auth_source: &str) -> bool {
        self.providers
            .iter()
            .find(|p| p.handles_source() == auth_source)
            .map(|p| p.supports_password_change())
            .unwrap_or(false)
    }
}
