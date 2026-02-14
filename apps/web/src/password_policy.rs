//! Password policy loading and validation helpers.

use trueid_common::db::Db;
use trueid_common::db_auth::verify_password;

/// Runtime password policy loaded from config table.
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub history_count: usize,
    pub max_age_days: i64,
    pub session_max_idle_minutes: i64,
    pub session_absolute_max_hours: i64,
    pub totp_required_for_admins: bool,
}

impl PasswordPolicy {
    /// Loads password policy and session security settings from config.
    ///
    /// Parameters: `db` - database handle.
    /// Returns: resolved policy with defaults.
    pub async fn load(db: &Db) -> Self {
        Self {
            min_length: db.get_config_i64("password_min_length", 12).await.max(1) as usize,
            require_uppercase: config_bool(db, "password_require_uppercase", true).await,
            require_lowercase: config_bool(db, "password_require_lowercase", true).await,
            require_digit: config_bool(db, "password_require_digit", true).await,
            require_special: config_bool(db, "password_require_special", false).await,
            history_count: db.get_config_i64("password_history_count", 5).await.max(0) as usize,
            max_age_days: db.get_config_i64("password_max_age_days", 0).await.max(0),
            session_max_idle_minutes: db
                .get_config_i64("session_max_idle_minutes", 480)
                .await
                .max(1),
            session_absolute_max_hours: db
                .get_config_i64("session_absolute_max_hours", 24)
                .await
                .max(1),
            totp_required_for_admins: config_bool(db, "totp_required_for_admins", false).await,
        }
    }

    /// Validates password complexity according to active policy.
    ///
    /// Parameters: `password` - plaintext password candidate.
    /// Returns: `Ok(())` if valid or user-friendly error message.
    pub fn validate(&self, password: &str) -> Result<(), String> {
        if password.len() < self.min_length {
            return Err(format!(
                "Password must be at least {} characters",
                self.min_length
            ));
        }
        if self.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err("Password must contain at least one uppercase letter".to_string());
        }
        if self.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err("Password must contain at least one lowercase letter".to_string());
        }
        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err("Password must contain at least one digit".to_string());
        }
        if self.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
            return Err("Password must contain at least one special character".to_string());
        }
        Ok(())
    }

    /// Checks password history to prevent reuse of recently used passwords.
    ///
    /// Parameters: `db` - database handle, `user_id` - target user id, `password` - candidate plaintext password.
    /// Returns: `Ok(())` if password was not recently used.
    pub async fn check_history(&self, db: &Db, user_id: i64, password: &str) -> Result<(), String> {
        if self.history_count == 0 {
            return Ok(());
        }
        let rows = db
            .get_password_history_hashes(user_id, self.history_count as i64)
            .await
            .map_err(|_| "Failed to validate password history".to_string())?;
        for hash in rows {
            let reused =
                verify_password(password, &hash, db.pepper()).map_err(|_| "Failed to validate password history".to_string())?;
            if reused {
                return Err(format!(
                    "Password must not match the last {} passwords",
                    self.history_count
                ));
            }
        }
        Ok(())
    }
}

/// Reads boolean config value with common true/false coercion.
///
/// Parameters: `db` - database handle, `key` - config key, `default_value` - fallback.
/// Returns: parsed boolean value.
async fn config_bool(db: &Db, key: &str, default_value: bool) -> bool {
    match db.get_config(key).await.ok().flatten() {
        Some(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        None => default_value,
    }
}

#[cfg(test)]
mod tests {
    use super::PasswordPolicy;

    /// Verifies password complexity validation for required length/case/digit.
    #[test]
    fn test_password_policy_validation() {
        let policy = PasswordPolicy {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: false,
            require_digit: true,
            require_special: false,
            history_count: 0,
            max_age_days: 0,
            session_max_idle_minutes: 480,
            session_absolute_max_hours: 24,
            totp_required_for_admins: false,
        };
        assert!(policy.validate("short").is_err());
        assert!(policy.validate("alllowercase123").is_err());
        assert!(policy.validate("NoDigitsHereAtAll").is_err());
        assert!(policy.validate("ValidPass1234").is_ok());
    }
}
