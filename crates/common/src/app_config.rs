//! Runtime configuration snapshot loaded from `config` table.

use crate::db::Db;

/// Password policy subset from runtime config.
#[derive(Debug, Clone)]
pub struct PasswordPolicyConfig {
    pub min_length: i64,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub history_count: i64,
    pub max_age_days: i64,
}

/// In-memory runtime configuration used by handlers and middleware.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub ttl_minutes: i64,
    pub password_policy: PasswordPolicyConfig,
    pub session_idle_minutes: i64,
    pub session_max_hours: i64,
    pub retention_interval_hours: i64,
    pub report_interval_hours: i64,
    pub totp_required_for_admins: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            ttl_minutes: 5,
            password_policy: PasswordPolicyConfig {
                min_length: 12,
                require_uppercase: true,
                require_lowercase: true,
                require_digit: true,
                require_special: false,
                history_count: 5,
                max_age_days: 0,
            },
            session_idle_minutes: 480,
            session_max_hours: 24,
            retention_interval_hours: 6,
            report_interval_hours: 24,
            totp_required_for_admins: false,
        }
    }
}

impl AppConfig {
    /// Loads runtime config from database with defaults.
    ///
    /// Parameters: `db` - database handle.
    /// Returns: fully populated runtime config snapshot.
    pub async fn load(db: &Db) -> Self {
        Self {
            ttl_minutes: db.get_config_i64("ttl_minutes", 5).await.max(1),
            password_policy: PasswordPolicyConfig {
                min_length: db.get_config_i64("password_min_length", 12).await.max(1),
                require_uppercase: config_bool(db, "password_require_uppercase", true).await,
                require_lowercase: config_bool(db, "password_require_lowercase", true).await,
                require_digit: config_bool(db, "password_require_digit", true).await,
                require_special: config_bool(db, "password_require_special", false).await,
                history_count: db.get_config_i64("password_history_count", 5).await.max(0),
                max_age_days: db.get_config_i64("password_max_age_days", 0).await.max(0),
            },
            session_idle_minutes: db.get_config_i64("session_max_idle_minutes", 480).await,
            session_max_hours: db.get_config_i64("session_absolute_max_hours", 24).await,
            retention_interval_hours: db
                .get_config_i64("retention_interval_hours", 6)
                .await
                .max(1),
            report_interval_hours: db.get_config_i64("report_interval_hours", 24).await.max(1),
            totp_required_for_admins: config_bool(db, "totp_required_for_admins", false).await,
        }
    }

    /// Reloads runtime config in place from database.
    ///
    /// Parameters: `db` - database handle.
    /// Returns: none.
    pub async fn reload(&mut self, db: &Db) {
        *self = Self::load(db).await;
    }
}

/// Reads boolean config value with true/false coercion.
///
/// Parameters: `db` - database handle, `key` - config key, `default_value` - fallback.
/// Returns: parsed boolean value.
async fn config_bool(db: &Db, key: &str, default_value: bool) -> bool {
    match db.get_config(key).await.ok().flatten() {
        Some(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        None => default_value,
    }
}
