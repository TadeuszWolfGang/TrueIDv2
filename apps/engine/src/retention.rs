//! Retention policy executor for periodic table cleanup.

use serde::Serialize;
use sqlx::{Row, SqlitePool};
use tracing::{info, warn};
use trueid_common::db::Db;

/// Retention policy row loaded from database.
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    pub id: i64,
    pub table_name: String,
    pub retention_days: i64,
    pub enabled: bool,
}

/// Outcome of a single retention policy execution.
#[derive(Debug, Clone, Serialize)]
pub struct RetentionResult {
    pub table_name: String,
    pub deleted: i64,
    pub status: String,
    pub message: Option<String>,
}

impl RetentionResult {
    /// Creates success result.
    ///
    /// Parameters: `table_name` - target table, `deleted` - deleted rows count.
    /// Returns: success result payload.
    pub fn ok(table_name: &str, deleted: i64) -> Self {
        Self {
            table_name: table_name.to_string(),
            deleted,
            status: "ok".to_string(),
            message: None,
        }
    }

    /// Creates skipped result.
    ///
    /// Parameters: `table_name` - target table, `message` - skip reason.
    /// Returns: skipped result payload.
    pub fn skipped(table_name: &str, message: &str) -> Self {
        Self {
            table_name: table_name.to_string(),
            deleted: 0,
            status: "skipped".to_string(),
            message: Some(message.to_string()),
        }
    }

    /// Creates error result.
    ///
    /// Parameters: `table_name` - target table, `message` - error message.
    /// Returns: error result payload.
    pub fn error(table_name: &str, message: &str) -> Self {
        Self {
            table_name: table_name.to_string(),
            deleted: 0,
            status: "error".to_string(),
            message: Some(message.to_string()),
        }
    }
}

/// Executes all retention policies in configured batches.
pub struct RetentionExecutor {
    pool: SqlitePool,
    vacuum_after_retention: bool,
}

impl RetentionExecutor {
    /// Creates retention executor from DB handle.
    ///
    /// Parameters: `db` - shared database handle.
    /// Returns: configured retention executor.
    pub async fn from_db(db: &Db) -> Self {
        let raw = db
            .get_config("vacuum_after_retention")
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "true".to_string());
        let vacuum_after_retention = matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
        Self::new(db.pool().clone(), vacuum_after_retention)
    }

    /// Creates retention executor from pool and vacuum flag.
    ///
    /// Parameters: `pool` - sqlite pool, `vacuum_after_retention` - run VACUUM on large deletions.
    /// Returns: configured retention executor.
    pub fn new(pool: SqlitePool, vacuum_after_retention: bool) -> Self {
        Self {
            pool,
            vacuum_after_retention,
        }
    }

    /// Runs all enabled retention policies.
    ///
    /// Parameters: none.
    /// Returns: per-policy execution results.
    pub async fn run_all(&self) -> Vec<RetentionResult> {
        let policies = match self.load_policies().await {
            Ok(v) => v,
            Err(e) => {
                return vec![RetentionResult::error(
                    "retention_policies",
                    &format!("failed to load policies: {e}"),
                )];
            }
        };
        let mut results = Vec::with_capacity(policies.len());
        let mut total_deleted = 0_i64;
        for policy in policies {
            if !policy.enabled {
                results.push(RetentionResult::skipped(&policy.table_name, "disabled"));
                continue;
            }
            let result = self.execute_policy(&policy).await;
            if result.status == "ok" {
                total_deleted += result.deleted;
            }
            results.push(result);
        }

        if self.vacuum_after_retention && total_deleted > 10_000 {
            info!(
                deleted = total_deleted,
                "Running VACUUM after retention cleanup"
            );
            if let Err(e) = sqlx::query("VACUUM").execute(&self.pool).await {
                warn!(error = %e, "VACUUM after retention failed");
            }
        }
        results
    }

    /// Loads configured retention policies.
    ///
    /// Parameters: none.
    /// Returns: enabled/disabled retention policies.
    async fn load_policies(&self) -> anyhow::Result<Vec<RetentionPolicy>> {
        let rows = sqlx::query(
            "SELECT id, table_name, retention_days, enabled
             FROM retention_policies
             ORDER BY id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(RetentionPolicy {
                id: row.try_get("id").unwrap_or_default(),
                table_name: row.try_get("table_name").unwrap_or_default(),
                retention_days: row.try_get("retention_days").unwrap_or(90),
                enabled: row.try_get("enabled").unwrap_or(true),
            });
        }
        Ok(out)
    }

    /// Executes a single retention policy with 1000-row batches.
    ///
    /// Parameters: `policy` - retention policy row.
    /// Returns: retention result for the policy.
    async fn execute_policy(&self, policy: &RetentionPolicy) -> RetentionResult {
        let (safe_table, timestamp_col) = match policy.table_name.as_str() {
            "events" => ("events", "timestamp"),
            "conflicts" => ("conflicts", "detected_at"),
            "alert_history" => ("alert_history", "fired_at"),
            "audit_log" => ("audit_log", "timestamp"),
            "notification_deliveries" => ("notification_deliveries", "delivered_at"),
            "firewall_push_history" => ("firewall_push_history", "pushed_at"),
            "report_snapshots" => ("report_snapshots", "generated_at"),
            "dns_cache" => ("dns_cache", "resolved_at"),
            _ => return RetentionResult::skipped(&policy.table_name, "unknown table"),
        };
        let days = policy.retention_days.max(1);

        let mut total_deleted = 0_i64;
        loop {
            let sql = format!(
                "DELETE FROM {safe_table} WHERE rowid IN (
                    SELECT rowid FROM {safe_table}
                    WHERE {timestamp_col} < datetime('now', '-' || ? || ' days')
                    LIMIT 1000
                )"
            );
            let result = sqlx::query(&sql).bind(days).execute(&self.pool).await;
            match result {
                Ok(r) => {
                    let deleted = r.rows_affected() as i64;
                    total_deleted += deleted;
                    if deleted < 1000 {
                        break;
                    }
                }
                Err(e) => return RetentionResult::error(safe_table, &e.to_string()),
            }
        }

        let _ = sqlx::query(
            "UPDATE retention_policies
             SET last_run_at = datetime('now'), last_deleted_count = ?, updated_at = datetime('now')
             WHERE id = ?",
        )
        .bind(total_deleted)
        .bind(policy.id)
        .execute(&self.pool)
        .await;

        RetentionResult::ok(safe_table, total_deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies retention run on empty migrated DB returns zero deletions.
    #[tokio::test]
    async fn test_retention_executor_empty_tables() {
        let db = trueid_common::db::init_db("sqlite::memory:")
            .await
            .expect("init db failed");
        let executor = RetentionExecutor::new(db.pool().clone(), false);
        let results = executor.run_all().await;
        assert!(!results.is_empty(), "expected seeded retention policies");
        assert!(
            results
                .iter()
                .all(|r| r.status == "ok" && r.deleted == 0 || r.status == "skipped"),
            "unexpected retention results: {results:?}"
        );
    }
}
