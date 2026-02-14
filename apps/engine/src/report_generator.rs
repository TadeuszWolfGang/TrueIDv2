//! Scheduled daily report generator.

use chrono::{Duration, Utc};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tracing::warn;
use trueid_common::db::Db;
use trueid_common::db_analytics;

/// Reduced compliance subset used inside daily snapshots.
#[derive(Debug, Serialize)]
pub(crate) struct ComplianceSummary {
    active_mappings: i64,
    unresolved_conflicts: i64,
    stale_24h: i64,
    ips_without_subnet: i64,
}

/// Daily report payload persisted as JSON blob.
#[derive(Debug, Serialize)]
struct DailyReport {
    period: String,
    events_total: i64,
    new_mappings: i64,
    expired_mappings: i64,
    conflicts_detected: i64,
    conflicts_resolved: i64,
    alerts_fired: i64,
    top_users: Vec<(String, i64)>,
    top_sources: Vec<(String, i64)>,
    compliance: ComplianceSummary,
}

/// Computes compliance subset for report payload.
///
/// Parameters: `pool` - SQLite connection pool.
/// Returns: compliance subset.
pub(crate) async fn build_compliance_subset(
    pool: &sqlx::SqlitePool,
) -> anyhow::Result<ComplianceSummary> {
    let active_mappings: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE is_active = 1")
            .fetch_one(pool)
            .await?;
    let unresolved_conflicts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM conflicts WHERE resolved_at IS NULL")
            .fetch_one(pool)
            .await?;
    let stale_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mappings
         WHERE is_active = 1 AND last_seen < datetime('now', '-24 hours')",
    )
    .fetch_one(pool)
    .await?;
    let ips_without_subnet: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE subnet_id IS NULL")
            .fetch_one(pool)
            .await?;
    Ok(ComplianceSummary {
        active_mappings,
        unresolved_conflicts,
        stale_24h,
        ips_without_subnet,
    })
}

/// Generates and persists a single daily report snapshot.
///
/// Parameters: `db_ref` - shared DB wrapper.
/// Returns: snapshot id.
pub(crate) async fn generate_once(db_ref: &Db) -> anyhow::Result<i64> {
    let end = Utc::now();
    let start = end - Duration::days(1);
    let period = start.format("%Y-%m-%d").to_string();
    let period_start = start.to_rfc3339();
    let period_end = end.to_rfc3339();

    let events_total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE timestamp >= ? AND timestamp < ?")
            .bind(start)
            .bind(end)
            .fetch_one(db_ref.pool())
            .await?;
    let new_mappings: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE last_seen >= ? AND last_seen < ?")
            .bind(start)
            .bind(end)
            .fetch_one(db_ref.pool())
            .await?;
    let expired_mappings: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mappings
         WHERE is_active = 0 AND last_seen >= ? AND last_seen < ?",
    )
    .bind(start)
    .bind(end)
    .fetch_one(db_ref.pool())
    .await?;
    let conflicts_detected: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conflicts WHERE detected_at >= ? AND detected_at < ?",
    )
    .bind(start)
    .bind(end)
    .fetch_one(db_ref.pool())
    .await?;
    let conflicts_resolved: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conflicts WHERE resolved_at >= ? AND resolved_at < ?",
    )
    .bind(start)
    .bind(end)
    .fetch_one(db_ref.pool())
    .await?;
    let alerts_fired: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alert_history WHERE fired_at >= ? AND fired_at < ?",
    )
    .bind(start)
    .bind(end)
    .fetch_one(db_ref.pool())
    .await?;

    let top_users = db_analytics::top_n_users(db_ref.pool(), 1, "events", 5).await?;
    let top_sources = db_analytics::source_distribution(db_ref.pool(), 1).await?;
    let compliance = build_compliance_subset(db_ref.pool()).await?;

    let payload = DailyReport {
        period,
        events_total,
        new_mappings,
        expired_mappings,
        conflicts_detected,
        conflicts_resolved,
        alerts_fired,
        top_users,
        top_sources,
        compliance,
    };
    let summary = format!(
        "events={}, conflicts={}, alerts={}",
        payload.events_total, payload.conflicts_detected, payload.alerts_fired
    );
    let blob = serde_json::to_string(&payload)?;
    let id = db_analytics::save_report_snapshot(
        db_ref.pool(),
        "daily",
        &period_start,
        &period_end,
        &blob,
        Some(&summary),
    )
    .await?;
    let _ = db_analytics::cleanup_old_reports(db_ref.pool(), 90).await;
    Ok(id)
}

/// Starts background loop that generates daily report snapshots.
///
/// Parameters: `db` - shared DB wrapper.
/// Returns: nothing.
pub(crate) fn start_report_generator(db: Arc<Db>) {
    tokio::spawn(async move {
        loop {
            if let Err(err) = generate_once(&db).await {
                warn!(error = %err, "Daily report generation failed");
            }
            let hours = db.get_config_i64("report_interval_hours", 24).await.max(1);
            tokio::time::sleep(StdDuration::from_secs((hours as u64) * 3600)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use trueid_common::db::init_db;

    /// Verifies compliance summary returns zeros for an empty database.
    ///
    /// Parameters: none.
    /// Returns: none.
    #[tokio::test]
    async fn test_compliance_summary_empty_db() {
        let db = init_db("sqlite::memory:").await.expect("init_db failed");
        let summary = build_compliance_subset(db.pool())
            .await
            .expect("build_compliance_subset failed");
        assert_eq!(summary.active_mappings, 0);
        assert_eq!(summary.unresolved_conflicts, 0);
        assert_eq!(summary.stale_24h, 0);
        assert_eq!(summary.ips_without_subnet, 0);
    }

    /// Verifies daily report generation creates one snapshot row.
    ///
    /// Parameters: none.
    /// Returns: none.
    #[tokio::test]
    async fn test_generate_once_creates_snapshot() {
        let db = init_db("sqlite::memory:").await.expect("init_db failed");
        let id = generate_once(&db).await.expect("generate_once failed");
        assert!(id > 0);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM report_snapshots")
            .fetch_one(db.pool())
            .await
            .expect("snapshot count query failed");
        assert_eq!(count, 1);
    }
}
