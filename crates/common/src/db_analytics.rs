//! Analytics and report snapshot SQL helpers.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

/// Stored analytics report snapshot metadata + JSON payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSnapshot {
    pub id: i64,
    pub report_type: String,
    pub generated_at: String,
    pub period_start: String,
    pub period_end: String,
    pub data: String,
    pub summary: Option<String>,
}

/// Counts events grouped into time buckets.
///
/// Parameters: `pool` - SQLite pool, `start` - range start (inclusive),
/// `end` - range end (exclusive), `interval` - hour/day/week, `source` - optional source filter.
/// Returns: vector of `(bucket, count)`.
pub async fn count_events_by_period(
    pool: &SqlitePool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    interval: &str,
    source: Option<&str>,
) -> Result<Vec<(String, i64)>> {
    let bucket_expr = match interval {
        "hour" => "strftime('%Y-%m-%dT%H:00:00', timestamp)",
        "day" => "strftime('%Y-%m-%d', timestamp)",
        "week" => "strftime('%Y-W%W', timestamp)",
        _ => return Err(anyhow::anyhow!("unsupported interval: {interval}")),
    };
    let mut sql = format!(
        "SELECT {bucket_expr} AS bucket, COUNT(*) AS c
         FROM events
         WHERE timestamp >= ? AND timestamp < ?"
    );
    if source.is_some() {
        sql.push_str(" AND source = ?");
    }
    sql.push_str(" GROUP BY bucket ORDER BY bucket ASC");

    let mut q = sqlx::query(&sql).bind(start).bind(end);
    if let Some(src) = source {
        q = q.bind(src);
    }
    let rows = q.fetch_all(pool).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push((
            row.try_get("bucket").unwrap_or_default(),
            row.try_get("c").unwrap_or(0),
        ));
    }
    Ok(out)
}

/// Counts conflicts grouped into time buckets.
///
/// Parameters: `pool` - SQLite pool, `start` - range start, `end` - range end, `interval` - hour/day/week.
/// Returns: vector of `(bucket, count)`.
pub async fn count_conflicts_by_period(
    pool: &SqlitePool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    interval: &str,
) -> Result<Vec<(String, i64)>> {
    let bucket_expr = match interval {
        "hour" => "strftime('%Y-%m-%dT%H:00:00', detected_at)",
        "day" => "strftime('%Y-%m-%d', detected_at)",
        "week" => "strftime('%Y-W%W', detected_at)",
        _ => return Err(anyhow::anyhow!("unsupported interval: {interval}")),
    };
    let rows = sqlx::query(&format!(
        "SELECT {bucket_expr} AS bucket, COUNT(*) AS c
         FROM conflicts
         WHERE detected_at >= ? AND detected_at < ?
         GROUP BY bucket ORDER BY bucket ASC"
    ))
    .bind(start)
    .bind(end)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push((
            row.try_get("bucket").unwrap_or_default(),
            row.try_get("c").unwrap_or(0),
        ));
    }
    Ok(out)
}

/// Counts alerts grouped into time buckets.
///
/// Parameters: `pool` - SQLite pool, `start` - range start, `end` - range end, `interval` - hour/day/week.
/// Returns: vector of `(bucket, count)`.
pub async fn count_alerts_by_period(
    pool: &SqlitePool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    interval: &str,
) -> Result<Vec<(String, i64)>> {
    let bucket_expr = match interval {
        "hour" => "strftime('%Y-%m-%dT%H:00:00', fired_at)",
        "day" => "strftime('%Y-%m-%d', fired_at)",
        "week" => "strftime('%Y-W%W', fired_at)",
        _ => return Err(anyhow::anyhow!("unsupported interval: {interval}")),
    };
    let rows = sqlx::query(&format!(
        "SELECT {bucket_expr} AS bucket, COUNT(*) AS c
         FROM alert_history
         WHERE fired_at >= ? AND fired_at < ?
         GROUP BY bucket ORDER BY bucket ASC"
    ))
    .bind(start)
    .bind(end)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push((
            row.try_get("bucket").unwrap_or_default(),
            row.try_get("c").unwrap_or(0),
        ));
    }
    Ok(out)
}

/// Counts firewall pushes grouped into time buckets.
///
/// Parameters: `pool` - SQLite pool, `start` - range start, `end` - range end, `interval` - hour/day/week.
/// Returns: vector of `(bucket, count)`.
pub async fn count_firewall_pushes_by_period(
    pool: &SqlitePool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    interval: &str,
) -> Result<Vec<(String, i64)>> {
    let bucket_expr = match interval {
        "hour" => "strftime('%Y-%m-%dT%H:00:00', pushed_at)",
        "day" => "strftime('%Y-%m-%d', pushed_at)",
        "week" => "strftime('%Y-W%W', pushed_at)",
        _ => return Err(anyhow::anyhow!("unsupported interval: {interval}")),
    };
    let rows = sqlx::query(&format!(
        "SELECT {bucket_expr} AS bucket, COUNT(*) AS c
         FROM firewall_push_history
         WHERE pushed_at >= ? AND pushed_at < ?
         GROUP BY bucket ORDER BY bucket ASC"
    ))
    .bind(start)
    .bind(end)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push((
            row.try_get("bucket").unwrap_or_default(),
            row.try_get("c").unwrap_or(0),
        ));
    }
    Ok(out)
}

/// Returns top-N users by selected activity metric.
///
/// Parameters: `pool` - SQLite pool, `days` - lookback days, `metric` - events/conflicts/alerts, `limit` - row limit.
/// Returns: vector of `(username, count)`.
pub async fn top_n_users(
    pool: &SqlitePool,
    days: i64,
    metric: &str,
    limit: i64,
) -> Result<Vec<(String, i64)>> {
    let sql = match metric {
        "events" => {
            "SELECT COALESCE(NULLIF(user, ''), 'unknown') AS label, COUNT(*) AS c
             FROM events
             WHERE timestamp >= datetime('now', ? || ' days')
             GROUP BY label
             ORDER BY c DESC
             LIMIT ?"
        }
        "conflicts" => {
            "SELECT COALESCE(NULLIF(user_new, ''), NULLIF(user_old, ''), 'unknown') AS label, COUNT(*) AS c
             FROM conflicts
             WHERE detected_at >= datetime('now', ? || ' days')
             GROUP BY label
             ORDER BY c DESC
             LIMIT ?"
        }
        "alerts" => {
            "SELECT COALESCE(NULLIF(user_name, ''), 'unknown') AS label, COUNT(*) AS c
             FROM alert_history
             WHERE fired_at >= datetime('now', ? || ' days')
             GROUP BY label
             ORDER BY c DESC
             LIMIT ?"
        }
        _ => return Err(anyhow::anyhow!("unsupported metric: {metric}")),
    };
    let rows = sqlx::query(sql).bind(-days).bind(limit).fetch_all(pool).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push((
            row.try_get("label").unwrap_or_default(),
            row.try_get("c").unwrap_or(0),
        ));
    }
    Ok(out)
}

/// Returns top-N IPs by selected activity metric.
///
/// Parameters: `pool` - SQLite pool, `days` - lookback days, `metric` - events/conflicts/alerts, `limit` - row limit.
/// Returns: vector of `(ip, count)`.
pub async fn top_n_ips(
    pool: &SqlitePool,
    days: i64,
    metric: &str,
    limit: i64,
) -> Result<Vec<(String, i64)>> {
    let sql = match metric {
        "events" => {
            "SELECT COALESCE(NULLIF(ip, ''), 'unknown') AS label, COUNT(*) AS c
             FROM events
             WHERE timestamp >= datetime('now', ? || ' days')
             GROUP BY label
             ORDER BY c DESC
             LIMIT ?"
        }
        "conflicts" => {
            "SELECT COALESCE(NULLIF(ip, ''), 'unknown') AS label, COUNT(*) AS c
             FROM conflicts
             WHERE detected_at >= datetime('now', ? || ' days')
             GROUP BY label
             ORDER BY c DESC
             LIMIT ?"
        }
        "alerts" => {
            "SELECT COALESCE(NULLIF(ip, ''), 'unknown') AS label, COUNT(*) AS c
             FROM alert_history
             WHERE fired_at >= datetime('now', ? || ' days')
             GROUP BY label
             ORDER BY c DESC
             LIMIT ?"
        }
        _ => return Err(anyhow::anyhow!("unsupported metric: {metric}")),
    };
    let rows = sqlx::query(sql).bind(-days).bind(limit).fetch_all(pool).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push((
            row.try_get("label").unwrap_or_default(),
            row.try_get("c").unwrap_or(0),
        ));
    }
    Ok(out)
}

/// Returns source distribution for recent events.
///
/// Parameters: `pool` - SQLite pool, `days` - lookback days.
/// Returns: vector of `(source, count)`.
pub async fn source_distribution(pool: &SqlitePool, days: i64) -> Result<Vec<(String, i64)>> {
    let rows = sqlx::query(
        "SELECT source, COUNT(*) AS c
         FROM events
         WHERE timestamp >= datetime('now', ? || ' days')
         GROUP BY source
         ORDER BY c DESC",
    )
    .bind(-days)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push((
            row.try_get("source").unwrap_or_default(),
            row.try_get("c").unwrap_or(0),
        ));
    }
    Ok(out)
}

/// Persists a report snapshot JSON blob.
///
/// Parameters: `pool` - SQLite pool, `report_type` - snapshot type, `period_start`/`period_end` - period bounds, `data_json` - serialized JSON, `summary` - optional short summary.
/// Returns: inserted snapshot ID.
pub async fn save_report_snapshot(
    pool: &SqlitePool,
    report_type: &str,
    period_start: &str,
    period_end: &str,
    data_json: &str,
    summary: Option<&str>,
) -> Result<i64> {
    let res = sqlx::query(
        "INSERT INTO report_snapshots (report_type, period_start, period_end, data, summary)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(report_type)
    .bind(period_start)
    .bind(period_end)
    .bind(data_json)
    .bind(summary)
    .execute(pool)
    .await?;
    Ok(res.last_insert_rowid())
}

/// Lists report snapshots ordered by newest first.
///
/// Parameters: `pool` - SQLite pool, `report_type` - optional type filter, `limit` - max rows.
/// Returns: ordered report snapshots.
pub async fn list_report_snapshots(
    pool: &SqlitePool,
    report_type: Option<&str>,
    limit: i64,
) -> Result<Vec<ReportSnapshot>> {
    let rows = if let Some(kind) = report_type {
        sqlx::query(
            "SELECT id, report_type, generated_at, period_start, period_end, data, summary
             FROM report_snapshots
             WHERE report_type = ?
             ORDER BY generated_at DESC
             LIMIT ?",
        )
        .bind(kind)
        .bind(limit)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query(
            "SELECT id, report_type, generated_at, period_start, period_end, data, summary
             FROM report_snapshots
             ORDER BY generated_at DESC
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(pool)
        .await?
    };

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(ReportSnapshot {
            id: row.try_get("id").unwrap_or_default(),
            report_type: row.try_get("report_type").unwrap_or_else(|_| "daily".to_string()),
            generated_at: row.try_get("generated_at").unwrap_or_default(),
            period_start: row.try_get("period_start").unwrap_or_default(),
            period_end: row.try_get("period_end").unwrap_or_default(),
            data: row.try_get("data").unwrap_or_else(|_| "{}".to_string()),
            summary: row.try_get("summary").ok(),
        });
    }
    Ok(out)
}

/// Fetches single report snapshot by ID.
///
/// Parameters: `pool` - SQLite pool, `id` - snapshot ID.
/// Returns: optional snapshot.
pub async fn get_report_snapshot(pool: &SqlitePool, id: i64) -> Result<Option<ReportSnapshot>> {
    let row = sqlx::query(
        "SELECT id, report_type, generated_at, period_start, period_end, data, summary
         FROM report_snapshots
         WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(ReportSnapshot {
        id: row.try_get("id").unwrap_or_default(),
        report_type: row.try_get("report_type").unwrap_or_else(|_| "daily".to_string()),
        generated_at: row.try_get("generated_at").unwrap_or_default(),
        period_start: row.try_get("period_start").unwrap_or_default(),
        period_end: row.try_get("period_end").unwrap_or_default(),
        data: row.try_get("data").unwrap_or_else(|_| "{}".to_string()),
        summary: row.try_get("summary").ok(),
    }))
}

/// Deletes old report snapshots keeping newest N rows.
///
/// Parameters: `pool` - SQLite pool, `keep_count` - number of newest rows to keep.
/// Returns: number of deleted rows.
pub async fn cleanup_old_reports(pool: &SqlitePool, keep_count: i64) -> Result<u64> {
    if keep_count <= 0 {
        let res = sqlx::query("DELETE FROM report_snapshots").execute(pool).await?;
        return Ok(res.rows_affected());
    }
    let res = sqlx::query(
        "DELETE FROM report_snapshots
         WHERE id NOT IN (
            SELECT id FROM report_snapshots ORDER BY generated_at DESC LIMIT ?
         )",
    )
    .bind(keep_count)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
