//! Analytics, compliance, and report snapshot endpoints.

use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use tracing::warn;
use trueid_common::db_analytics;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;

/// Query params for trend endpoint.
#[derive(Deserialize)]
pub(crate) struct TrendsQuery {
    metric: String,
    interval: Option<String>,
    days: Option<i64>,
    source: Option<String>,
}

/// Query params for top-N endpoint.
#[derive(Deserialize)]
pub(crate) struct TopQuery {
    dimension: String,
    metric: Option<String>,
    days: Option<i64>,
    limit: Option<i64>,
}

/// Query params for source distribution.
#[derive(Deserialize)]
pub(crate) struct SourcesQuery {
    days: Option<i64>,
}

/// Query params for report list.
#[derive(Deserialize)]
pub(crate) struct ReportsQuery {
    #[serde(rename = "type")]
    report_type: Option<String>,
    limit: Option<i64>,
}

/// Time bucket point for chart data.
#[derive(Serialize)]
struct TrendPoint {
    timestamp: String,
    count: i64,
}

/// Trends response payload.
#[derive(Serialize)]
struct TrendsResponse {
    metric: String,
    interval: String,
    days: i64,
    data: Vec<TrendPoint>,
    total: i64,
}

/// Top-N chart item.
#[derive(Serialize)]
struct TopPoint {
    label: String,
    count: i64,
    percentage: f64,
}

/// Top-N response payload.
#[derive(Serialize)]
struct TopResponse {
    dimension: String,
    metric: String,
    days: i64,
    data: Vec<TopPoint>,
}

/// Source distribution item.
#[derive(Serialize)]
struct SourcePoint {
    source: String,
    count: i64,
    percentage: f64,
}

/// Source distribution response payload.
#[derive(Serialize)]
struct SourceDistributionResponse {
    days: i64,
    total_events: i64,
    sources: Vec<SourcePoint>,
}

/// Compliance mappings section.
#[derive(Serialize, Clone)]
struct ComplianceMappings {
    total: i64,
    active: i64,
    inactive: i64,
    stale_24h: i64,
    no_user: i64,
    no_mac: i64,
    multi_user: i64,
}

/// Compliance conflicts section.
#[derive(Serialize, Clone)]
struct ComplianceConflicts {
    total_unresolved: i64,
    critical: i64,
    warning: i64,
    info: i64,
    oldest_unresolved_days: i64,
}

/// Compliance coverage section.
#[derive(Serialize, Clone)]
struct ComplianceCoverage {
    total_subnets: i64,
    subnets_with_mappings: i64,
    ips_in_known_subnets: i64,
    ips_without_subnet: i64,
}

/// Compliance integrations section.
#[derive(Serialize, Clone)]
struct ComplianceIntegrations {
    firewall_targets_enabled: i64,
    firewall_last_push_ok: bool,
    siem_targets_enabled: i64,
    siem_events_24h: i64,
    ldap_enabled: bool,
    ldap_last_sync_ok: bool,
    ldap_users_synced: i64,
}

/// Compliance alerts section.
#[derive(Serialize, Clone)]
struct ComplianceAlerts {
    rules_total: i64,
    rules_enabled: i64,
    fired_24h: i64,
    fired_7d: i64,
    webhook_success_rate_7d: f64,
}

/// Full compliance response payload.
#[derive(Serialize, Clone)]
struct ComplianceResponse {
    generated_at: String,
    mappings: ComplianceMappings,
    conflicts: ComplianceConflicts,
    coverage: ComplianceCoverage,
    integrations: ComplianceIntegrations,
    alerts: ComplianceAlerts,
}

/// Daily report payload stored in snapshot JSON.
#[derive(Serialize)]
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
    compliance: ComplianceResponse,
}

/// Lightweight report list row.
#[derive(Serialize)]
struct ReportListItem {
    id: i64,
    report_type: String,
    generated_at: String,
    period_start: String,
    period_end: String,
    summary: Option<String>,
}

/// Paginated report list payload.
#[derive(Serialize)]
struct ReportListResponse {
    data: Vec<ReportListItem>,
    total: i64,
}

/// Full report payload.
#[derive(Serialize)]
struct ReportDetailsResponse {
    id: i64,
    report_type: String,
    generated_at: String,
    period_start: String,
    period_end: String,
    summary: Option<String>,
    data: Value,
}

/// Normalizes bucket label to API timestamp-like output.
fn normalize_bucket(interval: &str, bucket: String) -> String {
    match interval {
        "hour" => format!("{bucket}Z"),
        "day" => format!("{bucket}T00:00:00Z"),
        _ => bucket,
    }
}

/// Safely computes percent value with one decimal precision.
fn pct(count: i64, total: i64) -> f64 {
    if total <= 0 {
        0.0
    } else {
        ((count as f64) * 1000.0 / (total as f64)).round() / 10.0
    }
}

/// Builds compliance summary by aggregating multiple SQL queries.
///
/// Parameters: `pool` - SQLite pool.
/// Returns: full compliance response.
async fn build_compliance(pool: &sqlx::SqlitePool) -> Result<ComplianceResponse> {
    let mappings_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mappings")
        .fetch_one(pool)
        .await?;
    let mappings_active: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE is_active = 1")
            .fetch_one(pool)
            .await?;
    let mappings_inactive = mappings_total.saturating_sub(mappings_active);
    let stale_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mappings
         WHERE is_active = 1 AND last_seen < datetime('now', '-24 hours')",
    )
    .fetch_one(pool)
    .await?;
    let no_user: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE user IS NULL OR trim(user) = ''")
            .fetch_one(pool)
            .await?;
    let no_mac: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE mac IS NULL OR trim(mac) = ''")
            .fetch_one(pool)
            .await?;
    let multi_user: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE multi_user = 1")
        .fetch_one(pool)
        .await?;

    let unresolved: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM conflicts WHERE resolved_at IS NULL")
            .fetch_one(pool)
            .await?;
    let unresolved_critical: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conflicts WHERE resolved_at IS NULL AND severity = 'critical'",
    )
    .fetch_one(pool)
    .await?;
    let unresolved_warning: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conflicts WHERE resolved_at IS NULL AND severity = 'warning'",
    )
    .fetch_one(pool)
    .await?;
    let unresolved_info: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conflicts WHERE resolved_at IS NULL AND severity = 'info'",
    )
    .fetch_one(pool)
    .await?;
    let oldest_unresolved_days: i64 = sqlx::query_scalar(
        "SELECT COALESCE(CAST(MAX(julianday('now') - julianday(detected_at)) AS INTEGER), 0)
         FROM conflicts WHERE resolved_at IS NULL",
    )
    .fetch_one(pool)
    .await?;

    let total_subnets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subnets")
        .fetch_one(pool)
        .await?;
    let subnets_with_mappings: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT subnet_id) FROM mappings WHERE subnet_id IS NOT NULL",
    )
    .fetch_one(pool)
    .await?;
    let ips_in_known_subnets: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE subnet_id IS NOT NULL")
            .fetch_one(pool)
            .await?;
    let ips_without_subnet: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE subnet_id IS NULL")
            .fetch_one(pool)
            .await?;

    let firewall_targets_enabled: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM firewall_targets WHERE enabled = 1")
            .fetch_one(pool)
            .await?;
    let firewall_last_push_status: Option<String> = sqlx::query_scalar(
        "SELECT h.status
         FROM firewall_push_history h
         JOIN firewall_targets t ON t.id = h.target_id
         WHERE t.enabled = 1
         ORDER BY h.pushed_at DESC
         LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    let firewall_last_push_ok = matches!(firewall_last_push_status.as_deref(), Some("ok"));

    let siem_targets_enabled: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM siem_targets WHERE enabled = 1")
            .fetch_one(pool)
            .await?;
    let siem_events_24h: i64 = if siem_targets_enabled > 0 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM events WHERE timestamp >= datetime('now', '-24 hours')",
        )
        .fetch_one(pool)
        .await?
    } else {
        0
    };

    let ldap_row = sqlx::query(
        "SELECT enabled, last_sync_status, last_sync_count
         FROM ldap_config
         WHERE id = 1",
    )
    .fetch_optional(pool)
    .await?;
    let (ldap_enabled, ldap_last_sync_ok, ldap_users_synced) = match ldap_row {
        Some(row) => {
            let enabled: i64 = row.try_get("enabled").unwrap_or(0);
            let status: Option<String> = row.try_get("last_sync_status").ok();
            let count: i64 = row.try_get("last_sync_count").unwrap_or(0);
            (enabled == 1, matches!(status.as_deref(), Some("ok")), count)
        }
        None => (false, false, 0),
    };

    let rules_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alert_rules")
        .fetch_one(pool)
        .await?;
    let rules_enabled: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM alert_rules WHERE enabled = 1")
            .fetch_one(pool)
            .await?;
    let fired_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alert_history WHERE fired_at >= datetime('now', '-24 hours')",
    )
    .fetch_one(pool)
    .await?;
    let fired_7d: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alert_history WHERE fired_at >= datetime('now', '-7 days')",
    )
    .fetch_one(pool)
    .await?;
    let webhook_rows = sqlx::query(
        "SELECT
            SUM(CASE WHEN webhook_status = 'sent' THEN 1 ELSE 0 END) AS sent_count,
            SUM(CASE WHEN webhook_status = 'failed' THEN 1 ELSE 0 END) AS failed_count
         FROM alert_history
         WHERE fired_at >= datetime('now', '-7 days')",
    )
    .fetch_one(pool)
    .await?;
    let sent_count: i64 = webhook_rows.try_get("sent_count").unwrap_or(0);
    let failed_count: i64 = webhook_rows.try_get("failed_count").unwrap_or(0);
    let webhook_total = sent_count + failed_count;
    let webhook_success_rate_7d = if webhook_total > 0 {
        sent_count as f64 / webhook_total as f64
    } else {
        1.0
    };

    Ok(ComplianceResponse {
        generated_at: Utc::now().to_rfc3339(),
        mappings: ComplianceMappings {
            total: mappings_total,
            active: mappings_active,
            inactive: mappings_inactive,
            stale_24h,
            no_user,
            no_mac,
            multi_user,
        },
        conflicts: ComplianceConflicts {
            total_unresolved: unresolved,
            critical: unresolved_critical,
            warning: unresolved_warning,
            info: unresolved_info,
            oldest_unresolved_days,
        },
        coverage: ComplianceCoverage {
            total_subnets,
            subnets_with_mappings,
            ips_in_known_subnets,
            ips_without_subnet,
        },
        integrations: ComplianceIntegrations {
            firewall_targets_enabled,
            firewall_last_push_ok,
            siem_targets_enabled,
            siem_events_24h,
            ldap_enabled,
            ldap_last_sync_ok,
            ldap_users_synced,
        },
        alerts: ComplianceAlerts {
            rules_total,
            rules_enabled,
            fired_24h,
            fired_7d,
            webhook_success_rate_7d,
        },
    })
}

/// Generates and stores a daily snapshot report immediately.
///
/// Parameters: `db_ref` - database handle.
/// Returns: `(snapshot_id, summary_text)`.
async fn generate_report_now(db_ref: &trueid_common::db::Db) -> Result<(i64, String)> {
    let now = Utc::now();
    let start = now - Duration::days(1);
    let period = start.format("%Y-%m-%d").to_string();
    let period_start = start.to_rfc3339();
    let period_end = now.to_rfc3339();

    let events_total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE timestamp >= ? AND timestamp < ?")
            .bind(start)
            .bind(now)
            .fetch_one(db_ref.pool())
            .await?;
    let new_mappings: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE last_seen >= ? AND last_seen < ?")
            .bind(start)
            .bind(now)
            .fetch_one(db_ref.pool())
            .await?;
    let expired_mappings: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mappings
         WHERE is_active = 0 AND last_seen >= ? AND last_seen < ?",
    )
    .bind(start)
    .bind(now)
    .fetch_one(db_ref.pool())
    .await?;
    let conflicts_detected: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conflicts WHERE detected_at >= ? AND detected_at < ?",
    )
    .bind(start)
    .bind(now)
    .fetch_one(db_ref.pool())
    .await?;
    let conflicts_resolved: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conflicts WHERE resolved_at >= ? AND resolved_at < ?",
    )
    .bind(start)
    .bind(now)
    .fetch_one(db_ref.pool())
    .await?;
    let alerts_fired: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alert_history WHERE fired_at >= ? AND fired_at < ?",
    )
    .bind(start)
    .bind(now)
    .fetch_one(db_ref.pool())
    .await?;

    let top_users = db_analytics::top_n_users(db_ref.pool(), 1, "events", 5).await?;
    let top_sources = db_analytics::source_distribution(db_ref.pool(), 1).await?;
    let compliance = build_compliance(db_ref.pool()).await?;
    let report = DailyReport {
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

    let json_blob = serde_json::to_string(&report)?;
    let summary = format!(
        "events={}, conflicts={}, alerts={}",
        report.events_total, report.conflicts_detected, report.alerts_fired
    );
    let id = db_analytics::save_report_snapshot(
        db_ref.pool(),
        "daily",
        &period_start,
        &period_end,
        &json_blob,
        Some(&summary),
    )
    .await?;
    let _ = db_analytics::cleanup_old_reports(db_ref.pool(), 90).await;
    Ok((id, summary))
}

/// Returns time-series bucketed counts for dashboards.
pub(crate) async fn trends(
    auth: AuthUser,
    Query(q): Query<TrendsQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db_ref = helpers::require_db(&state, &auth.request_id)?;
    let interval = q.interval.unwrap_or_else(|| "day".to_string());
    if !matches!(interval.as_str(), "hour" | "day" | "week") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "interval must be one of: hour, day, week",
        )
        .with_request_id(&auth.request_id));
    }
    let days = q.days.unwrap_or(30).clamp(1, 365);
    let start = Utc::now() - Duration::days(days);
    let end = Utc::now();

    let metric = q.metric.to_lowercase();
    let raw_rows = match metric.as_str() {
        "mappings" | "events" => {
            db_analytics::count_events_by_period(
                db_ref.pool(),
                start,
                end,
                &interval,
                q.source.as_deref(),
            )
            .await
        }
        "conflicts" => {
            db_analytics::count_conflicts_by_period(db_ref.pool(), start, end, &interval).await
        }
        "alerts" => {
            db_analytics::count_alerts_by_period(db_ref.pool(), start, end, &interval).await
        }
        "firewall_pushes" => {
            db_analytics::count_firewall_pushes_by_period(db_ref.pool(), start, end, &interval)
                .await
        }
        _ => Err(anyhow::anyhow!(
            "metric must be one of: mappings, events, conflicts, alerts, firewall_pushes"
        )),
    }
    .map_err(|e| {
        warn!(error = %e, metric = %metric, "Failed to load trends");
        ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Invalid trends query",
        )
        .with_request_id(&auth.request_id)
    })?;

    let mut total = 0_i64;
    let mut data = Vec::with_capacity(raw_rows.len());
    for (ts, count) in raw_rows {
        total += count;
        data.push(TrendPoint {
            timestamp: normalize_bucket(&interval, ts),
            count,
        });
    }

    Ok(Json(TrendsResponse {
        metric,
        interval,
        days,
        data,
        total,
    }))
}

/// Returns top-N dimensions by selected metric.
pub(crate) async fn top_n(
    auth: AuthUser,
    Query(q): Query<TopQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db_ref = helpers::require_db(&state, &auth.request_id)?;
    let metric = q
        .metric
        .unwrap_or_else(|| "events".to_string())
        .to_lowercase();
    if !matches!(metric.as_str(), "events" | "conflicts" | "alerts") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "metric must be one of: events, conflicts, alerts",
        )
        .with_request_id(&auth.request_id));
    }
    let days = q.days.unwrap_or(7).clamp(1, 90);
    let limit = q.limit.unwrap_or(10).clamp(1, 100);
    let dimension = q.dimension.to_lowercase();

    let rows: Vec<(String, i64)> = match dimension.as_str() {
        "users" => db_analytics::top_n_users(db_ref.pool(), days, &metric, limit).await,
        "ips" => db_analytics::top_n_ips(db_ref.pool(), days, &metric, limit).await,
        "sources" => {
            let sql = match metric.as_str() {
                "events" => {
                    "SELECT COALESCE(NULLIF(source, ''), 'unknown') AS label, COUNT(*) AS c
                     FROM events WHERE timestamp >= datetime('now', ? || ' days')
                     GROUP BY label ORDER BY c DESC LIMIT ?"
                }
                "conflicts" => {
                    "SELECT COALESCE(NULLIF(source, ''), 'unknown') AS label, COUNT(*) AS c
                     FROM conflicts WHERE detected_at >= datetime('now', ? || ' days')
                     GROUP BY label ORDER BY c DESC LIMIT ?"
                }
                _ => {
                    "SELECT COALESCE(NULLIF(source, ''), 'unknown') AS label, COUNT(*) AS c
                     FROM alert_history WHERE fired_at >= datetime('now', ? || ' days')
                     GROUP BY label ORDER BY c DESC LIMIT ?"
                }
            };
            sqlx::query(sql)
                .bind(-days)
                .bind(limit)
                .fetch_all(db_ref.pool())
                .await
                .map_err(anyhow::Error::from)
                .map(|rows| {
                    rows.into_iter()
                        .map(|r| {
                            (
                                r.try_get("label").unwrap_or_default(),
                                r.try_get("c").unwrap_or(0),
                            )
                        })
                        .collect()
                })
        }
        "subnets" | "device_types" | "vendors" => {
            let (col, join) = match dimension.as_str() {
                "subnets" => (
                    "COALESCE(NULLIF(s.name, ''), 'Unassigned')",
                    "LEFT JOIN subnets s ON s.id = m.subnet_id",
                ),
                "device_types" => ("COALESCE(NULLIF(m.device_type, ''), 'Unknown')", ""),
                _ => ("COALESCE(NULLIF(m.vendor, ''), 'Unknown')", ""),
            };
            let (table, ts_col, ip_col) = match metric.as_str() {
                "events" => ("events e", "e.timestamp", "e.ip"),
                "conflicts" => ("conflicts e", "e.detected_at", "e.ip"),
                _ => ("alert_history e", "e.fired_at", "e.ip"),
            };
            let sql = format!(
                "SELECT {col} AS label, COUNT(*) AS c
                 FROM {table}
                 LEFT JOIN mappings m ON m.ip = {ip_col}
                 {join}
                 WHERE {ts_col} >= datetime('now', ? || ' days')
                 GROUP BY label
                 ORDER BY c DESC
                 LIMIT ?"
            );
            sqlx::query(&sql)
                .bind(-days)
                .bind(limit)
                .fetch_all(db_ref.pool())
                .await
                .map_err(anyhow::Error::from)
                .map(|rows| {
                    rows.into_iter()
                        .map(|r| {
                            (
                                r.try_get("label").unwrap_or_default(),
                                r.try_get("c").unwrap_or(0),
                            )
                        })
                        .collect()
                })
        }
        _ => Err(anyhow::anyhow!(
            "dimension must be one of: users, ips, subnets, sources, device_types, vendors"
        )),
    }
    .map_err(|e| {
        warn!(error = %e, dimension = %dimension, metric = %metric, "Failed to compute top-N");
        ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Invalid top-N query",
        )
        .with_request_id(&auth.request_id)
    })?;

    let total: i64 = rows.iter().map(|(_, c)| *c).sum();
    let data = rows
        .into_iter()
        .map(|(label, count)| TopPoint {
            label,
            count,
            percentage: pct(count, total),
        })
        .collect::<Vec<_>>();

    Ok(Json(TopResponse {
        dimension,
        metric,
        days,
        data,
    }))
}

/// Returns event distribution grouped by source type.
pub(crate) async fn source_distribution(
    auth: AuthUser,
    Query(q): Query<SourcesQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db_ref = helpers::require_db(&state, &auth.request_id)?;
    let days = q.days.unwrap_or(7).clamp(1, 365);
    let rows = db_analytics::source_distribution(db_ref.pool(), days)
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to compute source distribution");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to compute source distribution",
            )
            .with_request_id(&auth.request_id)
        })?;
    let total_events: i64 = rows.iter().map(|(_, c)| *c).sum();
    let sources = rows
        .into_iter()
        .map(|(source, count)| SourcePoint {
            source,
            count,
            percentage: pct(count, total_events),
        })
        .collect::<Vec<_>>();

    Ok(Json(SourceDistributionResponse {
        days,
        total_events,
        sources,
    }))
}

/// Returns network hygiene and integration compliance summary.
pub(crate) async fn compliance(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db_ref = helpers::require_db(&state, &auth.request_id)?;
    let payload = build_compliance(db_ref.pool()).await.map_err(|e| {
        warn!(error = %e, "Failed to build compliance summary");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to compute compliance summary",
        )
        .with_request_id(&auth.request_id)
    })?;
    Ok(Json(payload))
}

/// Lists recent report snapshots.
pub(crate) async fn list_reports(
    auth: AuthUser,
    Query(q): Query<ReportsQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db_ref = helpers::require_db(&state, &auth.request_id)?;
    let limit = q.limit.unwrap_or(30).clamp(1, 200);
    let rows = db_analytics::list_report_snapshots(db_ref.pool(), q.report_type.as_deref(), limit)
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to list report snapshots");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to list reports",
            )
            .with_request_id(&auth.request_id)
        })?;

    let data = rows
        .iter()
        .map(|r| ReportListItem {
            id: r.id,
            report_type: r.report_type.clone(),
            generated_at: r.generated_at.clone(),
            period_start: r.period_start.clone(),
            period_end: r.period_end.clone(),
            summary: r.summary.clone(),
        })
        .collect::<Vec<_>>();
    Ok(Json(ReportListResponse {
        total: i64::try_from(data.len()).unwrap_or(0),
        data,
    }))
}

/// Returns one full report snapshot with parsed JSON blob.
pub(crate) async fn get_report(
    auth: AuthUser,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db_ref = helpers::require_db(&state, &auth.request_id)?;
    let row = db_analytics::get_report_snapshot(db_ref.pool(), id)
        .await
        .map_err(|e| {
            warn!(error = %e, report_id = id, "Failed to get report snapshot");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to get report",
            )
            .with_request_id(&auth.request_id)
        })?
        .ok_or_else(|| {
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "Report not found")
                .with_request_id(&auth.request_id)
        })?;

    let data = serde_json::from_str::<Value>(&row.data).unwrap_or(Value::String(row.data.clone()));
    Ok(Json(ReportDetailsResponse {
        id: row.id,
        report_type: row.report_type,
        generated_at: row.generated_at,
        period_start: row.period_start,
        period_end: row.period_end,
        summary: row.summary,
        data,
    }))
}

/// Forces immediate daily report generation and snapshot persistence.
pub(crate) async fn generate_report(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db_ref = helpers::require_db(&state, &auth.request_id)?;
    let (id, summary) = generate_report_now(db_ref).await.map_err(|e| {
        warn!(error = %e, "Failed to generate report snapshot");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to generate report",
        )
        .with_request_id(&auth.request_id)
    })?;
    helpers::audit(
        db_ref,
        &auth,
        "analytics_report_generate",
        Some(&id.to_string()),
        Some(&summary),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": id,
            "summary": summary
        })),
    ))
}
