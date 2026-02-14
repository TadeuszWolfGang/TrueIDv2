//! Scheduled report runner and channel delivery.

use chrono::{Datelike, Timelike, Utc, Weekday};
use serde_json::{json, Value};
use sqlx::Row;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use trueid_common::db::Db;
use trueid_common::db_analytics;

use crate::notifications::{NotificationDispatcher, ScheduledReportPayload};
use crate::report_generator;

/// Report schedule row loaded from database.
#[derive(Debug, Clone)]
pub struct ReportSchedule {
    pub id: i64,
    pub name: String,
    pub report_type: String,
    pub schedule_cron: String,
    pub channel_ids: Vec<i64>,
    pub include_sections: Vec<String>,
    pub last_sent_at: Option<String>,
}

/// Send-now API response payload.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SendNowResult {
    pub success: bool,
    pub delivered: i64,
    pub attempted: i64,
}

/// Parses simple cron string (`min hour * * dow`).
///
/// Parameters: `cron` - cron string.
/// Returns: `(minute, hour, weekday)` when valid.
fn parse_simple_cron(cron: &str) -> Option<(u32, u32, u32)> {
    let parts = cron.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 5 {
        return None;
    }
    let minute = parts[0].parse::<u32>().ok()?;
    let hour = parts[1].parse::<u32>().ok()?;
    let dow = parts[4].parse::<u32>().ok()?;
    if minute > 59 || hour > 23 || dow > 6 {
        return None;
    }
    Some((minute, hour, dow))
}

/// Converts chrono weekday to cron-compatible value.
///
/// Parameters: `weekday` - chrono weekday.
/// Returns: weekday number (`0` Sunday ... `6` Saturday).
fn weekday_to_cron(weekday: Weekday) -> u32 {
    match weekday {
        Weekday::Sun => 0,
        Weekday::Mon => 1,
        Weekday::Tue => 2,
        Weekday::Wed => 3,
        Weekday::Thu => 4,
        Weekday::Fri => 5,
        Weekday::Sat => 6,
    }
}

/// Checks if schedule should run in current minute window.
///
/// Parameters: `schedule` - schedule row.
/// Returns: true when run should be executed.
fn should_run_now(schedule: &ReportSchedule) -> bool {
    let now = Utc::now();
    let Some((minute, hour, dow)) = parse_simple_cron(&schedule.schedule_cron) else {
        return false;
    };
    if now.minute() != minute || now.hour() != hour || weekday_to_cron(now.weekday()) != dow {
        return false;
    }
    // Prevent duplicates in the same minute.
    if let Some(last_sent) = &schedule.last_sent_at {
        if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(last_sent) {
            let last = parsed.with_timezone(&Utc);
            if last.year() == now.year()
                && last.month() == now.month()
                && last.day() == now.day()
                && last.hour() == now.hour()
                && last.minute() == now.minute()
            {
                return false;
            }
        }
    }
    true
}

/// Loads all enabled report schedules.
///
/// Parameters: `db` - shared database handle.
/// Returns: parsed schedules.
pub async fn load_enabled_schedules(db: &Db) -> anyhow::Result<Vec<ReportSchedule>> {
    let rows = sqlx::query(
        "SELECT id, name, report_type, schedule_cron, channel_ids, include_sections, last_sent_at
         FROM report_schedules
         WHERE enabled = 1
         ORDER BY id ASC",
    )
    .fetch_all(db.pool())
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let channel_ids_raw: String = row.try_get("channel_ids").unwrap_or_else(|_| "[]".into());
        let include_sections_raw: String = row
            .try_get("include_sections")
            .unwrap_or_else(|_| "[\"summary\",\"conflicts\",\"alerts\"]".into());
        let channel_ids = serde_json::from_str::<Vec<i64>>(&channel_ids_raw).unwrap_or_default();
        let include_sections = serde_json::from_str::<Vec<String>>(&include_sections_raw)
            .unwrap_or_else(|_| {
                vec![
                    "summary".to_string(),
                    "conflicts".to_string(),
                    "alerts".to_string(),
                ]
            });
        out.push(ReportSchedule {
            id: row.try_get("id").unwrap_or_default(),
            name: row.try_get("name").unwrap_or_default(),
            report_type: row
                .try_get("report_type")
                .unwrap_or_else(|_| "daily".to_string()),
            schedule_cron: row
                .try_get("schedule_cron")
                .unwrap_or_else(|_| "0 8 * * 1".to_string()),
            channel_ids,
            include_sections,
            last_sent_at: row.try_get("last_sent_at").ok(),
        });
    }
    Ok(out)
}

/// Builds one report JSON according to selected sections.
///
/// Parameters: `db` - shared database handle, `schedule` - schedule.
/// Returns: report payload for channel delivery.
pub async fn generate_report_for_schedule(
    db: &Db,
    schedule: &ReportSchedule,
) -> anyhow::Result<ScheduledReportPayload> {
    let lookback_days = if schedule.report_type == "weekly" {
        7
    } else {
        1
    };
    let period_end = Utc::now();
    let period_start = period_end - chrono::Duration::days(lookback_days);

    let mut sections = serde_json::Map::new();
    let wants = |name: &str| schedule.include_sections.iter().any(|s| s == name);

    if wants("summary") {
        let mappings_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mappings")
            .fetch_one(db.pool())
            .await
            .unwrap_or(0);
        let events_total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events WHERE timestamp >= datetime('now', ? || ' days')",
        )
        .bind(-lookback_days)
        .fetch_one(db.pool())
        .await
        .unwrap_or(0);
        let active_users: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT user) FROM mappings WHERE is_active = 1 AND user IS NOT NULL AND user != ''",
        )
        .fetch_one(db.pool())
        .await
        .unwrap_or(0);
        let top_sources = db_analytics::source_distribution(db.pool(), lookback_days)
            .await
            .unwrap_or_default();
        sections.insert(
            "summary".to_string(),
            json!({
                "mappings_total": mappings_total,
                "events_total": events_total,
                "active_users": active_users,
                "top_sources": top_sources,
            }),
        );
    }

    if wants("conflicts") {
        let open_total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM conflicts WHERE resolved_at IS NULL")
                .fetch_one(db.pool())
                .await
                .unwrap_or(0);
        let critical: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM conflicts WHERE resolved_at IS NULL AND severity='critical'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap_or(0);
        let warning: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM conflicts WHERE resolved_at IS NULL AND severity='warning'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap_or(0);
        let info_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM conflicts WHERE resolved_at IS NULL AND severity='info'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap_or(0);
        sections.insert(
            "conflicts".to_string(),
            json!({
                "open_total": open_total,
                "critical": critical,
                "warning": warning,
                "info": info_count,
            }),
        );
    }

    if wants("alerts") {
        let fired: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM alert_history WHERE fired_at >= datetime('now', ? || ' days')",
        )
        .bind(-lookback_days)
        .fetch_one(db.pool())
        .await
        .unwrap_or(0);
        let recent = sqlx::query(
            "SELECT rule_name, severity, fired_at
             FROM alert_history
             ORDER BY fired_at DESC
             LIMIT 10",
        )
        .fetch_all(db.pool())
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| {
            json!({
                "rule_name": r.try_get::<String, _>("rule_name").unwrap_or_default(),
                "severity": r.try_get::<String, _>("severity").unwrap_or_default(),
                "fired_at": r.try_get::<String, _>("fired_at").unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();
        sections.insert(
            "alerts".to_string(),
            json!({
                "fired": fired,
                "recent": recent,
            }),
        );
    }

    if wants("compliance") {
        let compliance = report_generator::build_compliance_subset(db.pool()).await?;
        sections.insert("compliance".to_string(), serde_json::to_value(compliance)?);
    }

    if wants("top_users") {
        let top_users = db_analytics::top_n_users(db.pool(), lookback_days, "events", 10)
            .await
            .unwrap_or_default();
        sections.insert("top_users".to_string(), serde_json::to_value(top_users)?);
    }

    if wants("top_ips") {
        let top_ips = db_analytics::top_n_ips(db.pool(), lookback_days, "events", 10)
            .await
            .unwrap_or_default();
        sections.insert("top_ips".to_string(), serde_json::to_value(top_ips)?);
    }

    Ok(ScheduledReportPayload {
        title: format!("TrueID Scheduled Report: {}", schedule.name),
        report_type: schedule.report_type.clone(),
        period_start: period_start.to_rfc3339(),
        period_end: period_end.to_rfc3339(),
        sections: Value::Object(sections),
    })
}

/// Delivers one generated report via configured channels.
///
/// Parameters: `dispatcher` - notification dispatcher, `schedule` - schedule, `report` - payload.
/// Returns: send-now result with counters.
pub async fn deliver_report(
    dispatcher: &NotificationDispatcher,
    schedule: &ReportSchedule,
    report: &ScheduledReportPayload,
) -> SendNowResult {
    if schedule.channel_ids.is_empty() {
        return SendNowResult {
            success: true,
            delivered: 0,
            attempted: 0,
        };
    }
    let outcomes = dispatcher
        .dispatch_report(&schedule.channel_ids, report)
        .await;
    let attempted = i64::try_from(outcomes.len()).unwrap_or(0);
    let delivered =
        i64::try_from(outcomes.iter().filter(|o| o.outcome.is_ok()).count()).unwrap_or(0);
    SendNowResult {
        success: delivered == attempted,
        delivered,
        attempted,
    }
}

/// Updates `last_sent_at` timestamp for schedule.
///
/// Parameters: `db` - shared DB handle, `schedule_id` - schedule id.
/// Returns: result of update.
pub async fn update_last_sent(db: &Db, schedule_id: i64) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE report_schedules
         SET last_sent_at = datetime('now'), updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(schedule_id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Executes one schedule immediately (used by API send-now and cron loop).
///
/// Parameters: `db` - shared DB handle, `schedule` - schedule row.
/// Returns: send result.
pub async fn run_schedule_now(db: Arc<Db>, schedule: ReportSchedule) -> SendNowResult {
    let dispatcher = NotificationDispatcher::new(db.clone(), reqwest::Client::new());
    let report = match generate_report_for_schedule(db.as_ref(), &schedule).await {
        Ok(report) => report,
        Err(e) => {
            warn!(error = %e, schedule_id = schedule.id, "Failed to generate scheduled report");
            return SendNowResult {
                success: false,
                delivered: 0,
                attempted: i64::try_from(schedule.channel_ids.len()).unwrap_or(0),
            };
        }
    };
    let result = deliver_report(&dispatcher, &schedule, &report).await;
    if let Err(e) = update_last_sent(db.as_ref(), schedule.id).await {
        warn!(error = %e, schedule_id = schedule.id, "Failed to update last_sent_at");
    }
    result
}

/// Executes send-now for a schedule id.
///
/// Parameters: `db` - shared DB handle, `schedule_id` - schedule id.
/// Returns: send result.
pub async fn run_schedule_now_by_id(
    db: Arc<Db>,
    schedule_id: i64,
) -> anyhow::Result<SendNowResult> {
    let rows = load_enabled_schedules(db.as_ref()).await?;
    let schedule = rows
        .into_iter()
        .find(|s| s.id == schedule_id)
        .ok_or_else(|| anyhow::anyhow!("schedule not found or disabled"))?;
    Ok(run_schedule_now(db, schedule).await)
}

/// Background scheduler loop checking schedules every minute.
///
/// Parameters: `db` - shared DB handle.
/// Returns: never.
pub async fn run_report_scheduler(db: Arc<Db>) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let schedules = match load_enabled_schedules(db.as_ref()).await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "Failed to load enabled report schedules");
                continue;
            }
        };
        for schedule in schedules {
            if !should_run_now(&schedule) {
                continue;
            }
            let result = run_schedule_now(db.clone(), schedule.clone()).await;
            info!(
                schedule_id = schedule.id,
                delivered = result.delivered,
                attempted = result.attempted,
                success = result.success,
                "Scheduled report delivery executed"
            );
        }
    }
}

/// Starts report scheduler loop in background task.
///
/// Parameters: `db` - shared DB handle.
/// Returns: none.
pub fn start_report_scheduler(db: Arc<Db>) {
    tokio::spawn(async move {
        run_report_scheduler(db).await;
    });
}
