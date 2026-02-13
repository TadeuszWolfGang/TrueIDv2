//! Prometheus metrics rendering helpers.

use chrono::Utc;
use sqlx::Row;
use std::time::Instant;
use trueid_common::model::AdapterStatus;

/// Escapes Prometheus label values.
///
/// Parameters: `value` - unescaped label value.
/// Returns: escaped label value.
fn esc_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Adds a counter metric header.
///
/// Parameters: `buf` - output buffer, `name` - metric name, `help` - metric description.
/// Returns: none.
fn add_counter_header(buf: &mut String, name: &str, help: &str) {
    buf.push_str(&format!("# HELP {name} {help}\n"));
    buf.push_str(&format!("# TYPE {name} counter\n"));
}

/// Adds a gauge metric header.
///
/// Parameters: `buf` - output buffer, `name` - metric name, `help` - metric description.
/// Returns: none.
fn add_gauge_header(buf: &mut String, name: &str, help: &str) {
    buf.push_str(&format!("# HELP {name} {help}\n"));
    buf.push_str(&format!("# TYPE {name} gauge\n"));
}

/// Generates Prometheus text metrics from runtime and DB state.
///
/// Parameters: `adapter_stats` - live adapter counters, `pool` - database pool, `start_time` - engine boot instant.
/// Returns: metrics payload in Prometheus exposition format.
pub async fn generate_metrics(
    adapter_stats: &[AdapterStatus],
    pool: &sqlx::SqlitePool,
    start_time: Instant,
) -> String {
    let active_mappings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE is_active = 1")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    let conflicts_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM conflicts")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    let alerts_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alert_history")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    let ldap_sync_users: i64 = sqlx::query_scalar("SELECT COALESCE(last_sync_count, 0) FROM ldap_config WHERE id = 1")
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or(0);

    let firewall_rows = sqlx::query(
        "SELECT t.name AS target_name, h.status AS status, COUNT(*) AS c
         FROM firewall_push_history h
         JOIN firewall_targets t ON t.id = h.target_id
         GROUP BY t.name, h.status
         ORDER BY t.name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let siem_rows = sqlx::query("SELECT name, events_forwarded FROM siem_targets ORDER BY name")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    let mut out = String::new();
    add_counter_header(
        &mut out,
        "trueid_events_total",
        "Total identity events processed",
    );
    for s in adapter_stats {
        out.push_str(&format!(
            "trueid_events_total{{source=\"{}\"}} {}\n",
            esc_label(&s.name),
            s.events_total
        ));
    }

    add_gauge_header(
        &mut out,
        "trueid_active_mappings",
        "Current active IP-to-user mappings",
    );
    out.push_str(&format!("trueid_active_mappings {active_mappings}\n"));

    add_counter_header(
        &mut out,
        "trueid_conflicts_total",
        "Total conflicts detected",
    );
    out.push_str(&format!("trueid_conflicts_total {conflicts_total}\n"));

    add_counter_header(
        &mut out,
        "trueid_alerts_fired_total",
        "Total alerts fired",
    );
    out.push_str(&format!("trueid_alerts_fired_total {alerts_total}\n"));

    add_counter_header(
        &mut out,
        "trueid_firewall_push_total",
        "Total firewall pushes",
    );
    for row in firewall_rows {
        let target_name: String = row.try_get("target_name").unwrap_or_default();
        let status: String = row.try_get("status").unwrap_or_else(|_| "unknown".to_string());
        let count: i64 = row.try_get("c").unwrap_or(0);
        out.push_str(&format!(
            "trueid_firewall_push_total{{target=\"{}\",status=\"{}\"}} {}\n",
            esc_label(&target_name),
            esc_label(&status),
            count
        ));
    }

    add_counter_header(
        &mut out,
        "trueid_siem_events_forwarded_total",
        "SIEM events forwarded",
    );
    for row in siem_rows {
        let target_name: String = row.try_get("name").unwrap_or_default();
        let count: i64 = row.try_get("events_forwarded").unwrap_or(0);
        out.push_str(&format!(
            "trueid_siem_events_forwarded_total{{target=\"{}\"}} {}\n",
            esc_label(&target_name),
            count
        ));
    }

    add_gauge_header(
        &mut out,
        "trueid_ldap_sync_users",
        "Users synced in last LDAP cycle",
    );
    out.push_str(&format!("trueid_ldap_sync_users {ldap_sync_users}\n"));

    add_gauge_header(&mut out, "trueid_db_pool_size", "SQLite connection pool size");
    out.push_str(&format!("trueid_db_pool_size {}\n", pool.size()));

    add_gauge_header(&mut out, "trueid_uptime_seconds", "Engine uptime");
    out.push_str(&format!(
        "trueid_uptime_seconds {}\n",
        start_time.elapsed().as_secs()
    ));

    out.push_str(&format!("# generated_at {}\n", Utc::now().to_rfc3339()));
    out
}
