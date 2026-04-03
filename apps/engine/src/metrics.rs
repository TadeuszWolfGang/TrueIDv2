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
    let active_mappings: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mappings WHERE is_active = 1")
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
    let ldap_sync_users: i64 =
        sqlx::query_scalar("SELECT COALESCE(last_sync_count, 0) FROM ldap_config WHERE id = 1")
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

    add_counter_header(&mut out, "trueid_alerts_fired_total", "Total alerts fired");
    out.push_str(&format!("trueid_alerts_fired_total {alerts_total}\n"));

    add_counter_header(
        &mut out,
        "trueid_firewall_push_total",
        "Total firewall pushes",
    );
    for row in firewall_rows {
        let target_name: String = row.try_get("target_name").unwrap_or_default();
        let status: String = row
            .try_get("status")
            .unwrap_or_else(|_| "unknown".to_string());
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

    add_gauge_header(
        &mut out,
        "trueid_db_pool_size",
        "SQLite connection pool size",
    );
    out.push_str(&format!("trueid_db_pool_size {}\n", pool.size()));

    add_gauge_header(&mut out, "trueid_uptime_seconds", "Engine uptime");
    out.push_str(&format!(
        "trueid_uptime_seconds {}\n",
        start_time.elapsed().as_secs()
    ));

    out.push_str(&format!("# generated_at {}\n", Utc::now().to_rfc3339()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::net::IpAddr;
    use trueid_common::db::init_db;
    use trueid_common::model::{IdentityEvent, SourceType};

    #[tokio::test]
    async fn test_generate_metrics_renders_expected_families_and_labels() {
        let db = init_db("sqlite::memory:")
            .await
            .expect("init_db should succeed");

        let event = IdentityEvent {
            source: SourceType::Radius,
            ip: "10.1.2.3"
                .parse::<IpAddr>()
                .expect("ip parse should succeed"),
            user: "alice".to_string(),
            timestamp: Utc::now() - Duration::minutes(1),
            raw_data: "radius login".to_string(),
            mac: Some("AA:BB:CC:DD:EE:FF".to_string()),
            confidence_score: 95,
        };
        db.upsert_mapping(event, Some("Acme \"Switch\"\nCore"))
            .await
            .expect("upsert_mapping should succeed");

        sqlx::query(
            "INSERT INTO conflicts (ip, conflict_type, severity, user_old, user_new, source)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind("10.1.2.3")
        .bind("duplicate_ip")
        .bind("high")
        .bind("alice")
        .bind("bob")
        .bind("Radius")
        .execute(db.pool())
        .await
        .expect("insert conflict should succeed");

        sqlx::query(
            "INSERT INTO alert_rules (name, rule_type, severity)
             VALUES (?, ?, ?)",
        )
        .bind("new_subnet")
        .bind("new_subnet")
        .bind("high")
        .execute(db.pool())
        .await
        .expect("insert alert rule should succeed");

        sqlx::query(
            "INSERT INTO alert_history (rule_id, rule_name, rule_type, severity, details)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(1_i64)
        .bind("new_subnet")
        .bind("new_subnet")
        .bind("high")
        .bind("detected")
        .execute(db.pool())
        .await
        .expect("insert alert should succeed");

        sqlx::query(
            "INSERT INTO firewall_targets (name, firewall_type, host, port, enabled)
             VALUES (?, 'panos', ?, ?, 1)",
        )
        .bind("fw\"edge\n1")
        .bind("fw.example")
        .bind(443_i64)
        .execute(db.pool())
        .await
        .expect("insert firewall target should succeed");

        sqlx::query(
            "INSERT INTO firewall_push_history (target_id, mapping_count, status, duration_ms)
             VALUES (1, 1, 'ok', 12)",
        )
        .execute(db.pool())
        .await
        .expect("insert firewall history should succeed");

        sqlx::query(
            "INSERT INTO siem_targets (name, format, transport, host, port, events_forwarded)
             VALUES (?, 'cef', 'udp', ?, ?, ?)",
        )
        .bind("siem\\core")
        .bind("siem.example")
        .bind(514_i64)
        .bind(42_i64)
        .execute(db.pool())
        .await
        .expect("insert siem target should succeed");

        sqlx::query("UPDATE ldap_config SET last_sync_count = 17 WHERE id = 1")
            .execute(db.pool())
            .await
            .expect("update ldap config should succeed");

        let adapter_stats = vec![AdapterStatus {
            name: "radius\nadapter".to_string(),
            protocol: "udp".to_string(),
            bind: "0.0.0.0:1813".to_string(),
            status: "running".to_string(),
            last_event_at: Some(Utc::now()),
            events_total: 9,
        }];

        let output = generate_metrics(&adapter_stats, db.pool(), Instant::now()).await;

        assert!(output.contains("# HELP trueid_events_total Total identity events processed"));
        assert!(output.contains("trueid_events_total{source=\"radius\\nadapter\"} 9"));
        assert!(output.contains("trueid_active_mappings 1"));
        assert!(output.contains("trueid_conflicts_total 1"));
        assert!(output.contains("trueid_alerts_fired_total 1"));
        assert!(output
            .contains("trueid_firewall_push_total{target=\"fw\\\"edge\\n1\",status=\"ok\"} 1"));
        assert!(output.contains("trueid_siem_events_forwarded_total{target=\"siem\\\\core\"} 42"));
        assert!(output.contains("trueid_ldap_sync_users 17"));
        assert!(output.contains("trueid_db_pool_size "));
        assert!(output.contains("trueid_uptime_seconds "));
    }
}
