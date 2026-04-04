//! Conflict detection for real-time identity ingestion.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::{Row, SqlitePool};
use trueid_common::model::IdentityEvent;

/// Conflict row representation used by the engine logger and APIs.
#[derive(Debug, Clone, Serialize)]
pub struct ConflictRecord {
    pub id: i64,
    pub conflict_type: String,
    pub severity: String,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub user_old: Option<String>,
    pub user_new: Option<String>,
    pub source: String,
    pub details: Option<String>,
    pub detected_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
}

/// Insert payload for a conflict row.
#[derive(Debug, Clone)]
struct NewConflict {
    conflict_type: String,
    severity: String,
    ip: Option<String>,
    mac: Option<String>,
    user_old: Option<String>,
    user_new: Option<String>,
    source: String,
    details: Option<String>,
}

/// Detects and stores conflicts for a single incoming event.
///
/// Parameters: `pool` - SQLite connection pool, `event` - incoming identity event.
/// Returns: vector of inserted conflict records for logging/observability.
pub async fn detect_conflicts(
    pool: &SqlitePool,
    event: &IdentityEvent,
) -> Result<Vec<ConflictRecord>> {
    let mut detected = Vec::new();
    let event_ip = event.ip.to_string();
    let event_source = format!("{:?}", event.source);

    let current = sqlx::query("SELECT user, mac FROM mappings WHERE ip = ?")
        .bind(&event_ip)
        .fetch_optional(pool)
        .await?;

    if let Some(row) = current {
        let existing_user: String = row.try_get("user").unwrap_or_default();
        let existing_mac: Option<String> = row.try_get("mac").ok();
        if !existing_user.is_empty() && existing_user != event.user {
            let details = json!({
                "ip": event_ip,
                "old_user": existing_user,
                "new_user": event.user,
                "source": event_source,
            })
            .to_string();
            if let Some(record) = insert_conflict_if_not_recent(
                pool,
                NewConflict {
                    conflict_type: "ip_user_change".to_string(),
                    severity: "warning".to_string(),
                    ip: Some(event_ip.clone()),
                    mac: event.mac.clone().or(existing_mac),
                    user_old: Some(existing_user),
                    user_new: Some(event.user.clone()),
                    source: event_source.clone(),
                    details: Some(details),
                },
            )
            .await?
            {
                detected.push(record);
            }
        }
    }

    if let Some(event_mac) = event.mac.clone() {
        let rows = sqlx::query("SELECT ip FROM mappings WHERE mac = ? AND ip != ?")
            .bind(&event_mac)
            .bind(&event_ip)
            .fetch_all(pool)
            .await?;

        if !rows.is_empty() {
            let mut other_ips = Vec::with_capacity(rows.len());
            for row in rows {
                let other_ip: String = row.try_get("ip").unwrap_or_default();
                if !other_ip.is_empty() {
                    other_ips.push(other_ip);
                }
            }

            if !other_ips.is_empty() {
                let info_details = json!({
                    "old_ip": other_ips[0],
                    "new_ip": event_ip,
                    "mac": event_mac,
                    "source": event_source,
                })
                .to_string();
                if let Some(record) = insert_conflict_if_not_recent(
                    pool,
                    NewConflict {
                        conflict_type: "mac_ip_conflict".to_string(),
                        severity: "info".to_string(),
                        ip: Some(event_ip.clone()),
                        mac: Some(event_mac.clone()),
                        user_old: None,
                        user_new: Some(event.user.clone()),
                        source: event_source.clone(),
                        details: Some(info_details),
                    },
                )
                .await?
                {
                    detected.push(record);
                }

                let critical_details = json!({
                    "mac": event_mac,
                    "new_ip": event_ip,
                    "other_ips": other_ips,
                    "source": event_source,
                })
                .to_string();
                if let Some(record) = insert_conflict_if_not_recent(
                    pool,
                    NewConflict {
                        conflict_type: "duplicate_mac".to_string(),
                        severity: "critical".to_string(),
                        ip: Some(event_ip.clone()),
                        mac: Some(event_mac),
                        user_old: None,
                        user_new: Some(event.user.clone()),
                        source: event_source,
                        details: Some(critical_details),
                    },
                )
                .await?
                {
                    detected.push(record);
                }
            }
        }
    }

    Ok(detected)
}

/// Inserts a conflict row unless an equivalent unresolved conflict exists recently.
///
/// Parameters: all conflict fields matching table columns.
/// Returns: inserted conflict record or `None` if deduplicated.
async fn insert_conflict_if_not_recent(
    pool: &SqlitePool,
    new_conflict: NewConflict,
) -> Result<Option<ConflictRecord>> {
    let recent = sqlx::query(
        "SELECT id FROM conflicts
         WHERE conflict_type = ?
           AND COALESCE(ip, '') = COALESCE(?, '')
           AND COALESCE(mac, '') = COALESCE(?, '')
           AND COALESCE(user_old, '') = COALESCE(?, '')
           AND COALESCE(user_new, '') = COALESCE(?, '')
           AND resolved_at IS NULL
           AND detected_at > datetime('now', '-5 minutes')
         LIMIT 1",
    )
    .bind(&new_conflict.conflict_type)
    .bind(new_conflict.ip.clone())
    .bind(new_conflict.mac.clone())
    .bind(new_conflict.user_old.clone())
    .bind(new_conflict.user_new.clone())
    .fetch_optional(pool)
    .await?;

    if recent.is_some() {
        return Ok(None);
    }

    let now = Utc::now();
    let insert_result = sqlx::query(
        "INSERT INTO conflicts (
            conflict_type, severity, ip, mac, user_old, user_new, source, details, detected_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&new_conflict.conflict_type)
    .bind(&new_conflict.severity)
    .bind(new_conflict.ip.clone())
    .bind(new_conflict.mac.clone())
    .bind(new_conflict.user_old.clone())
    .bind(new_conflict.user_new.clone())
    .bind(new_conflict.source.clone())
    .bind(new_conflict.details.clone())
    .bind(now)
    .execute(pool)
    .await?;

    let inserted_id = insert_result.last_insert_rowid();
    let row = sqlx::query(
        "SELECT id, conflict_type, severity, ip, mac, user_old, user_new, source, details, \
                detected_at, resolved_at, resolved_by
         FROM conflicts
         WHERE id = ?",
    )
    .bind(inserted_id)
    .fetch_one(pool)
    .await?;

    Ok(Some(ConflictRecord {
        id: row.try_get("id").unwrap_or(0),
        conflict_type: row.try_get("conflict_type").unwrap_or_default(),
        severity: row.try_get("severity").unwrap_or_default(),
        ip: row.try_get("ip").ok(),
        mac: row.try_get("mac").ok(),
        user_old: row.try_get("user_old").ok(),
        user_new: row.try_get("user_new").ok(),
        source: row.try_get("source").unwrap_or_default(),
        details: row.try_get("details").ok(),
        detected_at: row.try_get("detected_at").unwrap_or_else(|_| Utc::now()),
        resolved_at: row.try_get("resolved_at").ok(),
        resolved_by: row.try_get("resolved_by").ok(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use trueid_common::db::init_db;
    use trueid_common::model::SourceType;

    fn test_event(ip: &str, user: &str, mac: &str) -> IdentityEvent {
        IdentityEvent {
            source: SourceType::AdLog,
            ip: ip.parse::<IpAddr>().expect("ip parse failed"),
            user: user.to_string(),
            timestamp: Utc::now(),
            raw_data: format!("event for {ip}"),
            mac: Some(mac.to_string()),
            confidence_score: 90,
        }
    }

    #[tokio::test]
    async fn test_conflict_dedup_keeps_distinct_user_transitions() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");

        let first = insert_conflict_if_not_recent(
            db.pool(),
            NewConflict {
                conflict_type: "ip_user_change".to_string(),
                severity: "warning".to_string(),
                ip: Some("10.0.0.10".to_string()),
                mac: None,
                user_old: Some("alice".to_string()),
                user_new: Some("bob".to_string()),
                source: "AdLog".to_string(),
                details: None,
            },
        )
        .await
        .expect("insert first conflict failed");
        let second = insert_conflict_if_not_recent(
            db.pool(),
            NewConflict {
                conflict_type: "ip_user_change".to_string(),
                severity: "warning".to_string(),
                ip: Some("10.0.0.10".to_string()),
                mac: None,
                user_old: Some("bob".to_string()),
                user_new: Some("charlie".to_string()),
                source: "AdLog".to_string(),
                details: None,
            },
        )
        .await
        .expect("insert second conflict failed");
        let duplicate = insert_conflict_if_not_recent(
            db.pool(),
            NewConflict {
                conflict_type: "ip_user_change".to_string(),
                severity: "warning".to_string(),
                ip: Some("10.0.0.10".to_string()),
                mac: None,
                user_old: Some("bob".to_string()),
                user_new: Some("charlie".to_string()),
                source: "AdLog".to_string(),
                details: None,
            },
        )
        .await
        .expect("insert duplicate conflict failed");

        assert!(first.is_some(), "first conflict should be inserted");
        assert!(
            second.is_some(),
            "distinct user transition should not be deduplicated"
        );
        assert!(
            duplicate.is_none(),
            "identical conflict should still deduplicate"
        );
    }

    #[tokio::test]
    async fn test_duplicate_mac_detects_inactive_mapping() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        db.upsert_mapping(test_event("10.0.0.1", "alice", "AA:BB:CC:DD:EE:01"), None)
            .await
            .expect("seed mapping failed");
        sqlx::query("UPDATE mappings SET is_active = false WHERE ip = '10.0.0.1'")
            .execute(db.pool())
            .await
            .expect("deactivate mapping failed");

        let conflicts = detect_conflicts(
            db.pool(),
            &test_event("10.0.0.2", "bob", "AA:BB:CC:DD:EE:01"),
        )
        .await
        .expect("conflict detection failed");

        assert!(
            conflicts.iter().any(|c| c.conflict_type == "duplicate_mac"),
            "expected duplicate_mac conflict for inactive prior mapping"
        );
    }

    // ── Phase 1: ip_user_change detection ──

    #[tokio::test]
    async fn test_ip_user_change_fires_when_user_differs() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        db.upsert_mapping(test_event("10.0.0.1", "alice", "AA:BB:CC:DD:EE:01"), None)
            .await
            .expect("seed mapping failed");

        let conflicts = detect_conflicts(
            db.pool(),
            &test_event("10.0.0.1", "bob", "AA:BB:CC:DD:EE:01"),
        )
        .await
        .expect("conflict detection failed");

        let change = conflicts
            .iter()
            .find(|c| c.conflict_type == "ip_user_change");
        assert!(change.is_some(), "expected ip_user_change conflict");
        let c = change.unwrap();
        assert_eq!(c.severity, "warning");
        assert_eq!(c.user_old.as_deref(), Some("alice"));
        assert_eq!(c.user_new.as_deref(), Some("bob"));
        assert_eq!(c.ip.as_deref(), Some("10.0.0.1"));
    }

    #[tokio::test]
    async fn test_ip_user_change_does_not_fire_for_same_user() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        db.upsert_mapping(test_event("10.0.0.1", "alice", "AA:BB:CC:DD:EE:01"), None)
            .await
            .expect("seed mapping failed");

        let conflicts = detect_conflicts(
            db.pool(),
            &test_event("10.0.0.1", "alice", "AA:BB:CC:DD:EE:02"),
        )
        .await
        .expect("conflict detection failed");

        assert!(
            !conflicts.iter().any(|c| c.conflict_type == "ip_user_change"),
            "same user should not trigger ip_user_change"
        );
    }

    #[tokio::test]
    async fn test_ip_user_change_does_not_fire_for_new_ip() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");

        let conflicts = detect_conflicts(
            db.pool(),
            &test_event("10.0.0.99", "alice", "AA:BB:CC:DD:EE:01"),
        )
        .await
        .expect("conflict detection failed");

        assert!(
            conflicts.is_empty(),
            "new IP with no prior mapping should produce no conflicts"
        );
    }

    // ── Phase 1: mac_ip_conflict and duplicate_mac detection ──

    #[tokio::test]
    async fn test_mac_conflict_fires_when_mac_seen_on_different_ip() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        db.upsert_mapping(test_event("10.0.0.1", "alice", "AA:BB:CC:DD:EE:01"), None)
            .await
            .expect("seed mapping failed");

        let conflicts = detect_conflicts(
            db.pool(),
            &test_event("10.0.0.2", "bob", "AA:BB:CC:DD:EE:01"),
        )
        .await
        .expect("conflict detection failed");

        assert!(
            conflicts.iter().any(|c| c.conflict_type == "mac_ip_conflict"),
            "expected mac_ip_conflict when MAC appears on different IP"
        );
        let info = conflicts
            .iter()
            .find(|c| c.conflict_type == "mac_ip_conflict")
            .unwrap();
        assert_eq!(info.severity, "info");

        assert!(
            conflicts.iter().any(|c| c.conflict_type == "duplicate_mac"),
            "expected duplicate_mac alongside mac_ip_conflict"
        );
        let crit = conflicts
            .iter()
            .find(|c| c.conflict_type == "duplicate_mac")
            .unwrap();
        assert_eq!(crit.severity, "critical");
    }

    #[tokio::test]
    async fn test_mac_conflict_does_not_fire_for_same_ip() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        db.upsert_mapping(test_event("10.0.0.1", "alice", "AA:BB:CC:DD:EE:01"), None)
            .await
            .expect("seed mapping failed");

        let conflicts = detect_conflicts(
            db.pool(),
            &test_event("10.0.0.1", "bob", "AA:BB:CC:DD:EE:01"),
        )
        .await
        .expect("conflict detection failed");

        assert!(
            !conflicts.iter().any(|c| c.conflict_type == "mac_ip_conflict"),
            "same IP should not trigger mac_ip_conflict"
        );
        assert!(
            !conflicts.iter().any(|c| c.conflict_type == "duplicate_mac"),
            "same IP should not trigger duplicate_mac"
        );
    }

    #[tokio::test]
    async fn test_no_mac_conflict_without_mac_in_event() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        db.upsert_mapping(test_event("10.0.0.1", "alice", "AA:BB:CC:DD:EE:01"), None)
            .await
            .expect("seed mapping failed");

        let event = IdentityEvent {
            source: SourceType::AdLog,
            ip: "10.0.0.2".parse::<IpAddr>().unwrap(),
            user: "bob".to_string(),
            timestamp: Utc::now(),
            raw_data: "no-mac event".to_string(),
            mac: None,
            confidence_score: 90,
        };

        let conflicts = detect_conflicts(db.pool(), &event)
            .await
            .expect("conflict detection failed");

        assert!(
            !conflicts.iter().any(|c| c.conflict_type == "mac_ip_conflict"
                || c.conflict_type == "duplicate_mac"),
            "events without MAC should not produce MAC-related conflicts"
        );
    }

    // ── Phase 1: multi-IP MAC scenario ──

    #[tokio::test]
    async fn test_duplicate_mac_reports_all_other_ips_in_details() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        db.upsert_mapping(test_event("10.0.0.1", "alice", "AA:BB:CC:DD:EE:01"), None)
            .await
            .expect("seed first mapping");
        db.upsert_mapping(test_event("10.0.0.2", "bob", "AA:BB:CC:DD:EE:01"), None)
            .await
            .expect("seed second mapping");

        let conflicts = detect_conflicts(
            db.pool(),
            &test_event("10.0.0.3", "charlie", "AA:BB:CC:DD:EE:01"),
        )
        .await
        .expect("conflict detection failed");

        let dup = conflicts
            .iter()
            .find(|c| c.conflict_type == "duplicate_mac")
            .expect("expected duplicate_mac conflict");

        let details: serde_json::Value =
            serde_json::from_str(dup.details.as_deref().unwrap()).unwrap();
        let other_ips = details["other_ips"].as_array().unwrap();
        assert!(
            other_ips.len() >= 2,
            "expected at least 2 other IPs in details, got {}",
            other_ips.len()
        );
    }

    // ── Phase 1: deduplication edge cases ──

    #[tokio::test]
    async fn test_dedup_allows_same_type_different_ip() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        db.upsert_mapping(test_event("10.0.0.1", "alice", "AA:BB:CC:DD:EE:01"), None)
            .await
            .unwrap();
        db.upsert_mapping(test_event("10.0.0.2", "alice", "AA:BB:CC:DD:EE:02"), None)
            .await
            .unwrap();

        let first = detect_conflicts(
            db.pool(),
            &test_event("10.0.0.1", "bob", "AA:BB:CC:DD:EE:01"),
        )
        .await
        .unwrap();
        let second = detect_conflicts(
            db.pool(),
            &test_event("10.0.0.2", "bob", "AA:BB:CC:DD:EE:02"),
        )
        .await
        .unwrap();

        assert!(
            first.iter().any(|c| c.conflict_type == "ip_user_change"),
            "first ip_user_change should be inserted"
        );
        assert!(
            second.iter().any(|c| c.conflict_type == "ip_user_change"),
            "different IP should not be deduped against first"
        );
    }

    #[tokio::test]
    async fn test_resolved_conflict_allows_new_insert() {
        let db = init_db("sqlite::memory:").await.expect("init db failed");
        db.upsert_mapping(test_event("10.0.0.1", "alice", "AA:BB:CC:DD:EE:01"), None)
            .await
            .unwrap();

        let first = detect_conflicts(
            db.pool(),
            &test_event("10.0.0.1", "bob", "AA:BB:CC:DD:EE:01"),
        )
        .await
        .unwrap();
        assert!(!first.is_empty(), "first conflict should be inserted");

        // Resolve all conflicts
        sqlx::query("UPDATE conflicts SET resolved_at = datetime('now'), resolved_by = 'admin'")
            .execute(db.pool())
            .await
            .unwrap();

        let second = detect_conflicts(
            db.pool(),
            &test_event("10.0.0.1", "bob", "AA:BB:CC:DD:EE:01"),
        )
        .await
        .unwrap();
        assert!(
            second.iter().any(|c| c.conflict_type == "ip_user_change"),
            "resolved conflict should allow re-detection"
        );
    }
}
