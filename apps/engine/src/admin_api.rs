//! Engine Admin API — internal HTTP handlers on :8080.
//!
//! Exposes status, configuration, and manual mapping endpoints.
//! Only accessible from localhost (127.0.0.1) or within Docker network.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use trueid_common::db::Db;
use trueid_common::model::{AdapterStatus, IdentityEvent, SourceType};

/// Shared state for the engine admin API.
#[derive(Clone)]
pub struct EngineAdminState {
    pub db: Arc<Db>,
    pub vendors: Arc<HashMap<String, String>>,
    pub adapter_stats: Arc<RwLock<Vec<AdapterStatus>>>,
    /// Runtime config values cached in env at startup.
    pub runtime_env: Arc<RuntimeEnv>,
}

/// Snapshot of engine environment at startup (read-only diagnostics).
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeEnv {
    pub database_url: String,
    pub radius_bind: String,
    pub radius_secret_set: bool,
    pub ad_syslog_bind: String,
    pub dhcp_syslog_bind: String,
    pub ad_tls_bind: String,
    pub dhcp_tls_bind: String,
    pub tls_enabled: bool,
    pub tls_ca_exists: bool,
    pub tls_cert_exists: bool,
    pub tls_key_exists: bool,
    pub oui_csv_path: String,
    pub admin_http_bind: String,
}

/// Builds the admin API router with all E1-E12 handlers.
pub fn admin_router(state: EngineAdminState) -> Router {
    Router::new()
        .route("/engine/status/stats", get(stats))
        .route("/engine/status/adapters", get(adapters_status))
        .route("/engine/status/agents", get(agents_list))
        .route("/engine/status/runtime-config", get(runtime_config))
        .route("/engine/config/ttl", get(get_ttl).put(set_ttl))
        .route("/engine/config/source-priority", get(get_source_priority).put(set_source_priority))
        .route("/engine/config/sycope", get(get_sycope_config).put(set_sycope_config))
        .route("/engine/mappings", post(create_manual_mapping))
        .route("/engine/mappings/{ip}", delete(delete_mapping))
        .with_state(state)
}

// ── E1: Stats ───────────────────────────────────────────────

#[derive(Serialize)]
struct StatsResponse {
    total_mappings: i64,
    active_mappings: i64,
    inactive_mappings: i64,
    total_events: i64,
    events_by_source: HashMap<String, i64>,
    last_event_at: Option<String>,
    oui_vendors_loaded: usize,
}

async fn stats(State(s): State<EngineAdminState>) -> Result<impl IntoResponse, StatusCode> {
    let total = s.db.count_mappings(None).await.unwrap_or(0);
    let active = s.db.count_mappings(Some(true)).await.unwrap_or(0);
    let events = s.db.count_events().await.unwrap_or(0);
    let by_source = s.db.count_events_by_source().await.unwrap_or_default();
    let last = s.db.get_last_event_timestamp().await.ok().flatten();
    Ok(Json(StatsResponse {
        total_mappings: total,
        active_mappings: active,
        inactive_mappings: total - active,
        total_events: events,
        events_by_source: by_source,
        last_event_at: last.map(|t| t.to_rfc3339()),
        oui_vendors_loaded: s.vendors.len(),
    }))
}

// ── E2: Adapter Status ──────────────────────────────────────

async fn adapters_status(State(s): State<EngineAdminState>) -> impl IntoResponse {
    let adapters = s.adapter_stats.read().await.clone();
    Json(serde_json::json!({ "adapters": adapters }))
}

// ── E3: Agents ──────────────────────────────────────────────

async fn agents_list(State(s): State<EngineAdminState>) -> Result<impl IntoResponse, StatusCode> {
    match s.db.get_agents().await {
        Ok(agents) => Ok(Json(serde_json::json!({ "agents": agents }))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// ── E4: Runtime Config ──────────────────────────────────────

async fn runtime_config(State(s): State<EngineAdminState>) -> impl IntoResponse {
    let env = &s.runtime_env;
    Json(serde_json::json!({
        "database_url": env.database_url,
        "listeners": {
            "radius_bind": env.radius_bind,
            "radius_secret": "***",
            "ad_syslog_bind": env.ad_syslog_bind,
            "dhcp_syslog_bind": env.dhcp_syslog_bind,
            "ad_tls_bind": env.ad_tls_bind,
            "dhcp_tls_bind": env.dhcp_tls_bind,
        },
        "tls": {
            "enabled": env.tls_enabled,
            "ca_cert_exists": env.tls_ca_exists,
            "server_cert_exists": env.tls_cert_exists,
            "server_key_exists": env.tls_key_exists,
        },
        "enrichment": {
            "oui_csv_path": env.oui_csv_path,
            "oui_vendors_loaded": s.vendors.len(),
        },
        "admin_http_bind": env.admin_http_bind,
    }))
}

// ── E5/E6: TTL Config ───────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct TtlConfig {
    stale_ttl_minutes: i64,
    janitor_interval_secs: i64,
}

async fn get_ttl(State(s): State<EngineAdminState>) -> impl IntoResponse {
    let ttl = s.db.get_config_i64("stale_ttl_minutes", 5).await;
    let interval = s.db.get_config_i64("janitor_interval_secs", 60).await;
    Json(TtlConfig { stale_ttl_minutes: ttl, janitor_interval_secs: interval })
}

async fn set_ttl(
    State(s): State<EngineAdminState>,
    Json(body): Json<TtlConfig>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if !(1..=1440).contains(&body.stale_ttl_minutes) {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "stale_ttl_minutes must be 1..1440"}))));
    }
    if !(10..=3600).contains(&body.janitor_interval_secs) {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "janitor_interval_secs must be 10..3600"}))));
    }
    let _ = s.db.set_config("stale_ttl_minutes", &body.stale_ttl_minutes.to_string()).await;
    let _ = s.db.set_config("janitor_interval_secs", &body.janitor_interval_secs.to_string()).await;
    info!(ttl = body.stale_ttl_minutes, interval = body.janitor_interval_secs, "TTL config updated");
    Ok(Json(body))
}

// ── E7/E8: Source Priority ──────────────────────────────────

#[derive(Serialize, Deserialize)]
struct SourcePriorityEntry {
    name: String,
    priority: i64,
    default_confidence: i64,
}

#[derive(Serialize, Deserialize)]
struct SourcePriorityResponse {
    sources: Vec<SourcePriorityEntry>,
}

async fn get_source_priority(State(s): State<EngineAdminState>) -> impl IntoResponse {
    let sources = vec![
        SourcePriorityEntry {
            name: "Radius".into(),
            priority: s.db.get_config_i64("source_priority_radius", 3).await,
            default_confidence: s.db.get_config_i64("default_confidence_radius", 100).await,
        },
        SourcePriorityEntry {
            name: "AdLog".into(),
            priority: s.db.get_config_i64("source_priority_adlog", 2).await,
            default_confidence: s.db.get_config_i64("default_confidence_adlog", 90).await,
        },
        SourcePriorityEntry {
            name: "DhcpLease".into(),
            priority: s.db.get_config_i64("source_priority_dhcplease", 1).await,
            default_confidence: s.db.get_config_i64("default_confidence_dhcplease", 60).await,
        },
        SourcePriorityEntry {
            name: "Manual".into(),
            priority: s.db.get_config_i64("source_priority_manual", 0).await,
            default_confidence: s.db.get_config_i64("default_confidence_manual", 100).await,
        },
    ];
    Json(SourcePriorityResponse { sources })
}

async fn set_source_priority(
    State(s): State<EngineAdminState>,
    Json(body): Json<SourcePriorityResponse>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if body.sources.len() != 4 {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "exactly 4 sources required"}))));
    }
    for src in &body.sources {
        if !(0..=10).contains(&src.priority) || !(0..=100).contains(&src.default_confidence) {
            return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("invalid values for {}", src.name)}))));
        }
        let key_p = format!("source_priority_{}", src.name.to_lowercase());
        let key_c = format!("default_confidence_{}", src.name.to_lowercase());
        let _ = s.db.set_config(&key_p, &src.priority.to_string()).await;
        let _ = s.db.set_config(&key_c, &src.default_confidence.to_string()).await;
    }
    info!("Source priority config updated");
    Ok(Json(body))
}

// ── E9: Manual Mapping ──────────────────────────────────────

#[derive(Deserialize)]
struct CreateMappingRequest {
    ip: String,
    user: String,
    mac: Option<String>,
    confidence_score: Option<u8>,
}

async fn create_manual_mapping(
    State(s): State<EngineAdminState>,
    Json(body): Json<CreateMappingRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let ip: IpAddr = body.ip.parse().map_err(|_|
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid IP address"})))
    )?;
    if body.user.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "user must not be empty"}))));
    }
    let confidence = body.confidence_score.unwrap_or(100);
    let vendor = body.mac.as_deref().and_then(|m| crate::resolve_vendor(m, &s.vendors));
    let event = IdentityEvent {
        source: SourceType::Manual,
        ip,
        user: body.user.clone(),
        timestamp: Utc::now(),
        raw_data: format!("Manual mapping via admin API: ip={} user={}", ip, body.user),
        mac: body.mac.clone(),
        confidence_score: confidence,
    };
    s.db.upsert_mapping(event, vendor.as_deref()).await.map_err(|_|
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "database write failed"})))
    )?;
    info!(ip = %ip, user = %body.user, "Manual mapping created");
    let mapping = s.db.get_mapping(&ip.to_string()).await.ok().flatten();
    Ok((StatusCode::CREATED, Json(mapping)))
}

// ── E10: Delete Mapping ─────────────────────────────────────

async fn delete_mapping(
    State(s): State<EngineAdminState>,
    Path(ip): Path<String>,
) -> Result<StatusCode, StatusCode> {
    match s.db.delete_mapping(&ip).await {
        Ok(true) => {
            info!(ip = %ip, "Mapping deleted");
            Ok(StatusCode::NO_CONTENT)
        }
        Ok(false) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// ── E11/E12: Sycope Config ─────────────────────────────────

async fn get_sycope_config(State(s): State<EngineAdminState>) -> impl IntoResponse {
    let db = &s.db;
    let enabled = db.get_config("sycope_enabled").await.ok().flatten().unwrap_or_default() == "true";
    let host = db.get_config("sycope_host").await.ok().flatten().unwrap_or_default();
    let login = db.get_config("sycope_login").await.ok().flatten().unwrap_or_default();
    let pass_set = db.get_config("sycope_pass").await.ok().flatten().map(|p| !p.is_empty()).unwrap_or(false);
    let lookup = db.get_config("sycope_lookup_name").await.ok().flatten().unwrap_or_else(|| "TrueID_Enrichment".into());
    let interval = db.get_config_i64("sycope_sync_interval_seconds", 300).await;
    let evt_idx = db.get_config("sycope_enable_event_index").await.ok().flatten().unwrap_or_default() == "true";
    let idx_name = db.get_config("sycope_index_name").await.ok().flatten().unwrap_or_else(|| "trueid_events".into());
    let sync = db.get_sync_status("sycope").await.ok().flatten();

    Json(serde_json::json!({
        "enabled": enabled,
        "sycope_host": host,
        "sycope_login": login,
        "sycope_pass_set": pass_set,
        "lookup_name": lookup,
        "sync_interval_seconds": interval,
        "enable_event_index": evt_idx,
        "index_name": idx_name,
        "last_sync": sync,
    }))
}

#[derive(Deserialize)]
struct SycopeConfigRequest {
    enabled: Option<bool>,
    sycope_host: Option<String>,
    sycope_login: Option<String>,
    sycope_pass: Option<String>,
    lookup_name: Option<String>,
    sync_interval_seconds: Option<i64>,
    enable_event_index: Option<bool>,
    index_name: Option<String>,
}

async fn set_sycope_config(
    State(s): State<EngineAdminState>,
    Json(body): Json<SycopeConfigRequest>,
) -> impl IntoResponse {
    let db = &s.db;
    if let Some(v) = body.enabled { let _ = db.set_config("sycope_enabled", &v.to_string()).await; }
    if let Some(ref v) = body.sycope_host { let _ = db.set_config("sycope_host", v).await; }
    if let Some(ref v) = body.sycope_login { let _ = db.set_config("sycope_login", v).await; }
    if let Some(ref v) = body.sycope_pass { if !v.is_empty() { let _ = db.set_config("sycope_pass", v).await; } }
    if let Some(ref v) = body.lookup_name { let _ = db.set_config("sycope_lookup_name", v).await; }
    if let Some(v) = body.sync_interval_seconds { let _ = db.set_config("sycope_sync_interval_seconds", &v.to_string()).await; }
    if let Some(v) = body.enable_event_index { let _ = db.set_config("sycope_enable_event_index", &v.to_string()).await; }
    if let Some(ref v) = body.index_name { let _ = db.set_config("sycope_index_name", v).await; }
    info!("Sycope config updated");
    get_sycope_config(State(s)).await
}
