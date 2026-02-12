//! In-process API v2 integration tests for TrueID web.
//!
//! Uses in-memory SQLite and builds the Axum router directly.
//! No external server required — runs in `cargo test -p trueid-web`.

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::Arc;
use tower::ServiceExt;
use trueid_common::db::init_db;
use trueid_common::model::{IdentityEvent, SourceType, UserRole};
use trueid_web::{auth, build_router, rate_limit, AppState};

/// Builds an isolated in-memory test app and seeds deterministic data.
///
/// Parameters: none.
/// Returns: `(Router, Arc<Db>)` ready for in-process requests.
async fn build_test_app() -> (Router, Arc<trueid_common::db::Db>) {
    let db = Arc::new(init_db("sqlite::memory:").await.expect("init_db failed"));

    let user = db
        .create_user("testadmin", "testpassword123", UserRole::Admin)
        .await
        .expect("create_user failed");
    db.set_force_password_change(user.id, false)
        .await
        .expect("set_force_password_change failed");

    seed_test_data(&db).await;

    let state = AppState {
        db: Some(db.clone()),
        engine_url: "http://127.0.0.1:8080".to_string(),
        http_client: reqwest::Client::new(),
        jwt_config: auth::JwtConfig::from_env(true),
        engine_service_token: None,
        login_limiter: Arc::new(rate_limit::RateLimiter::new(1000, 60)),
        api_key_limiter: Arc::new(rate_limit::RateLimiter::new(1000, 60)),
        auth_chain: Some(Arc::new(
            trueid_common::auth_provider::AuthProviderChain::default_chain(db.clone()),
        )),
    };
    (build_router(state), db)
}

/// Seeds mappings/events for API v2 tests.
///
/// Parameters: `db` - initialized in-memory DB handle.
/// Returns: none.
async fn seed_test_data(db: &trueid_common::db::Db) {
    let base = vec![
        ("10.1.2.3", "jkowalski", SourceType::Radius, "AA:BB:CC:DD:EE:01", 95_u8),
        ("10.1.2.4", "asmith", SourceType::AdLog, "AA:BB:CC:DD:EE:02", 85_u8),
        ("10.1.2.5", "mjones", SourceType::DhcpLease, "AA:BB:CC:DD:EE:03", 60_u8),
        ("192.168.1.10", "jkowalski", SourceType::Radius, "AA:BB:CC:DD:EE:04", 90_u8),
        ("192.168.1.11", "bwilson", SourceType::Manual, "AA:BB:CC:DD:EE:05", 100_u8),
    ];
    for (idx, (ip, user, source, mac, confidence)) in base.into_iter().enumerate() {
        let event = IdentityEvent {
            source,
            ip: ip.parse::<IpAddr>().expect("ip parse failed"),
            user: user.to_string(),
            timestamp: Utc::now() - Duration::minutes(30 - idx as i64),
            raw_data: format!("test event for {ip}"),
            mac: Some(mac.to_string()),
            confidence_score: confidence,
        };
        db.upsert_mapping(event, Some("TestVendor"))
            .await
            .expect("upsert_mapping failed");
    }

    // Extra events for richer history/user-change coverage.
    for i in 0..12 {
        let event = IdentityEvent {
            source: if i % 2 == 0 {
                SourceType::AdLog
            } else {
                SourceType::Radius
            },
            ip: "10.1.2.3".parse::<IpAddr>().expect("ip parse failed"),
            user: if i % 3 == 0 {
                "asmith".to_string()
            } else {
                "jkowalski".to_string()
            },
            timestamp: Utc::now() - Duration::minutes(120 - i as i64),
            raw_data: format!("history event #{i}"),
            mac: Some("AA:BB:CC:DD:EE:01".to_string()),
            confidence_score: 88,
        };
        db.upsert_mapping(event, Some("TestVendor"))
            .await
            .expect("history upsert_mapping failed");
    }
}

/// Logs in and returns combined auth cookie header.
///
/// Parameters: `app` - test router, `user` - username, `pass` - password.
/// Returns: cookie header string with JWT cookies.
async fn login_and_get_cookie(app: &Router, user: &str, pass: &str) -> String {
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&json!({
                "username": user,
                "password": pass
            }))
            .expect("serialize login body failed"),
        ))
        .expect("build login request failed");

    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("login request execution failed");
    assert_eq!(resp.status(), StatusCode::OK);

    let mut parts = Vec::new();
    for value in &resp.headers().get_all("set-cookie") {
        let raw = value.to_str().unwrap_or("");
        if raw.contains("trueid_access_token=")
            || raw.contains("trueid_refresh_token=")
            || raw.contains("trueid_csrf_token=")
        {
            let first = raw.split(';').next().unwrap_or("");
            if !first.is_empty() {
                parts.push(first.to_string());
            }
        }
    }
    assert!(!parts.is_empty(), "No auth cookies in login response");
    parts.join("; ")
}

/// Executes authenticated GET and parses JSON response body.
///
/// Parameters: `app` - test router, `cookie` - cookie header string, `uri` - request path.
/// Returns: `(status, json_body)`.
async fn auth_get(app: &Router, cookie: &str, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("cookie", cookie)
        .body(Body::empty())
        .expect("build auth_get request failed");

    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("auth_get execution failed");
    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect body failed")
        .to_bytes();
    let json_body: Value = serde_json::from_slice(&body).unwrap_or(json!(null));
    (status, json_body)
}

/// Executes authenticated GET and returns raw response.
///
/// Parameters: `app` - test router, `cookie` - cookie header string, `uri` - request path.
/// Returns: `(status, headers, body_bytes)`.
async fn auth_get_raw(app: &Router, cookie: &str, uri: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("cookie", cookie)
        .body(Body::empty())
        .expect("build auth_get_raw request failed");

    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("auth_get_raw execution failed");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect raw body failed")
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

#[tokio::test]
async fn test_search_requires_auth() {
    let (app, _) = build_test_app().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/v2/search")
        .body(Body::empty())
        .expect("build request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("execute request failed");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_search_all_scopes() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/search").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["mappings"].is_object());
    assert!(body["events"].is_object());
    assert!(body["mappings"]["total"].as_i64().unwrap_or(0) > 0);
    assert!(body["events"]["total"].as_i64().unwrap_or(0) > 0);
}

#[tokio::test]
async fn test_search_scope_mappings_only() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/search?scope=mappings").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["mappings"].is_object());
    assert!(body["events"].is_null());
}

#[tokio::test]
async fn test_search_scope_events_only() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/search?scope=events").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["events"].is_object());
    assert!(body["mappings"].is_null());
}

#[tokio::test]
async fn test_search_free_text() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/search?q=jkowalski").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["mappings"]["total"].as_i64().unwrap_or(0) >= 1);
    assert!(body["events"]["total"].as_i64().unwrap_or(0) >= 1);
}

#[tokio::test]
async fn test_search_exact_ip() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/search?scope=mappings&ip=10.1.2.4").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["mappings"]["total"].as_i64().unwrap_or(-1), 1);
}

#[tokio::test]
async fn test_search_exact_user() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(
        &app,
        &cookie,
        "/api/v2/search?scope=mappings&user=jkowalski",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["mappings"]["total"].as_i64().unwrap_or(-1), 2);
}

#[tokio::test]
async fn test_search_by_source() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(
        &app,
        &cookie,
        "/api/v2/search?scope=mappings&source=Radius",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["mappings"]["total"].as_i64().unwrap_or(-1), 2);
}

#[tokio::test]
async fn test_search_pagination() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (_, p1) = auth_get(
        &app,
        &cookie,
        "/api/v2/search?scope=mappings&limit=2&page=1&sort=ip&order=asc",
    )
    .await;
    let (_, p2) = auth_get(
        &app,
        &cookie,
        "/api/v2/search?scope=mappings&limit=2&page=2&sort=ip&order=asc",
    )
    .await;
    let (_, p3) = auth_get(
        &app,
        &cookie,
        "/api/v2/search?scope=mappings&limit=2&page=3&sort=ip&order=asc",
    )
    .await;

    assert_eq!(p1["mappings"]["total"].as_i64().unwrap_or(-1), 5);
    assert_eq!(p1["mappings"]["data"].as_array().map(|a| a.len()).unwrap_or(0), 2);
    assert_eq!(p2["mappings"]["data"].as_array().map(|a| a.len()).unwrap_or(0), 2);
    assert_eq!(p3["mappings"]["data"].as_array().map(|a| a.len()).unwrap_or(0), 1);
}

#[tokio::test]
async fn test_search_pagination_edge_cases() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (_, page_zero) = auth_get(
        &app,
        &cookie,
        "/api/v2/search?scope=mappings&page=0&limit=50",
    )
    .await;
    assert_eq!(page_zero["page"].as_u64().unwrap_or(0), 1);

    let (_, limit_zero) = auth_get(
        &app,
        &cookie,
        "/api/v2/search?scope=mappings&page=1&limit=0",
    )
    .await;
    assert_eq!(limit_zero["limit"].as_u64().unwrap_or(0), 1);

    let (_, limit_high) = auth_get(
        &app,
        &cookie,
        "/api/v2/search?scope=mappings&page=1&limit=999",
    )
    .await;
    assert_eq!(limit_high["limit"].as_u64().unwrap_or(0), 200);
}

#[tokio::test]
async fn test_search_invalid_scope() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/search?scope=invalid").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");
}

#[tokio::test]
async fn test_search_invalid_datetime() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_get(&app, &cookie, "/api/v2/search?from=not-a-date").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_search_has_query_time() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/search").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["query_time_ms"].as_u64().is_some());
}

#[tokio::test]
async fn test_export_mappings_json() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, headers, body) = auth_get_raw(&app, &cookie, "/api/v2/export/mappings?format=json").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .contains("application/json")
    );
    let dispo = headers
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(dispo.contains("trueid-mappings-") && dispo.contains(".json"));
    let arr: Value = serde_json::from_slice(&body).expect("json array parse failed");
    assert_eq!(arr.as_array().map(|a| a.len()).unwrap_or(0), 5);
}

#[tokio::test]
async fn test_export_mappings_csv() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, headers, body) = auth_get_raw(&app, &cookie, "/api/v2/export/mappings?format=csv").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .contains("text/csv")
    );
    let dispo = headers
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(dispo.contains(".csv"));
    let text = String::from_utf8(body).expect("csv utf8 decode failed");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.first().copied().unwrap_or(""),
        "ip,user,mac,source,last_seen,confidence,is_active,vendor"
    );
    assert_eq!(lines.len(), 6);
}

#[tokio::test]
async fn test_export_mappings_with_filter() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _, body) =
        auth_get_raw(&app, &cookie, "/api/v2/export/mappings?format=json&source=Radius").await;
    assert_eq!(status, StatusCode::OK);
    let arr: Value = serde_json::from_slice(&body).expect("json parse failed");
    assert_eq!(arr.as_array().map(|a| a.len()).unwrap_or(0), 2);
}

#[tokio::test]
async fn test_export_events_json() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, headers, body) = auth_get_raw(&app, &cookie, "/api/v2/export/events?format=json").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .contains("application/json")
    );
    let arr: Value = serde_json::from_slice(&body).expect("json parse failed");
    assert!(arr.as_array().map(|a| a.len()).unwrap_or(0) >= 5);
}

#[tokio::test]
async fn test_export_events_csv() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _, body) = auth_get_raw(&app, &cookie, "/api/v2/export/events?format=csv").await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(body).expect("csv utf8 decode failed");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.first().copied().unwrap_or(""),
        "id,ip,user,source,timestamp,raw_data"
    );
}

#[tokio::test]
async fn test_export_invalid_format() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/export/mappings?format=xml").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");
}

#[tokio::test]
async fn test_export_requires_auth() {
    let (app, _) = build_test_app().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/v2/export/mappings?format=json")
        .body(Body::empty())
        .expect("build request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("execute request failed");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_v1_mappings_still_works() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v1/mappings").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].is_array());
    assert!(body["total"].is_i64());
    assert!(body["page"].is_i64());
    assert!(body["per_page"].is_i64());
}

#[tokio::test]
async fn test_v1_events_still_works() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v1/events").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_array());
}

#[tokio::test]
async fn test_lookup_still_works() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/lookup/10.1.2.3").await;
    assert_eq!(status, StatusCode::OK, "lookup body: {body}");
    assert!(body["mapping"].is_object() || body["mapping"].is_null());
    assert!(body["recent_events"].is_array());
}

#[tokio::test]
async fn test_health() {
    let (app, _) = build_test_app().await;
    let req = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .expect("build health request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("execute health request failed");
    assert_eq!(resp.status(), StatusCode::OK);
}
