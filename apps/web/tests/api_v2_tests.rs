//! In-process API v2 integration tests for TrueID web.
//!
//! Uses in-memory SQLite and builds the Axum router directly.
//! No external server required — runs in `cargo test -p trueid-web`.

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::get;
use axum::Router;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::{Arc, Once};
use tower::ServiceExt;
use trueid_common::db::init_db;
use trueid_common::model::{IdentityEvent, SourceType, UserRole};
use trueid_web::{auth, build_router, rate_limit, AppState};

/// Builds an isolated in-memory test app and seeds deterministic data.
///
/// Parameters: none.
/// Returns: `(Router, Arc<Db>)` ready for in-process requests.
async fn build_test_app() -> (Router, Arc<trueid_common::db::Db>) {
    build_test_app_with_engine_url("http://127.0.0.1:8080".to_string()).await
}

/// Builds an isolated in-memory test app with custom engine URL.
///
/// Parameters: `engine_url` - upstream engine base URL for proxy routes.
/// Returns: `(Router, Arc<Db>)` ready for in-process requests.
async fn build_test_app_with_engine_url(
    engine_url: String,
) -> (Router, Arc<trueid_common::db::Db>) {
    ensure_test_encryption_key();
    let db = Arc::new(init_db("sqlite::memory:").await.expect("init_db failed"));

    let user = db
        .create_user("testadmin", "testpassword123", UserRole::Admin)
        .await
        .expect("create_user failed");
    db.set_force_password_change(user.id, false)
        .await
        .expect("set_force_password_change failed");

    seed_test_data(&db).await;
    let runtime_config = trueid_common::app_config::AppConfig::load(db.as_ref()).await;

    let state = AppState {
        db: Some(db.clone()),
        config: Arc::new(tokio::sync::RwLock::new(runtime_config)),
        engine_url,
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

/// Spawns a minimal mock engine SSE server for proxy tests.
///
/// Parameters: none.
/// Returns: `(base_url, task_handle)` for the spawned mock server.
async fn spawn_mock_engine_sse() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/engine/events/stream",
        get(|| async {
            (
                StatusCode::OK,
                [("content-type", "text/event-stream")],
                "event: heartbeat\ndata: {\"type\":\"heartbeat\"}\n\n",
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock engine failed");
    let addr = listener
        .local_addr()
        .expect("read mock engine local addr failed");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{}", addr), handle)
}

/// Spawns a minimal mock engine retention endpoint for proxy tests.
///
/// Parameters: none.
/// Returns: `(base_url, task_handle)` for the spawned mock server.
async fn spawn_mock_engine_retention_run() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/engine/retention/run",
        get(|| async move {
            (
                StatusCode::OK,
                [("content-type", "application/json")],
                serde_json::to_string(&json!({
                    "results": [
                        {"table_name":"events","deleted":0,"status":"ok"}
                    ]
                }))
                .expect("serialize mock retention response failed"),
            )
        })
        .post(|| async move {
            (
                StatusCode::OK,
                [("content-type", "application/json")],
                serde_json::to_string(&json!({
                    "results": [
                        {"table_name":"events","deleted":0,"status":"ok"}
                    ]
                }))
                .expect("serialize mock retention response failed"),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock engine failed");
    let addr = listener
        .local_addr()
        .expect("read mock engine local addr failed");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{}", addr), handle)
}

/// Seeds mappings/events for API v2 tests.
///
/// Parameters: `db` - initialized in-memory DB handle.
/// Returns: none.
async fn seed_test_data(db: &trueid_common::db::Db) {
    let base = vec![
        (
            "10.1.2.3",
            "jkowalski",
            SourceType::Radius,
            "AA:BB:CC:DD:EE:01",
            95_u8,
        ),
        (
            "10.1.2.4",
            "asmith",
            SourceType::AdLog,
            "AA:BB:CC:DD:EE:02",
            85_u8,
        ),
        (
            "10.1.2.5",
            "mjones",
            SourceType::DhcpLease,
            "AA:BB:CC:DD:EE:03",
            60_u8,
        ),
        (
            "192.168.1.10",
            "jkowalski",
            SourceType::Radius,
            "AA:BB:CC:DD:EE:04",
            90_u8,
        ),
        (
            "192.168.1.11",
            "bwilson",
            SourceType::Manual,
            "AA:BB:CC:DD:EE:05",
            100_u8,
        ),
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

    // Phase 2 seed: subnets.
    sqlx::query(
        "INSERT INTO subnets (id, cidr, name, vlan_id, location) VALUES (1, '10.1.2.0/24', 'Office LAN', 100, 'Floor 3')",
    )
    .execute(db.pool())
    .await
    .expect("insert subnet 1 failed");
    sqlx::query(
        "INSERT INTO subnets (id, cidr, name, vlan_id) VALUES (2, '192.168.1.0/24', 'Server VLAN', 200)",
    )
    .execute(db.pool())
    .await
    .expect("insert subnet 2 failed");

    sqlx::query("UPDATE mappings SET subnet_id = 1 WHERE ip LIKE '10.1.2.%'")
        .execute(db.pool())
        .await
        .expect("tag mappings subnet 1 failed");
    sqlx::query("UPDATE mappings SET subnet_id = 2 WHERE ip LIKE '192.168.1.%'")
        .execute(db.pool())
        .await
        .expect("tag mappings subnet 2 failed");

    // Phase 2 seed: dns cache.
    sqlx::query(
        "INSERT INTO dns_cache (ip, hostname, resolved_at, expires_at) VALUES ('10.1.2.3', 'jkowalski-pc.corp.local', datetime('now'), datetime('now', '+1 hour'))",
    )
    .execute(db.pool())
    .await
    .expect("insert dns 10.1.2.3 failed");
    sqlx::query(
        "INSERT INTO dns_cache (ip, hostname, previous_hostname, resolved_at, expires_at, resolve_count) VALUES ('10.1.2.4', 'asmith-laptop.corp.local', 'old-host.corp.local', datetime('now'), datetime('now', '+1 hour'), 3)",
    )
    .execute(db.pool())
    .await
    .expect("insert dns 10.1.2.4 failed");

    // Phase 2 seed: DHCP observations + mapping device type.
    sqlx::query(
        "INSERT INTO dhcp_observations (mac, fingerprint, device_type, hostname, ip, match_source) VALUES ('AA:BB:CC:DD:EE:01', '1,3,6,15,31,33,43,44,46,47,119,121,249,252', 'Windows 10/11', 'jkowalski-pc', '10.1.2.3', 'exact')",
    )
    .execute(db.pool())
    .await
    .expect("insert dhcp observation failed");
    sqlx::query("UPDATE mappings SET device_type = 'Windows 10/11' WHERE ip = '10.1.2.3'")
        .execute(db.pool())
        .await
        .expect("update mapping device_type failed");

    // Multi-user session seed (terminal server style).
    sqlx::query(
        "INSERT OR IGNORE INTO ip_sessions (ip, user, source, mac, session_start, last_seen, is_active)
         VALUES
         ('10.1.2.3', 'jkowalski', 'Radius', 'AA:BB:CC:DD:EE:01', datetime('now'), datetime('now'), 1),
         ('10.1.2.3', 'asmith', 'AdLog', 'AA:BB:CC:DD:EE:01', datetime('now'), datetime('now'), 1),
         ('10.1.2.3', 'tsguest', 'Manual', 'AA:BB:CC:DD:EE:01', datetime('now'), datetime('now'), 1)",
    )
    .execute(db.pool())
    .await
    .expect("insert ip_sessions seed failed");
    sqlx::query("UPDATE mappings SET multi_user = 1 WHERE ip = '10.1.2.3'")
        .execute(db.pool())
        .await
        .expect("update mapping multi_user failed");
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

/// Extracts CSRF token value from login cookie string.
///
/// Parameters: `cookie` - combined Cookie header value.
/// Returns: CSRF token string or empty string when missing.
fn csrf_from_cookie(cookie: &str) -> String {
    cookie
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("trueid_csrf_token=").map(str::to_string))
        .unwrap_or_default()
}

/// Executes authenticated POST with JSON body and parses JSON response.
///
/// Parameters: `app` - test router, `cookie` - cookie header string, `uri` - path, `body` - JSON payload.
/// Returns: `(status, json_body)`.
async fn auth_post(app: &Router, cookie: &str, uri: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("cookie", cookie)
        .header("x-csrf-token", csrf_from_cookie(cookie))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(body).expect("serialize post body failed"),
        ))
        .expect("build auth_post request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("auth_post execution failed");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect post body failed")
        .to_bytes();
    let json_body: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json_body)
}

/// Executes authenticated PUT with JSON body and parses JSON response.
///
/// Parameters: `app` - test router, `cookie` - cookie header string, `uri` - path, `body` - JSON payload.
/// Returns: `(status, json_body)`.
async fn auth_put(app: &Router, cookie: &str, uri: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("cookie", cookie)
        .header("x-csrf-token", csrf_from_cookie(cookie))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(body).expect("serialize put body failed"),
        ))
        .expect("build auth_put request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("auth_put execution failed");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect put body failed")
        .to_bytes();
    let json_body: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json_body)
}

/// Executes authenticated DELETE and parses JSON response.
///
/// Parameters: `app` - test router, `cookie` - cookie header string, `uri` - path.
/// Returns: `(status, json_body)`.
async fn auth_delete(app: &Router, cookie: &str, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("cookie", cookie)
        .header("x-csrf-token", csrf_from_cookie(cookie))
        .body(Body::empty())
        .expect("build auth_delete request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("auth_delete execution failed");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect delete body failed")
        .to_bytes();
    let json_body: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json_body)
}

/// Ensures CONFIG_ENCRYPTION_KEY is set for switch CRUD tests.
///
/// Parameters: none.
/// Returns: none.
fn ensure_test_encryption_key() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::env::set_var(
            "CONFIG_ENCRYPTION_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
    });
}

/// Seeds additional events for analytics top/source tests.
///
/// Parameters: `db` - initialized in-memory DB handle.
/// Returns: none.
async fn seed_analytics_events(db: &trueid_common::db::Db) {
    for idx in 0..3 {
        let event = IdentityEvent {
            source: SourceType::Radius,
            ip: "10.9.0.10".parse::<IpAddr>().expect("ip parse failed"),
            user: "alice".to_string(),
            timestamp: Utc::now() - Duration::minutes(idx),
            raw_data: format!("alice event #{idx}"),
            mac: Some("AA:BB:CC:DD:FA:01".to_string()),
            confidence_score: 90,
        };
        db.upsert_mapping(event, Some("TestVendor"))
            .await
            .expect("alice seed failed");
    }
    for idx in 0..2 {
        let event = IdentityEvent {
            source: SourceType::AdLog,
            ip: "10.9.0.20".parse::<IpAddr>().expect("ip parse failed"),
            user: "bob".to_string(),
            timestamp: Utc::now() - Duration::minutes(idx),
            raw_data: format!("bob event #{idx}"),
            mac: Some("AA:BB:CC:DD:FA:02".to_string()),
            confidence_score: 85,
        };
        db.upsert_mapping(event, Some("TestVendor"))
            .await
            .expect("bob seed failed");
    }
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
    let (status, body) =
        auth_get(&app, &cookie, "/api/v2/search?scope=mappings&source=Radius").await;
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
    assert_eq!(
        p1["mappings"]["data"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        2
    );
    assert_eq!(
        p2["mappings"]["data"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        2
    );
    assert_eq!(
        p3["mappings"]["data"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        1
    );
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
    let (status, headers, body) =
        auth_get_raw(&app, &cookie, "/api/v2/export/mappings?format=json").await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .contains("application/json"));
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
    let (status, headers, body) =
        auth_get_raw(&app, &cookie, "/api/v2/export/mappings?format=csv").await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .contains("text/csv"));
    let dispo = headers
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(dispo.contains(".csv"));
    let text = String::from_utf8(body).expect("csv utf8 decode failed");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.first().copied().unwrap_or(""),
        "ip,user,mac,source,last_seen,confidence,is_active,vendor,subnet_id,subnet_name,hostname,device_type,multi_user,current_users,groups"
    );
    assert_eq!(lines.len(), 6);
}

#[tokio::test]
async fn test_export_mappings_with_filter() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _, body) = auth_get_raw(
        &app,
        &cookie,
        "/api/v2/export/mappings?format=json&source=Radius",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr: Value = serde_json::from_slice(&body).expect("json parse failed");
    assert_eq!(arr.as_array().map(|a| a.len()).unwrap_or(0), 2);
}

#[tokio::test]
async fn test_export_events_json() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, headers, body) =
        auth_get_raw(&app, &cookie, "/api/v2/export/events?format=json").await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .contains("application/json"));
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
async fn test_v1_mappings_has_enrichment_fields() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v1/mappings?limit=50").await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["data"].as_array().cloned().unwrap_or_default();
    let target = rows
        .iter()
        .find(|r| r["ip"] == "10.1.2.3")
        .expect("expected mapping 10.1.2.3");
    assert_eq!(target["subnet_name"], "Office LAN");
    assert_eq!(target["hostname"], "jkowalski-pc.corp.local");
    assert_eq!(target["device_type"], "Windows 10/11");
}

#[tokio::test]
async fn test_export_csv_has_enrichment_columns() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _, body) = auth_get_raw(&app, &cookie, "/api/v2/export/mappings?format=csv").await;
    assert_eq!(status, StatusCode::OK);
    let csv = String::from_utf8(body).expect("csv decode failed");
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(
        lines.first().copied().unwrap_or(""),
        "ip,user,mac,source,last_seen,confidence,is_active,vendor,subnet_id,subnet_name,hostname,device_type,multi_user,current_users,groups"
    );
    let row = lines
        .iter()
        .find(|l| l.starts_with("10.1.2.3,"))
        .expect("missing 10.1.2.3 row");
    assert!(row.contains("Office LAN"));
    assert!(row.contains("jkowalski-pc.corp.local"));
    assert!(row.contains("Windows 10/11"));
}

#[tokio::test]
async fn test_search_returns_enrichment_fields() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/search?q=10.1.2.3&scope=mappings").await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["mappings"]["data"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let target = rows
        .iter()
        .find(|r| r["ip"] == "10.1.2.3")
        .expect("expected mapping 10.1.2.3");
    assert_eq!(target["subnet_name"], "Office LAN");
    assert_eq!(target["hostname"], "jkowalski-pc.corp.local");
    assert_eq!(target["device_type"], "Windows 10/11");
}

#[tokio::test]
async fn test_multi_user_session_tracking() {
    let (app, db) = build_test_app().await;
    let ip = "10.9.9.9";
    for user in ["alice", "bob", "carol"] {
        let event = IdentityEvent {
            source: SourceType::Radius,
            ip: ip.parse::<IpAddr>().expect("ip parse failed"),
            user: user.to_string(),
            timestamp: Utc::now(),
            raw_data: format!("multi-user event for {user}"),
            mac: Some("AA:BB:CC:DD:EE:99".to_string()),
            confidence_score: 90,
        };
        db.upsert_mapping(event, Some("TestVendor"))
            .await
            .expect("multi-user upsert failed");
    }

    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v1/mappings?search=10.9.9.9").await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["data"].as_array().cloned().unwrap_or_default();
    let target = rows
        .iter()
        .find(|r| r["ip"] == ip)
        .expect("expected multi-user mapping");
    assert_eq!(target["multi_user"], true);
    let users = target["current_users"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    assert!(users.iter().any(|u| u == "alice"));
    assert!(users.iter().any(|u| u == "bob"));
    assert!(users.iter().any(|u| u == "carol"));
}

#[tokio::test]
async fn test_single_user_not_multi() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v1/mappings?search=192.168.1.11").await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["data"].as_array().cloned().unwrap_or_default();
    let target = rows
        .iter()
        .find(|r| r["ip"] == "192.168.1.11")
        .expect("expected single-user mapping");
    assert_eq!(target["multi_user"], false);
    assert_eq!(target["current_users"][0], "bwilson");
}

#[tokio::test]
async fn test_ipv6_mapping() {
    let (app, db) = build_test_app().await;
    let ipv6 = "2001:db8::10";
    let event = IdentityEvent {
        source: SourceType::Manual,
        ip: ipv6.parse::<IpAddr>().expect("ipv6 parse failed"),
        user: "ipv6user".to_string(),
        timestamp: Utc::now(),
        raw_data: "ipv6 test event".to_string(),
        mac: Some("AA:BB:CC:DD:EE:66".to_string()),
        confidence_score: 100,
    };
    db.upsert_mapping(event, Some("TestVendor"))
        .await
        .expect("ipv6 upsert failed");

    sqlx::query(
        "INSERT INTO subnets (cidr, name, vlan_id) VALUES ('2001:db8::/32', 'IPv6 LAN', 300)",
    )
    .execute(db.pool())
    .await
    .expect("insert ipv6 subnet failed");
    sqlx::query(
        "UPDATE mappings
         SET subnet_id = (SELECT id FROM subnets WHERE cidr = '2001:db8::/32')
         WHERE ip = ?",
    )
    .bind(ipv6)
    .execute(db.pool())
    .await
    .expect("tag ipv6 mapping failed");

    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v1/mappings?search=2001:db8::10").await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["data"].as_array().cloned().unwrap_or_default();
    let target = rows
        .iter()
        .find(|r| r["ip"] == ipv6)
        .expect("expected ipv6 mapping");
    assert_eq!(target["subnet_name"], "IPv6 LAN");
}

#[tokio::test]
async fn test_list_subnets() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/subnets").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().map(|a| a.len()).unwrap_or(0), 2);
}

#[tokio::test]
async fn test_subnet_stats() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/subnets/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total_subnets"].as_i64().unwrap_or(-1), 2);
    assert_eq!(body["total_tagged_mappings"].as_i64().unwrap_or(-1), 5);
}

#[tokio::test]
async fn test_subnet_mappings() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/subnets/1/mappings").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"].as_i64().unwrap_or(-1), 3);
}

#[tokio::test]
async fn test_create_subnet() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/subnets",
        &json!({"cidr":"172.16.0.0/16","name":"VPN"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["name"], "VPN");
    let (status, list) = auth_get(&app, &cookie, "/api/v2/subnets").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().map(|a| a.len()).unwrap_or(0), 3);
}

#[tokio::test]
async fn test_create_subnet_duplicate_cidr() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_post(
        &app,
        &cookie,
        "/api/v2/subnets",
        &json!({"cidr":"10.1.2.0/24","name":"Dup"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "CONFLICT");
}

#[tokio::test]
async fn test_create_subnet_invalid_vlan() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_post(
        &app,
        &cookie,
        "/api/v2/subnets",
        &json!({"cidr":"10.10.0.0/16","name":"X","vlan_id":5000}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");
}

#[tokio::test]
async fn test_update_subnet() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_put(
        &app,
        &cookie,
        "/api/v2/subnets/1",
        &json!({"name":"Renamed LAN","location":"Floor 5"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Renamed LAN");
    assert_eq!(body["location"], "Floor 5");
}

#[tokio::test]
async fn test_delete_subnet_cascades_null() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_delete(&app, &cookie, "/api/v2/subnets/1").await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = auth_get(&app, &cookie, "/api/v1/mappings?limit=50").await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["data"].as_array().cloned().unwrap_or_default();
    for row in &rows {
        assert_ne!(row["subnet_name"], "Office LAN");
    }
}

#[tokio::test]
async fn test_list_dns() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/dns").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"].as_i64().unwrap_or(-1), 2);
}

#[tokio::test]
async fn test_dns_stats() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/dns/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total_cached"].as_i64().unwrap_or(-1), 2);
    assert_eq!(body["resolved_ok"].as_i64().unwrap_or(-1), 2);
}

#[tokio::test]
async fn test_dns_by_ip() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/dns/10.1.2.4").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["hostname"], "asmith-laptop.corp.local");
    assert_eq!(body["previous_hostname"], "old-host.corp.local");
}

#[tokio::test]
async fn test_delete_dns_entry() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_delete(&app, &cookie, "/api/v2/dns/10.1.2.3").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = auth_get(&app, &cookie, "/api/v2/dns/10.1.2.3").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_flush_dns_cache() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_post(&app, &cookie, "/api/v2/dns/flush", &json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted"].as_i64().unwrap_or(0), 2);
    let (status, stats) = auth_get(&app, &cookie, "/api/v2/dns/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stats["total_cached"].as_i64().unwrap_or(-1), 0);
}

#[tokio::test]
async fn test_list_switches_empty() {
    ensure_test_encryption_key();
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/switches").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().map(|a| a.len()).unwrap_or(0), 0);
}

#[tokio::test]
async fn test_create_switch() {
    ensure_test_encryption_key();
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_post(
        &app,
        &cookie,
        "/api/v2/switches",
        &json!({"ip":"10.0.0.1","name":"Core Switch","community":"public"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ip"], "10.0.0.1");
    assert!(body.get("community").is_none());
    assert!(body.get("community_encrypted").is_none());
}

#[tokio::test]
async fn test_create_switch_duplicate_ip() {
    ensure_test_encryption_key();
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let _ = auth_post(
        &app,
        &cookie,
        "/api/v2/switches",
        &json!({"ip":"10.0.0.1","name":"Core Switch","community":"public"}),
    )
    .await;
    let (status, body) = auth_post(
        &app,
        &cookie,
        "/api/v2/switches",
        &json!({"ip":"10.0.0.1","name":"Core Switch 2","community":"public"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "CONFLICT");
}

#[tokio::test]
async fn test_update_switch() {
    ensure_test_encryption_key();
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (_, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/switches",
        &json!({"ip":"10.0.0.2","name":"Old Name","community":"public"}),
    )
    .await;
    let id = created["id"].as_i64().unwrap_or(0);
    let (status, body) = auth_put(
        &app,
        &cookie,
        &format!("/api/v2/switches/{id}"),
        &json!({"name":"Renamed"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Renamed");
}

#[tokio::test]
async fn test_delete_switch() {
    ensure_test_encryption_key();
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (_, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/switches",
        &json!({"ip":"10.0.0.3","name":"DeleteMe","community":"public"}),
    )
    .await;
    let id = created["id"].as_i64().unwrap_or(0);
    let (status, _) = auth_delete(&app, &cookie, &format!("/api/v2/switches/{id}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, list) = auth_get(&app, &cookie, "/api/v2/switches").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().map(|a| a.len()).unwrap_or(0), 0);
}

#[tokio::test]
async fn test_switch_stats() {
    ensure_test_encryption_key();
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, stats0) = auth_get(&app, &cookie, "/api/v2/switches/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stats0["total_switches"].as_i64().unwrap_or(-1), 0);
    let _ = auth_post(
        &app,
        &cookie,
        "/api/v2/switches",
        &json!({"ip":"10.0.0.4","name":"S1","community":"public"}),
    )
    .await;
    let (status, stats1) = auth_get(&app, &cookie, "/api/v2/switches/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stats1["total_switches"].as_i64().unwrap_or(-1), 1);
}

#[tokio::test]
async fn test_switch_community_never_in_response() {
    ensure_test_encryption_key();
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (_, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/switches",
        &json!({"ip":"10.0.0.5","name":"NoSecret","community":"public"}),
    )
    .await;
    let id = created["id"].as_i64().unwrap_or(0);
    let (status, body) = auth_get(&app, &cookie, &format!("/api/v2/switches/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("community").is_none());
    assert!(body.get("community_encrypted").is_none());
}

#[tokio::test]
async fn test_list_fingerprints() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/fingerprints").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().map(|a| a.len()).unwrap_or(0) >= 20);
}

#[tokio::test]
async fn test_fingerprint_stats() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/fingerprints/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["builtin_fingerprints"].as_i64().unwrap_or(0) >= 20);
    assert_eq!(body["total_observations"].as_i64().unwrap_or(-1), 1);
}

#[tokio::test]
async fn test_list_observations() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/fingerprints/observations").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"].as_i64().unwrap_or(-1), 1);
    assert_eq!(body["data"][0]["mac"], "AA:BB:CC:DD:EE:01");
}

#[tokio::test]
async fn test_create_custom_fingerprint() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/fingerprints",
        &json!({"fingerprint":"15,3,1,6,28","device_type":"Custom Sensor"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["source"], "user");
    assert_eq!(created["fingerprint"], "1,3,6,15,28");
}

#[tokio::test]
async fn test_delete_builtin_fingerprint_forbidden() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, list) = auth_get(&app, &cookie, "/api/v2/fingerprints").await;
    assert_eq!(status, StatusCode::OK);
    let rows = list.as_array().cloned().unwrap_or_default();
    let builtin_id = rows
        .iter()
        .find(|r| r["source"] == "builtin")
        .and_then(|r| r["id"].as_i64())
        .expect("missing builtin fingerprint");
    let (status, body) =
        auth_delete(&app, &cookie, &format!("/api/v2/fingerprints/{builtin_id}")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "FORBIDDEN");
}

#[tokio::test]
async fn test_delete_user_fingerprint_ok() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (_, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/fingerprints",
        &json!({"fingerprint":"1,3,6,15,28","device_type":"Custom Sensor"}),
    )
    .await;
    let id = created["id"].as_i64().unwrap_or(0);
    let (status, _) = auth_delete(&app, &cookie, &format!("/api/v2/fingerprints/{id}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_fingerprint_backfill() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) =
        auth_post(&app, &cookie, "/api/v2/fingerprints/backfill", &json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["updated"].as_u64().is_some());
}

#[tokio::test]
async fn test_phase2_viewer_cannot_mutate() {
    ensure_test_encryption_key();
    let (app, db) = build_test_app().await;
    let viewer = db
        .create_user("testviewer", "testpassword123", UserRole::Viewer)
        .await
        .expect("create viewer failed");
    db.set_force_password_change(viewer.id, false)
        .await
        .expect("set force password failed");
    let cookie = login_and_get_cookie(&app, "testviewer", "testpassword123").await;

    let (s1, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/subnets",
        &json!({"cidr":"172.30.0.0/16","name":"ViewerWrite"}),
    )
    .await;
    assert_eq!(s1, StatusCode::FORBIDDEN);

    let (s2, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/switches",
        &json!({"ip":"10.0.9.1","name":"ViewerSwitch","community":"public"}),
    )
    .await;
    assert_eq!(s2, StatusCode::FORBIDDEN);

    let (s3, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/fingerprints",
        &json!({"fingerprint":"1,3,6,15","device_type":"Viewer Custom"}),
    )
    .await;
    assert_eq!(s3, StatusCode::FORBIDDEN);

    let (s4, _) = auth_delete(&app, &cookie, "/api/v2/dns/10.1.2.3").await;
    assert_eq!(s4, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_phase2_no_auth_rejected() {
    let (app, _) = build_test_app().await;
    for uri in [
        "/api/v2/subnets",
        "/api/v2/dns",
        "/api/v2/switches",
        "/api/v2/fingerprints",
    ] {
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .expect("build no-auth request failed");
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .expect("execute no-auth request failed");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "uri={uri}");
    }
}

#[tokio::test]
async fn test_analytics_trends() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(
        &app,
        &cookie,
        "/api/v2/analytics/trends?metric=events&days=7",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["metric"], "events");
    assert_eq!(body["interval"], "day");
    assert!(body["data"].is_array());
}

#[tokio::test]
async fn test_analytics_compliance() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/analytics/compliance").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["generated_at"].is_string());
    assert!(body["mappings"].is_object());
    assert!(body["conflicts"].is_object());
    assert!(body["coverage"].is_object());
    assert!(body["integrations"].is_object());
    assert!(body["alerts"].is_object());
}

#[tokio::test]
async fn test_analytics_reports_empty() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/analytics/reports").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"].as_i64().unwrap_or(-1), 0);
    assert_eq!(body["data"].as_array().map(|a| a.len()).unwrap_or(99), 0);
}

#[tokio::test]
async fn test_analytics_top_users() {
    let (app, db) = build_test_app().await;
    seed_analytics_events(&db).await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(
        &app,
        &cookie,
        "/api/v2/analytics/top?dimension=users&metric=events&days=7&limit=5",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["dimension"], "users");
    let rows = body["data"].as_array().cloned().unwrap_or_default();
    assert!(!rows.is_empty());
    let first = &rows[0];
    assert!(first["label"].is_string());
    assert!(first["count"].as_i64().unwrap_or(0) > 0);
}

#[tokio::test]
async fn test_analytics_top_invalid_dimension() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_get(
        &app,
        &cookie,
        "/api/v2/analytics/top?dimension=nonexistent&metric=events",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_analytics_source_distribution() {
    let (app, db) = build_test_app().await;
    seed_analytics_events(&db).await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/analytics/sources?days=7").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["total_events"].is_number());
    let rows = body["sources"].as_array().cloned().unwrap_or_default();
    assert!(!rows.is_empty());
    let first = &rows[0];
    assert!(first["source"].is_string());
    assert!(first["count"].is_number());
    assert!(first["percentage"].is_number());
}

#[tokio::test]
async fn test_analytics_generate_report() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_post(
        &app,
        &cookie,
        "/api/v2/analytics/reports/generate",
        &json!({}),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::CREATED);
    assert!(body["id"].as_i64().unwrap_or(0) > 0);
}

#[tokio::test]
async fn test_analytics_get_report() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (create_status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/analytics/reports/generate",
        &json!({}),
    )
    .await;
    assert!(create_status == StatusCode::OK || create_status == StatusCode::CREATED);
    let id = created["id"].as_i64().unwrap_or(0);
    assert!(id > 0);

    let (status, body) = auth_get(&app, &cookie, &format!("/api/v2/analytics/reports/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].is_object() || body["data"].is_string());
    assert!(body["report_type"].is_string());
    assert!(body["generated_at"].is_string());
}

#[tokio::test]
async fn test_analytics_reports_list_after_generate() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (create_status, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/analytics/reports/generate",
        &json!({}),
    )
    .await;
    assert!(create_status == StatusCode::OK || create_status == StatusCode::CREATED);

    let (status, body) = auth_get(&app, &cookie, "/api/v2/analytics/reports").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["total"].as_i64().unwrap_or(0) >= 1);
    assert!(body["data"].as_array().map(|v| v.len()).unwrap_or(0) >= 1);
}

#[tokio::test]
async fn test_analytics_trends_hourly() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(
        &app,
        &cookie,
        "/api/v2/analytics/trends?metric=events&interval=hour&days=1",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["interval"], "hour");
    assert!(body["data"].is_array());
}

#[tokio::test]
async fn test_analytics_trends_invalid_metric() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_get(&app, &cookie, "/api/v2/analytics/trends?metric=nonexistent").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_analytics_viewer_can_read() {
    let (app, db) = build_test_app().await;
    let viewer = db
        .create_user("analytics_viewer", "testpassword123", UserRole::Viewer)
        .await
        .expect("create viewer failed");
    db.set_force_password_change(viewer.id, false)
        .await
        .expect("set force password failed");
    let cookie = login_and_get_cookie(&app, "analytics_viewer", "testpassword123").await;

    let (status, _) = auth_get(
        &app,
        &cookie,
        "/api/v2/analytics/trends?metric=events&days=7",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_analytics_viewer_cannot_generate() {
    let (app, db) = build_test_app().await;
    let viewer = db
        .create_user("analytics_viewer2", "testpassword123", UserRole::Viewer)
        .await
        .expect("create viewer failed");
    db.set_force_password_change(viewer.id, false)
        .await
        .expect("set force password failed");
    let cookie = login_and_get_cookie(&app, "analytics_viewer2", "testpassword123").await;

    let (status, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/analytics/reports/generate",
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_map_topology() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/map/topology").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["subnets"].is_array());
    assert!(body["adapters"].is_array());
    assert!(body["stats"].is_object());
}

#[tokio::test]
async fn test_sse_endpoint_requires_auth() {
    let (app, _) = build_test_app().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/v2/events/stream")
        .body(Body::empty())
        .expect("build sse unauth request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("execute sse unauth request failed");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_sse_endpoint_returns_stream() {
    let (engine_url, mock_handle) = spawn_mock_engine_sse().await;
    let (app, _) = build_test_app_with_engine_url(engine_url).await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, headers, body) = auth_get_raw(&app, &cookie, "/api/v2/events/stream").await;
    mock_handle.abort();

    assert_eq!(status, StatusCode::OK);
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(content_type.starts_with("text/event-stream"));
    assert!(!body.is_empty());
}

#[tokio::test]
async fn test_notification_channel_crud() {
    ensure_test_encryption_key();
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/notifications/channels",
        &json!({
            "name": "Email Ops",
            "channel_type": "email",
            "enabled": true,
            "config": {
                "smtp_host": "mail.example.com",
                "smtp_port": 587,
                "smtp_tls": true,
                "smtp_user": "svc_trueid",
                "smtp_pass": "secret123",
                "from_address": "trueid@example.com",
                "to_addresses": ["soc@example.com"],
                "subject_prefix": "[TrueID]"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = created["id"].as_i64().unwrap_or_default();
    assert!(id > 0);

    let (status, list) = auth_get(&app, &cookie, "/api/v2/notifications/channels").await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.as_array().map(|a| !a.is_empty()).unwrap_or(false));

    let (status, one) = auth_get(
        &app,
        &cookie,
        &format!("/api/v2/notifications/channels/{id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(one["name"], "Email Ops");

    let (status, updated) = auth_put(
        &app,
        &cookie,
        &format!("/api/v2/notifications/channels/{id}"),
        &json!({
            "name": "Email Ops Updated",
            "channel_type": "email",
            "enabled": false,
            "config": {
                "smtp_host": "mail.example.com",
                "smtp_port": 587,
                "smtp_tls": true,
                "smtp_user": "svc_trueid",
                "smtp_pass": "secret123",
                "from_address": "trueid@example.com",
                "to_addresses": ["soc@example.com"],
                "subject_prefix": "[TrueID]"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["name"], "Email Ops Updated");
    assert_eq!(updated["enabled"], false);

    let (status, _) = auth_delete(
        &app,
        &cookie,
        &format!("/api/v2/notifications/channels/{id}"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_notification_channel_types() {
    ensure_test_encryption_key();
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let cases = vec![
        json!({
            "name": "email-ch",
            "channel_type": "email",
            "config": {
                "smtp_host": "mail.example.com",
                "smtp_port": 587,
                "smtp_tls": true,
                "from_address": "trueid@example.com",
                "to_addresses": ["ops@example.com"]
            }
        }),
        json!({
            "name": "slack-ch",
            "channel_type": "slack",
            "config": {
                "webhook_url": "https://hooks.slack.com/services/T000/B000/XXXX",
                "channel": "#alerts"
            }
        }),
        json!({
            "name": "teams-ch",
            "channel_type": "teams",
            "config": {
                "webhook_url": "https://webhook.office.com/webhookb2/tenant/IncomingWebhook/abc/def"
            }
        }),
        json!({
            "name": "webhook-ch",
            "channel_type": "webhook",
            "config": {
                "url": "https://example.com/hook",
                "method": "POST"
            }
        }),
    ];
    for payload in cases {
        let (status, _) =
            auth_post(&app, &cookie, "/api/v2/notifications/channels", &payload).await;
        assert_eq!(status, StatusCode::CREATED);
    }
}

#[tokio::test]
async fn test_notification_channel_validation() {
    ensure_test_encryption_key();
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/notifications/channels",
        &json!({
            "name": "bad-email",
            "channel_type": "email",
            "config": {
                "smtp_host": "mail.example.com",
                "smtp_port": 999,
                "smtp_tls": true,
                "from_address": "trueid@example.com",
                "to_addresses": ["ops@example.com"]
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/notifications/channels",
        &json!({
            "name": "bad-webhook",
            "channel_type": "webhook",
            "config": {}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_notification_deliveries_empty() {
    ensure_test_encryption_key();
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/notifications/channels",
        &json!({
            "name": "webhook-empty",
            "channel_type": "webhook",
            "config": {
                "url": "https://example.com/hook",
                "method": "POST"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = created["id"].as_i64().unwrap_or_default();
    let (status, rows) = auth_get(
        &app,
        &cookie,
        &format!("/api/v2/notifications/channels/{id}/deliveries"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rows.as_array().map(|v| v.len()).unwrap_or_default(), 0);
}

#[tokio::test]
async fn test_retention_policies_list() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/admin/retention").await;
    assert_eq!(status, StatusCode::OK);
    let policies = body["policies"].as_array().cloned().unwrap_or_default();
    assert!(!policies.is_empty());
    let names = policies
        .iter()
        .filter_map(|p| p["table_name"].as_str())
        .collect::<Vec<_>>();
    assert!(names.contains(&"events"));
    assert!(names.contains(&"audit_log"));
}

#[tokio::test]
async fn test_retention_policy_update() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_put(
        &app,
        &cookie,
        "/api/v2/admin/retention/events",
        &json!({"retention_days": 120, "enabled": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = auth_get(&app, &cookie, "/api/v2/admin/retention").await;
    assert_eq!(status, StatusCode::OK);
    let policies = body["policies"].as_array().cloned().unwrap_or_default();
    let events = policies
        .iter()
        .find(|p| p["table_name"] == "events")
        .cloned()
        .unwrap_or(json!({}));
    assert_eq!(events["retention_days"], 120);
    assert_eq!(events["enabled"], true);
}

#[tokio::test]
async fn test_retention_audit_minimum() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_put(
        &app,
        &cookie,
        "/api/v2/admin/retention/audit_log",
        &json!({"retention_days": 5, "enabled": true}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_import_events_success() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let payload = json!({
        "events": [
            {"ip": "10.20.30.1", "user": "import_user_1", "source": "Radius"},
            {"ip": "10.20.30.2", "user": "import_user_2", "source": "AdLog"},
            {"ip": "10.20.30.3", "user": "import_user_3", "source": "DhcpLease"},
            {"ip": "10.20.30.4", "user": "import_user_4", "source": "Manual"},
            {"ip": "10.20.30.5", "user": "import_user_5", "source": "Radius"}
        ]
    });
    let (status, body) = auth_post(&app, &cookie, "/api/v2/import/events", &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["imported"], 5);
    assert_eq!(body["skipped"], 0);
}

#[tokio::test]
async fn test_import_events_invalid_ip() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let payload = json!({
        "events": [
            {"ip": "999.999.999.999", "user": "broken_user", "source": "Radius"}
        ]
    });
    let (status, body) = auth_post(&app, &cookie, "/api/v2/import/events", &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["imported"], 0);
    assert_eq!(body["skipped"], 1);
    let errors = body["errors"].as_array().cloned().unwrap_or_default();
    assert!(!errors.is_empty());
}

#[tokio::test]
async fn test_import_events_max_limit() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let mut events = Vec::with_capacity(10_001);
    for i in 0..10_001_u32 {
        events.push(json!({
            "ip": format!("10.66.{}.{}", (i / 255) % 255, i % 255),
            "user": format!("user_{i}"),
            "source": "Manual"
        }));
    }
    let payload = json!({ "events": events });
    let (status, _) = auth_post(&app, &cookie, "/api/v2/import/events", &payload).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_firewall_create_target() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_post(
        &app,
        &cookie,
        "/api/v2/firewall/targets",
        &json!({
            "name":"PA-5260-DC1","firewall_type":"panos","host":"10.0.0.1","port":443,
            "username":"trueid-svc","password":"testpass123","verify_tls":false,"push_interval_secs":30
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "PA-5260-DC1");
    assert_eq!(body["firewall_type"], "panos");
    assert_eq!(body["host"], "10.0.0.1");
    assert_eq!(body["port"], 443);
    assert_eq!(body["username"], "trueid-svc");
    assert_eq!(body["verify_tls"], false);
    assert_eq!(body["push_interval_secs"], 30);
    assert!(body.get("password").is_none());
    assert!(body.get("password_enc").is_none());
    assert!(body.get("token").is_none());
}

#[tokio::test]
async fn test_firewall_create_fortigate() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_post(
        &app,
        &cookie,
        "/api/v2/firewall/targets",
        &json!({
            "name":"FG-600E-HQ","firewall_type":"fortigate","host":"10.0.0.2","port":443,
            "password":"api-token-test-123","verify_tls":false,"push_interval_secs":60
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["firewall_type"], "fortigate");
}

#[tokio::test]
async fn test_firewall_create_duplicate_host() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let _ = auth_post(
        &app,
        &cookie,
        "/api/v2/firewall/targets",
        &json!({
            "name":"PA1","firewall_type":"panos","host":"10.0.0.10","port":443,
            "username":"trueid-svc","password":"testpass123"
        }),
    )
    .await;
    let (status, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/firewall/targets",
        &json!({
            "name":"PA2","firewall_type":"panos","host":"10.0.0.10","port":443,
            "username":"trueid-svc","password":"testpass456"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_firewall_create_invalid_type() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/firewall/targets",
        &json!({
            "name":"J1","firewall_type":"juniper","host":"10.0.0.11","port":443,
            "username":"svc","password":"x"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_firewall_list_targets() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let _ = auth_post(&app, &cookie, "/api/v2/firewall/targets", &json!({
        "name":"PA","firewall_type":"panos","host":"10.0.0.12","port":443,"username":"svc","password":"x"
    })).await;
    let _ = auth_post(
        &app,
        &cookie,
        "/api/v2/firewall/targets",
        &json!({
            "name":"FG","firewall_type":"fortigate","host":"10.0.0.13","port":443,"password":"tok"
        }),
    )
    .await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/firewall/targets").await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().cloned().unwrap_or_default();
    assert_eq!(arr.len(), 2);
    for item in &arr {
        assert!(item.get("password").is_none());
        assert!(item.get("password_enc").is_none());
        assert!(item.get("token").is_none());
    }
}

#[tokio::test]
async fn test_firewall_get_update_target() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (_, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/firewall/targets",
        &json!({
            "name":"PA-OLD","firewall_type":"panos","host":"10.0.0.14","port":443,
            "username":"svc","password":"x","push_interval_secs":30
        }),
    )
    .await;
    let id = created["id"].as_i64().unwrap_or_default();
    let old_updated = created["updated_at"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let (status, got) = auth_get(&app, &cookie, &format!("/api/v2/firewall/targets/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got["name"], "PA-OLD");
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (status, _) = auth_put(
        &app,
        &cookie,
        &format!("/api/v2/firewall/targets/{id}"),
        &json!({"name":"PA-NEW","push_interval_secs":45}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, updated) =
        auth_get(&app, &cookie, &format!("/api/v2/firewall/targets/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["name"], "PA-NEW");
    assert_eq!(updated["push_interval_secs"], 45);
    assert_ne!(
        updated["updated_at"].as_str().unwrap_or_default(),
        old_updated
    );
}

#[tokio::test]
async fn test_firewall_delete_target() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (_, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/firewall/targets",
        &json!({
            "name":"PA-DEL","firewall_type":"panos","host":"10.0.0.15","port":443,
            "username":"svc","password":"x"
        }),
    )
    .await;
    let id = created["id"].as_i64().unwrap_or_default();
    sqlx::query(
        "INSERT INTO firewall_push_history (target_id, mapping_count, status) VALUES (?, 1, 'ok')",
    )
    .bind(id)
    .execute(db.pool())
    .await
    .expect("insert firewall history failed");
    let (status, _) = auth_delete(&app, &cookie, &format!("/api/v2/firewall/targets/{id}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = auth_get(&app, &cookie, &format!("/api/v2/firewall/targets/{id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let left: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM firewall_push_history WHERE target_id = ?")
            .bind(id)
            .fetch_one(db.pool())
            .await
            .expect("count firewall history failed");
    assert_eq!(left, 0);
}

#[tokio::test]
async fn test_firewall_history_empty() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (_, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/firewall/targets",
        &json!({
            "name":"PA-HIST","firewall_type":"panos","host":"10.0.0.16","port":443,
            "username":"svc","password":"x"
        }),
    )
    .await;
    let id = created["id"].as_i64().unwrap_or_default();
    let (status, body) = auth_get(
        &app,
        &cookie,
        &format!("/api/v2/firewall/targets/{id}/history"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 0);
    assert_eq!(body["data"].as_array().map(|a| a.len()).unwrap_or(0), 0);
}

#[tokio::test]
async fn test_firewall_stats() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/firewall/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["total_targets"].is_i64());
    assert!(body["enabled_targets"].is_i64());
    assert!(body["panos_targets"].is_i64());
    assert!(body["fortigate_targets"].is_i64());
}

#[tokio::test]
async fn test_siem_create_target() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_post(
        &app,
        &cookie,
        "/api/v2/siem/targets",
        &json!({
            "name":"Splunk-HEC","format":"cef","transport":"udp","host":"splunk.corp.local","port":514,
            "forward_mappings":true,"forward_conflicts":true,"forward_alerts":false
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["format"], "cef");
    assert_eq!(body["transport"], "udp");
}

#[tokio::test]
async fn test_siem_create_tcp_json() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_post(
        &app,
        &cookie,
        "/api/v2/siem/targets",
        &json!({"name":"Elastic","format":"json","transport":"tcp","host":"elastic.local","port":5514}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["format"], "json");
    assert_eq!(body["transport"], "tcp");
}

#[tokio::test]
async fn test_siem_create_invalid_format() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/siem/targets",
        &json!({"name":"X","format":"xml","transport":"udp","host":"x.local","port":514}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_siem_list_and_get() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let _ = auth_post(
        &app,
        &cookie,
        "/api/v2/siem/targets",
        &json!({
            "name":"S1","format":"cef","transport":"udp","host":"s1.local","port":514
        }),
    )
    .await;
    let (_, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/siem/targets",
        &json!({
            "name":"S2","format":"json","transport":"tcp","host":"s2.local","port":5514
        }),
    )
    .await;
    let id = created["id"].as_i64().unwrap_or_default();
    let (status, list) = auth_get(&app, &cookie, "/api/v2/siem/targets").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().map(|a| a.len()).unwrap_or(0), 2);
    let (status, got) = auth_get(&app, &cookie, &format!("/api/v2/siem/targets/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got["name"], "S2");
}

#[tokio::test]
async fn test_siem_update_and_delete() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (_, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/siem/targets",
        &json!({
            "name":"S-OLD","format":"cef","transport":"udp","host":"s3.local","port":514
        }),
    )
    .await;
    let id = created["id"].as_i64().unwrap_or_default();
    let (status, updated) = auth_put(
        &app,
        &cookie,
        &format!("/api/v2/siem/targets/{id}"),
        &json!({"name":"S-NEW","format":"json"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["name"], "S-NEW");
    assert_eq!(updated["format"], "json");
    let (status, _) = auth_delete(&app, &cookie, &format!("/api/v2/siem/targets/{id}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = auth_get(&app, &cookie, &format!("/api/v2/siem/targets/{id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_siem_stats() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/siem/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["total_targets"].is_i64());
    assert!(body["enabled_targets"].is_i64());
    assert!(body["total_events_forwarded"].is_i64());
}

#[tokio::test]
async fn test_ldap_get_default_config() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/ldap/config").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["enabled"], false);
    assert_eq!(body["password_set"], false);
    assert!(body["ldap_url"]
        .as_str()
        .unwrap_or_default()
        .starts_with("ldap://"));
}

#[tokio::test]
async fn test_ldap_update_config() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_put(
        &app,
        &cookie,
        "/api/v2/ldap/config",
        &json!({
            "ldap_url":"ldap://dc2.corp.local:389",
            "bind_dn":"CN=TrueID,OU=Service,DC=corp,DC=local",
            "bind_password":"secret123",
            "enabled":true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = auth_get(&app, &cookie, "/api/v2/ldap/config").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ldap_url"], "ldap://dc2.corp.local:389");
    assert_eq!(body["password_set"], true);
    assert!(body.get("bind_password").is_none());
}

#[tokio::test]
async fn test_ldap_update_config_validation() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_put(
        &app,
        &cookie,
        "/api/v2/ldap/config",
        &json!({"sync_interval_secs":5}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = auth_put(
        &app,
        &cookie,
        "/api/v2/ldap/config",
        &json!({"ldap_url":""}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_ldap_groups_empty() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/ldap/groups").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().map(|a| a.len()).unwrap_or(0), 0);
}

#[tokio::test]
async fn test_ldap_groups_with_data() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    sqlx::query(
        "INSERT INTO user_groups (username, group_name) VALUES
         ('jkowalski','Domain Admins'),
         ('jkowalski','VPN Users'),
         ('asmith','VPN Users')",
    )
    .execute(db.pool())
    .await
    .expect("seed user_groups failed");

    let (status, groups) = auth_get(&app, &cookie, "/api/v2/ldap/groups").await;
    assert_eq!(status, StatusCode::OK);
    let names = groups
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v["group_name"].as_str().map(str::to_string))
        .collect::<Vec<_>>();
    assert!(names.iter().any(|n| n == "Domain Admins"));
    assert!(names.iter().any(|n| n == "VPN Users"));

    let (status, members) =
        auth_get(&app, &cookie, "/api/v2/ldap/groups/VPN%20Users/members").await;
    assert_eq!(status, StatusCode::OK);
    let users = members
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v["username"].as_str().map(str::to_string))
        .collect::<Vec<_>>();
    assert!(users.iter().any(|u| u == "jkowalski"));
    assert!(users.iter().any(|u| u == "asmith"));

    let (status, user_groups) =
        auth_get(&app, &cookie, "/api/v2/ldap/users/jkowalski/groups").await;
    assert_eq!(status, StatusCode::OK);
    let user_group_names = user_groups
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v["group_name"].as_str().map(str::to_string))
        .collect::<Vec<_>>();
    assert!(user_group_names.iter().any(|n| n == "Domain Admins"));
    assert!(user_group_names.iter().any(|n| n == "VPN Users"));
}

#[tokio::test]
async fn test_ldap_groups_enrichment_in_mappings() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    sqlx::query("INSERT INTO user_groups (username, group_name) VALUES ('jkowalski', 'IT Dept')")
        .execute(db.pool())
        .await
        .expect("seed ldap group failed");
    let (status, body) = auth_get(&app, &cookie, "/api/v1/mappings?search=jkowalski").await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["data"].as_array().cloned().unwrap_or_default();
    let found = rows.iter().any(|row| {
        row["groups"]
            .as_array()
            .map(|arr| arr.iter().any(|g| g == "IT Dept"))
            .unwrap_or(false)
    });
    assert!(
        found,
        "expected IT Dept in at least one mapping groups field"
    );
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

#[tokio::test]
async fn test_password_policy_validation() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_post(
        &app,
        &cookie,
        "/api/v1/users",
        &json!({
            "username": "shortpassuser",
            "password": "short",
            "role": "Viewer"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap_or("").contains("at least"),
        "expected policy message, got: {body}"
    );
}

#[tokio::test]
async fn test_password_policy_update() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, current) = auth_get(&app, &cookie, "/api/v2/admin/security/password-policy").await;
    assert_eq!(status, StatusCode::OK);
    let mut payload = current.clone();
    payload["min_length"] = json!(16);
    let (status, _) = auth_put(
        &app,
        &cookie,
        "/api/v2/admin/security/password-policy",
        &payload,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = auth_post(
        &app,
        &cookie,
        "/api/v1/users",
        &json!({
            "username": "policyuser",
            "password": "Testpassword12",
            "role": "Viewer"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap_or("").contains("at least 16"),
        "expected min_length validation message, got: {body}"
    );
}

#[tokio::test]
async fn test_totp_setup_and_verify() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, setup) = auth_post(&app, &cookie, "/api/auth/totp/setup", &json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let secret = setup["secret"]
        .as_str()
        .expect("missing totp setup secret")
        .to_string();
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(secret)
            .to_bytes()
            .expect("invalid secret encoding"),
        Some("TrueID".to_string()),
        "testadmin".to_string(),
    )
    .expect("failed to build totp");
    let code = totp.generate_current().expect("failed to generate current code");
    let (status, verify) = auth_post(
        &app,
        &cookie,
        "/api/auth/totp/verify",
        &json!({ "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        verify["backup_codes"]
            .as_array()
            .map(|v| v.len() == 10)
            .unwrap_or(false),
        "expected 10 backup codes, got: {verify}"
    );
    let (status, s) = auth_get(&app, &cookie, "/api/auth/totp/status").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(s["enabled"], json!(true));
}

#[tokio::test]
async fn test_totp_login_requires_code() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (_, setup) = auth_post(&app, &cookie, "/api/auth/totp/setup", &json!({})).await;
    let secret = setup["secret"]
        .as_str()
        .expect("missing totp setup secret")
        .to_string();
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(secret)
            .to_bytes()
            .expect("invalid secret encoding"),
        Some("TrueID".to_string()),
        "testadmin".to_string(),
    )
    .expect("failed to build totp");
    let code = totp.generate_current().expect("failed to generate current code");
    let (status, _) = auth_post(
        &app,
        &cookie,
        "/api/auth/totp/verify",
        &json!({ "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&json!({
                "username": "testadmin",
                "password": "testpassword123"
            }))
            .expect("serialize login body failed"),
        ))
        .expect("build login request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("login request execution failed");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect login body failed")
        .to_bytes();
    let json_body: Value = serde_json::from_slice(&body).expect("parse login json failed");
    assert_eq!(json_body["requires_2fa"], json!(true));
}

#[tokio::test]
async fn test_session_info_includes_ip() {
    let (app, _) = build_test_app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .header("x-real-ip", "10.10.10.10")
        .body(Body::from(
            serde_json::to_string(&json!({
                "username": "testadmin",
                "password": "testpassword123"
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
    let cookie = parts.join("; ");
    let req = Request::builder()
        .method("GET")
        .uri("/api/auth/sessions")
        .header("cookie", cookie)
        .header("x-real-ip", "10.10.10.10")
        .body(Body::empty())
        .expect("build list sessions request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("list sessions execution failed");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect sessions response failed")
        .to_bytes();
    let body: Value = serde_json::from_slice(&bytes).expect("parse sessions json failed");
    let rows = body.as_array().cloned().unwrap_or_default();
    assert!(!rows.is_empty(), "expected at least one active session");
    assert_eq!(
        rows[0]["ip_address"].as_str().unwrap_or(""),
        "10.10.10.10",
        "expected bound IP in session info"
    );
}

#[tokio::test]
async fn test_ip_tag_crud() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/tags",
        &json!({
            "ip": "10.1.2.3",
            "tag": "server",
            "color": "#3b82f6"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let tag_id = created["id"].as_i64().unwrap_or_default();
    assert!(tag_id > 0, "expected created tag id, got: {created}");

    let (status, list) = auth_get(&app, &cookie, "/api/v2/tags").await;
    assert_eq!(status, StatusCode::OK);
    let rows = list["data"].as_array().cloned().unwrap_or_default();
    assert!(
        rows.iter().any(|r| r["tag"] == "server"),
        "expected server tag in list, got: {list}"
    );

    let (status, by_ip) = auth_get(&app, &cookie, "/api/v2/tags/ip/10.1.2.3").await;
    assert_eq!(status, StatusCode::OK);
    let tags = by_ip["data"].as_array().cloned().unwrap_or_default();
    assert!(
        tags.iter().any(|r| r["tag"] == "server"),
        "expected server tag on IP, got: {by_ip}"
    );

    let (status, _) = auth_delete(&app, &cookie, &format!("/api/v2/tags/{tag_id}")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_ip_tag_search() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/tags",
        &json!({"ip": "10.1.2.3", "tag": "vip", "color": "#d4af37"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/tags",
        &json!({"ip": "10.1.2.4", "tag": "vip", "color": "#d4af37"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = auth_get(&app, &cookie, "/api/v2/tags/search?tag=vip").await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["data"].as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 2, "expected 2 rows for vip tag, got: {body}");
}

#[tokio::test]
async fn test_discovered_subnets_list() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/subnets/discovered").await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["data"].as_array().cloned().unwrap_or_default();
    assert!(rows.is_empty(), "expected empty discovered subnets, got: {body}");
}

#[tokio::test]
async fn test_geo_lookup_private_ip() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/geo/10.0.0.1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["is_private"], json!(true));
}

#[tokio::test]
async fn test_sse_requires_auth() {
    let (app, _) = build_test_app().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/v2/events/stream")
        .body(Body::empty())
        .expect("build sse request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("sse request execution failed");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_sse_accepts_auth() {
    let (engine_url, mock_handle) = spawn_mock_engine_sse().await;
    let (app, _) = build_test_app_with_engine_url(engine_url).await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, headers, _) = auth_get_raw(&app, &cookie, "/api/v2/events/stream").await;
    mock_handle.abort();
    assert_eq!(status, StatusCode::OK);
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/event-stream"), "unexpected content-type: {ct}");
}

#[tokio::test]
async fn test_notification_channel_email_config() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/notifications/channels",
        &json!({
            "name": "smtp-main",
            "channel_type": "email",
            "enabled": true,
            "config": {
                "smtp_host": "mail.example.com",
                "smtp_port": 587,
                "smtp_tls": true,
                "smtp_user": "bot@example.com",
                "smtp_pass": "super-secret",
                "from_address": "trueid@example.com",
                "to_addresses": ["soc@example.com"],
                "subject_prefix": "[TrueID]"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = created["id"].as_i64().unwrap_or_default();
    let (status, one) = auth_get(
        &app,
        &cookie,
        &format!("/api/v2/notifications/channels/{id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let summary = one["config_summary"].as_str().unwrap_or("");
    assert!(summary.contains("mail.example.com"), "summary missing host: {summary}");
    assert!(!summary.contains("super-secret"), "summary leaked secret: {summary}");

    let (status, _) = auth_put(
        &app,
        &cookie,
        &format!("/api/v2/notifications/channels/{id}"),
        &json!({
            "name": "smtp-main",
            "channel_type": "email",
            "enabled": true,
            "config": {
                "smtp_host": "mail.example.com",
                "smtp_port": 465,
                "smtp_tls": true,
                "smtp_user": "bot@example.com",
                "smtp_pass": "super-secret",
                "from_address": "trueid@example.com",
                "to_addresses": ["soc@example.com"],
                "subject_prefix": "[TrueID]"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, one) = auth_get(
        &app,
        &cookie,
        &format!("/api/v2/notifications/channels/{id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let summary = one["config_summary"].as_str().unwrap_or("");
    assert!(summary.contains(":465"), "summary missing updated port: {summary}");
}

#[tokio::test]
async fn test_notification_channel_link_to_rule() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, ch) = auth_post(
        &app,
        &cookie,
        "/api/v2/notifications/channels",
        &json!({
            "name": "slack-alerts",
            "channel_type": "slack",
            "enabled": true,
            "config": {
                "webhook_url": "https://hooks.slack.com/services/T000/B000/XXXX",
                "channel": "#soc",
                "username": "TrueID",
                "icon_emoji": ":shield:"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let ch_id = ch["id"].as_i64().unwrap_or_default();
    let (status, rule) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "new-subnet-link-test",
            "rule_type": "new_subnet",
            "severity": "warning",
            "enabled": true,
            "cooldown_minutes": 5,
            "action_log": true,
            "cooldown_seconds": 300,
            "channel_ids": [ch_id]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let rule_id = rule["id"].as_i64().unwrap_or_default();
    let (status, got) = auth_get(&app, &cookie, "/api/v2/alerts/rules").await;
    assert_eq!(status, StatusCode::OK);
    let rows = got["rules"].as_array().cloned().unwrap_or_default();
    let linked = rows
        .iter()
        .find(|r| r["id"].as_i64() == Some(rule_id))
        .and_then(|r| r["channels"].as_array())
        .map(|arr| arr.iter().any(|c| c["id"].as_i64() == Some(ch_id)))
        .unwrap_or(false);
    assert!(linked, "expected linked channel in rule response: {got}");
}

#[tokio::test]
async fn test_notification_channel_delivery_log_empty() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, ch) = auth_post(
        &app,
        &cookie,
        "/api/v2/notifications/channels",
        &json!({
            "name": "wh-delivery-empty",
            "channel_type": "webhook",
            "enabled": true,
            "config": {
                "url": "https://example.com/hook",
                "method": "POST"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = ch["id"].as_i64().unwrap_or_default();
    let (status, body) = auth_get(
        &app,
        &cookie,
        &format!("/api/v2/notifications/channels/{id}/deliveries"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "expected empty delivery list, got: {body}"
    );
}

#[tokio::test]
async fn test_retention_force_run() {
    let (engine_url, mock_handle) = spawn_mock_engine_retention_run().await;
    let (app, _) = build_test_app_with_engine_url(engine_url).await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_post(&app, &cookie, "/api/v2/admin/retention/run", &json!({})).await;
    mock_handle.abort();
    assert_eq!(status, StatusCode::OK);
    assert!(body["results"].is_array(), "expected results array, got: {body}");
}

#[tokio::test]
async fn test_retention_stats() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/admin/retention/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["tables"].is_array(), "expected tables array, got: {body}");
    let has_row_count = body["tables"]
        .as_array()
        .map(|arr| arr.iter().any(|r| r.get("row_count").is_some()))
        .unwrap_or(false);
    assert!(has_row_count, "expected row_count in tables, got: {body}");
    assert!(
        body.get("database_size_bytes").is_some(),
        "expected database_size_bytes, got: {body}"
    );
}

#[tokio::test]
async fn test_retention_update_validation() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_put(
        &app,
        &cookie,
        "/api/v2/admin/retention/events",
        &json!({"retention_days": 0, "enabled": true}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = auth_put(
        &app,
        &cookie,
        "/api/v2/admin/retention/events",
        &json!({"retention_days": 30, "enabled": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = auth_get(&app, &cookie, "/api/v2/admin/retention").await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["policies"].as_array().cloned().unwrap_or_default();
    let events_days = rows
        .iter()
        .find(|r| r["table_name"] == "events")
        .and_then(|r| r["retention_days"].as_i64())
        .unwrap_or_default();
    assert_eq!(events_days, 30);
}

#[tokio::test]
async fn test_import_events_batch() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let events: Vec<Value> = (0..50)
        .map(|idx| {
            json!({
                "ip": format!("10.40.1.{idx}"),
                "user": format!("batch-user-{idx}"),
                "source": "Manual",
                "mac": format!("AA:BB:CC:40:01:{:02X}", idx),
                "timestamp": Utc::now().to_rfc3339(),
                "raw_data": format!("batch event #{idx}")
            })
        })
        .collect();
    let (status, body) = auth_post(
        &app,
        &cookie,
        "/api/v2/import/events",
        &json!({ "events": events }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let imported = body["imported"].as_i64().unwrap_or(0);
    assert!(imported >= 48, "expected imported >= 48, got: {imported}, body: {body}");

    let (status, mappings) = auth_get(&app, &cookie, "/api/v1/mappings?search=10.40.1.1").await;
    assert_eq!(status, StatusCode::OK);
    let found = mappings["data"]
        .as_array()
        .map(|arr| arr.iter().any(|r| r["ip"] == "10.40.1.1"))
        .unwrap_or(false);
    assert!(found, "expected imported IP in mappings, got: {mappings}");
}

#[tokio::test]
async fn test_import_events_partial_failure() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let payload = json!({
        "events": [
            {"ip":"10.50.1.1","user":"ok-1","source":"Manual","raw_data":"ok"},
            {"ip":"10.50.1.2","user":"ok-2","source":"Manual","raw_data":"ok"},
            {"ip":"10.50.1.3","user":"ok-3","source":"Manual","raw_data":"ok"},
            {"ip":"999.999.1.1","user":"bad-1","source":"Manual","raw_data":"bad"},
            {"ip":"abc","user":"bad-2","source":"Manual","raw_data":"bad"}
        ]
    });
    let (status, body) = auth_post(&app, &cookie, "/api/v2/import/events", &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["imported"], json!(3));
    let err_count = body["errors"].as_array().map(|a| a.len()).unwrap_or(0);
    assert_eq!(err_count, 2, "expected 2 errors, got: {body}");
}

#[tokio::test]
async fn test_password_history_reuse() {
    let (app, _) = build_test_app().await;
    let admin_cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, created) = auth_post(
        &app,
        &admin_cookie,
        "/api/v1/users",
        &json!({
            "username": "pw_hist_user",
            "password": "PasswordA123!",
            "role": "Viewer"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let user_id = created["id"].as_i64().unwrap_or_default();

    let user_cookie = login_and_get_cookie(&app, "pw_hist_user", "PasswordA123!").await;
    let (status, _) = auth_post(
        &app,
        &user_cookie,
        "/api/auth/change-password",
        &json!({
            "current_password": "PasswordA123!",
            "new_password": "PasswordB123!"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let user_cookie = login_and_get_cookie(&app, "pw_hist_user", "PasswordB123!").await;
    let (status, body) = auth_post(
        &app,
        &user_cookie,
        "/api/auth/change-password",
        &json!({
            "current_password": "PasswordB123!",
            "new_password": "PasswordA123!"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap_or("").contains("last"),
        "expected history rejection message, got: {body}"
    );

    let _ = auth_delete(&app, &admin_cookie, &format!("/api/v1/users/{user_id}")).await;
}

#[tokio::test]
async fn test_session_absolute_timeout() {
    let (app, db) = build_test_app().await;
    let admin_cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, mut policy) =
        auth_get(&app, &admin_cookie, "/api/v2/admin/security/password-policy").await;
    assert_eq!(status, StatusCode::OK);
    let default_hours = policy["session_absolute_max_hours"].as_i64().unwrap_or(24).max(1);
    policy["session_absolute_max_hours"] = json!(0);
    let (status, _) = auth_put(
        &app,
        &admin_cookie,
        "/api/v2/admin/security/password-policy",
        &policy,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_get(&app, &cookie, "/api/auth/me").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    db.set_config("session_absolute_max_hours", &default_hours.to_string())
        .await
        .expect("restore session_absolute_max_hours failed");
}

#[tokio::test]
async fn test_ip_tag_prevents_duplicate() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/tags",
        &json!({
            "ip": "10.0.1.42",
            "tag": "server",
            "color": "#3b82f6"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/tags",
        &json!({
            "ip": "10.0.1.42",
            "tag": "server",
            "color": "#3b82f6"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_mapping_includes_geo_fields() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let event = IdentityEvent {
        source: SourceType::Manual,
        ip: "10.0.0.1".parse::<IpAddr>().expect("ip parse failed"),
        user: "geo_user".to_string(),
        timestamp: Utc::now(),
        raw_data: "geo mapping seed".to_string(),
        mac: Some("AA:BB:CC:00:00:01".to_string()),
        confidence_score: 100,
    };
    db.upsert_mapping(event, Some("TestVendor"))
        .await
        .expect("upsert mapping for geo field check failed");
    let (status, body) = auth_get(&app, &cookie, "/api/v1/mappings?search=10.0.0.1").await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["data"].as_array().cloned().unwrap_or_default();
    assert!(!rows.is_empty(), "expected mapping row, got: {body}");
    assert!(
        rows[0].get("country_code").is_some(),
        "country_code field missing in mapping payload: {body}"
    );
}
