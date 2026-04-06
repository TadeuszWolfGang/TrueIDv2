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
use std::fs;
use std::net::IpAddr;
use std::sync::{Arc, Once};
use tower::ServiceExt;
use tower_http::services::ServeDir;
use trueid_common::db::init_db;
use trueid_common::model::{IdentityEvent, SourceType, UserRole};
use trueid_web::{auth, build_router, rate_limit, AppState};
use urlencoding::encode;

/// Builds an isolated in-memory test app and seeds deterministic data.
///
/// Parameters: none.
/// Returns: `(Router, Arc<Db>)` ready for in-process requests.
async fn build_test_app() -> (Router, Arc<trueid_common::db::Db>) {
    build_test_app_with_settings("http://127.0.0.1:8080".to_string(), None).await
}

/// Builds a test app with static assets mounted like production server.
///
/// Parameters: none.
/// Returns: `(Router, Arc<Db>)` with static file serving enabled.
async fn build_test_app_with_static() -> (Router, Arc<trueid_common::db::Db>) {
    let (app, db) = build_test_app().await;
    let assets_dir = format!("{}/assets", env!("CARGO_MANIFEST_DIR"));
    (
        app.fallback_service(ServeDir::new(assets_dir).append_index_html_on_directories(true)),
        db,
    )
}

/// Builds an isolated in-memory test app with custom engine URL.
///
/// Parameters: `engine_url` - upstream engine base URL for proxy routes.
/// Returns: `(Router, Arc<Db>)` ready for in-process requests.
async fn build_test_app_with_engine_url(
    engine_url: String,
) -> (Router, Arc<trueid_common::db::Db>) {
    build_test_app_with_settings(engine_url, None).await
}

/// Builds an isolated in-memory test app with custom engine URL and optional metrics token.
///
/// Parameters: `engine_url` - upstream engine base URL for proxy routes,
/// `metrics_token` - optional static token for `/metrics`.
/// Returns: `(Router, Arc<Db>)` ready for in-process requests.
async fn build_test_app_with_settings(
    engine_url: String,
    metrics_token: Option<String>,
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
    let http_client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("build test http client failed");

    let state = AppState {
        db: Some(db.clone()),
        config: Arc::new(tokio::sync::RwLock::new(runtime_config)),
        engine_url,
        http_client,
        jwt_config: auth::JwtConfig::from_env(true),
        engine_service_token: None,
        metrics_token,
        login_limiter: Arc::new(rate_limit::RateLimiter::new(1000, 60)),
        per_key_limiter: Arc::new(rate_limit::PerKeyLimiter::new(1000, 1000)),
        session_limiter: Arc::new(rate_limit::PerKeyLimiter::new(1000, 1000)),
        auth_chain: Some(Arc::new(
            trueid_common::auth_provider::AuthProviderChain::default_chain(db.clone()),
        )),
    };
    (build_router(state), db)
}

/// Spawns a minimal mock engine metrics endpoint for proxy tests.
///
/// Parameters: none.
/// Returns: `(base_url, task_handle)` for the spawned mock server.
async fn spawn_mock_engine_metrics() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/engine/metrics",
        get(|| async {
            (
                StatusCode::OK,
                [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
                "trueid_active_mappings 7\n",
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
    auth_cookie_from_headers(resp.headers())
}

/// Collects auth cookies from Set-Cookie headers.
///
/// Parameters: `headers` - response headers containing Set-Cookie values.
/// Returns: combined Cookie header string with auth cookies.
fn auth_cookie_from_headers(headers: &HeaderMap) -> String {
    let mut parts = Vec::new();
    for value in &headers.get_all("set-cookie") {
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

/// Executes authenticated POST with JSON body and returns raw response.
///
/// Parameters: `app` - test router, `cookie` - cookie header string, `uri` - path, `body` - JSON payload.
/// Returns: `(status, headers, body_bytes)`.
async fn auth_post_raw(
    app: &Router,
    cookie: &str,
    uri: &str,
    body: &Value,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("cookie", cookie)
        .header("x-csrf-token", csrf_from_cookie(cookie))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(body).expect("serialize post body failed"),
        ))
        .expect("build auth_post_raw request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("auth_post_raw execution failed");
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect post raw body failed")
        .to_bytes()
        .to_vec();
    (status, headers, bytes)
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
        std::env::set_var("CONFIG_ENCRYPTION_KEY", "ab".repeat(32));
    });
}

/// Creates a test user and disables forced password change.
///
/// Parameters: `db` - initialized test DB, `username` - login, `password` - plain password, `role` - RBAC role.
/// Returns: none.
async fn create_test_user(
    db: &trueid_common::db::Db,
    username: &str,
    password: &str,
    role: UserRole,
) {
    let user = db
        .create_user(username, password, role)
        .await
        .expect("create test user failed");
    db.set_force_password_change(user.id, false)
        .await
        .expect("set_force_password_change failed");
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
async fn test_timeline_ip_cursor_pagination() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, first) = auth_get(&app, &cookie, "/api/v2/timeline/ip/10.1.2.3?limit=3").await;
    assert_eq!(status, StatusCode::OK);

    let first_events = first["events"]["data"]
        .as_array()
        .expect("first page events must be an array");
    assert_eq!(first_events.len(), 3);
    let next_cursor = first["events"]["next_cursor"]
        .as_str()
        .expect("first page must expose next_cursor");
    let first_ids: Vec<i64> = first_events
        .iter()
        .map(|row| row["id"].as_i64().expect("event id missing"))
        .collect();

    let uri = format!(
        "/api/v2/timeline/ip/10.1.2.3?limit=3&cursor={}",
        encode(next_cursor)
    );
    let (status, second) = auth_get(&app, &cookie, &uri).await;
    assert_eq!(status, StatusCode::OK);

    let second_events = second["events"]["data"]
        .as_array()
        .expect("second page events must be an array");
    assert_eq!(second_events.len(), 3);
    let second_ids: Vec<i64> = second_events
        .iter()
        .map(|row| row["id"].as_i64().expect("event id missing"))
        .collect();
    assert!(first_ids.iter().all(|id| !second_ids.contains(id)));
}

#[tokio::test]
async fn test_timeline_user_cursor_pagination() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, first) = auth_get(&app, &cookie, "/api/v2/timeline/user/jkowalski?limit=2").await;
    assert_eq!(status, StatusCode::OK);

    let first_events = first["events"]["data"]
        .as_array()
        .expect("first page events must be an array");
    assert_eq!(first_events.len(), 2);
    let next_cursor = first["events"]["next_cursor"]
        .as_str()
        .expect("first page must expose next_cursor");
    let first_ids: Vec<i64> = first_events
        .iter()
        .map(|row| row["id"].as_i64().expect("event id missing"))
        .collect();

    let uri = format!(
        "/api/v2/timeline/user/jkowalski?limit=2&cursor={}",
        encode(next_cursor)
    );
    let (status, second) = auth_get(&app, &cookie, &uri).await;
    assert_eq!(status, StatusCode::OK);

    let second_events = second["events"]["data"]
        .as_array()
        .expect("second page events must be an array");
    assert_eq!(second_events.len(), 2);
    let second_ids: Vec<i64> = second_events
        .iter()
        .map(|row| row["id"].as_i64().expect("event id missing"))
        .collect();
    assert!(first_ids.iter().all(|id| !second_ids.contains(id)));
}

#[tokio::test]
async fn test_timeline_mac_cursor_pagination() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let mac = "02:42:ac:11:00:55";

    for idx in 0..3 {
        let event = IdentityEvent {
            source: SourceType::Radius,
            ip: format!("172.16.0.{}", idx + 10)
                .parse::<IpAddr>()
                .expect("ip parse failed"),
            user: format!("macuser{idx}"),
            timestamp: Utc::now() - Duration::minutes(idx as i64),
            raw_data: format!("mac timeline event #{idx}"),
            mac: Some(mac.to_string()),
            confidence_score: 92,
        };
        db.upsert_mapping(event, Some("TestVendor"))
            .await
            .expect("upsert mac timeline seed failed");
    }

    let (status, first) = auth_get(
        &app,
        &cookie,
        &format!("/api/v2/timeline/mac/{mac}?limit=2"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let first_rows = first["current_mappings"]
        .as_array()
        .expect("first page rows must be an array");
    assert_eq!(first_rows.len(), 2);
    let next_cursor = first["current_mappings_next_cursor"]
        .as_str()
        .expect("first page must expose current_mappings_next_cursor");
    let first_pairs: Vec<(String, String)> = first_rows
        .iter()
        .map(|row| {
            (
                row["ip"].as_str().expect("ip missing").to_string(),
                row["user"].as_str().expect("user missing").to_string(),
            )
        })
        .collect();

    let uri = format!(
        "/api/v2/timeline/mac/{mac}?limit=2&cursor={}",
        encode(next_cursor)
    );
    let (status, second) = auth_get(&app, &cookie, &uri).await;
    assert_eq!(status, StatusCode::OK);

    let second_rows = second["current_mappings"]
        .as_array()
        .expect("second page rows must be an array");
    assert!(!second_rows.is_empty());
    let second_pairs: Vec<(String, String)> = second_rows
        .iter()
        .map(|row| {
            (
                row["ip"].as_str().expect("ip missing").to_string(),
                row["user"].as_str().expect("user missing").to_string(),
            )
        })
        .collect();
    assert!(first_pairs.iter().all(|pair| !second_pairs.contains(pair)));
}

#[tokio::test]
async fn test_timeline_ip_deprecated_page_fallback() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, first) =
        auth_get(&app, &cookie, "/api/v2/timeline/ip/10.1.2.3?limit=3&page=1").await;
    assert_eq!(status, StatusCode::OK);
    let (status, second) =
        auth_get(&app, &cookie, "/api/v2/timeline/ip/10.1.2.3?limit=3&page=2").await;
    assert_eq!(status, StatusCode::OK);

    let first_ids: Vec<i64> = first["events"]["data"]
        .as_array()
        .expect("first page events must be an array")
        .iter()
        .map(|row| row["id"].as_i64().expect("event id missing"))
        .collect();
    let second_ids: Vec<i64> = second["events"]["data"]
        .as_array()
        .expect("second page events must be an array")
        .iter()
        .map(|row| row["id"].as_i64().expect("event id missing"))
        .collect();

    assert_eq!(second["events"]["page"], 2);
    assert!(first_ids.iter().all(|id| !second_ids.contains(id)));
}

#[tokio::test]
async fn test_timeline_rejects_invalid_cursor() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, body) =
        auth_get(&app, &cookie, "/api/v2/timeline/ip/10.1.2.3?cursor=broken").await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");
}

#[tokio::test]
async fn test_timeline_rejects_excessive_deprecated_offset() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, body) = auth_get(
        &app,
        &cookie,
        "/api/v2/timeline/ip/10.1.2.3?page=500&limit=500",
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");
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
async fn test_export_mappings_json_truncated_at_max_rows() {
    let (app, db) = build_test_app().await;
    sqlx::query(
        "WITH digits(d) AS (
            VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)
         ),
         nums(n) AS (
            SELECT
                d0.d
                + 10 * d1.d
                + 100 * d2.d
                + 1000 * d3.d
                + 10000 * d4.d
            FROM digits d0
            CROSS JOIN digits d1
            CROSS JOIN digits d2
            CROSS JOIN digits d3
            CROSS JOIN digits d4
         )
         INSERT INTO mappings (ip, user, source, last_seen, confidence, is_active)
         SELECT
            printf('172.%d.%d.%d', (n / 65536) % 256, (n / 256) % 256, n % 256),
            printf('bulk-%05d', n),
            'Manual',
            datetime('now'),
            50,
            1
         FROM nums",
    )
    .execute(db.pool())
    .await
    .expect("bulk insert mappings failed");

    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, headers, body) =
        auth_get_raw(&app, &cookie, "/api/v2/export/mappings?format=json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get("x-trueid-truncated")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );

    let arr: Value = serde_json::from_slice(&body).expect("json parse failed");
    assert_eq!(arr.as_array().map(|a| a.len()).unwrap_or(0), 100_000);
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
async fn test_phase4_no_auth_rejected() {
    let (app, _) = build_test_app().await;
    for uri in [
        "/api/v2/timeline/ip/10.1.2.3",
        "/api/v2/timeline/user/jkowalski",
        "/api/v2/timeline/mac/AA:BB:CC:DD:EE:01",
        "/api/v2/conflicts",
        "/api/v2/conflicts/stats",
        "/api/v2/alerts/history",
        "/api/v2/alerts/stats",
    ] {
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .expect("build no-auth phase4 request failed");
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .expect("execute no-auth phase4 request failed");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "uri={uri}");
    }
}

#[tokio::test]
async fn test_conflicts_list_stats_and_resolve() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let unresolved_id = sqlx::query(
        "INSERT INTO conflicts (conflict_type, severity, ip, mac, user_old, user_new, source, details, detected_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-5 minutes'))",
    )
    .bind("duplicate_mac")
    .bind("critical")
    .bind("10.1.2.3")
    .bind("AA:BB:CC:DD:EE:01")
    .bind("jkowalski")
    .bind("asmith")
    .bind("Radius")
    .bind("{\"context\":\"lab\"}")
    .execute(db.pool())
    .await
    .expect("insert unresolved conflict failed")
    .last_insert_rowid();

    sqlx::query(
        "INSERT INTO conflicts (conflict_type, severity, ip, mac, user_old, user_new, source, details, detected_at, resolved_at, resolved_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-10 minutes'), datetime('now', '-1 minutes'), ?)",
    )
    .bind("user_flip")
    .bind("warning")
    .bind("10.1.2.4")
    .bind("AA:BB:CC:DD:EE:02")
    .bind("asmith")
    .bind("mjones")
    .bind("AdLog")
    .bind("{\"context\":\"resolved\"}")
    .bind("testadmin")
    .execute(db.pool())
    .await
    .expect("insert resolved conflict failed");

    let (status, list) = auth_get(
        &app,
        &cookie,
        "/api/v2/conflicts?type=duplicate_mac&ip=10.1.2.3",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["total"], 1);
    assert_eq!(list["data"][0]["conflict_type"], "duplicate_mac");
    assert_eq!(list["data"][0]["severity"], "critical");
    assert_eq!(list["data"][0]["resolved_at"], Value::Null);
    let listed_id = list["data"][0]["id"]
        .as_i64()
        .expect("conflict list must include row id");
    assert_eq!(listed_id, unresolved_id);

    let (status, stats) = auth_get(&app, &cookie, "/api/v2/conflicts/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stats["total_unresolved"], 1);
    assert_eq!(stats["by_type"]["duplicate_mac"], 1);
    assert_eq!(stats["by_severity"]["critical"], 1);

    let (status, resolved) = auth_post(
        &app,
        &cookie,
        &format!("/api/v2/conflicts/{unresolved_id}/resolve"),
        &json!({"note": "validated in API test"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "resolve body: {resolved}");
    assert_eq!(resolved["id"], unresolved_id);
    assert_eq!(resolved["resolved_by"], "testadmin");
    let details = resolved["details"]
        .as_str()
        .expect("resolved details must be a string");
    let details_json: Value =
        serde_json::from_str(details).expect("resolved details must be valid JSON");
    assert_eq!(details_json["resolution_note"], "validated in API test");

    let (status, after) = auth_get(&app, &cookie, "/api/v2/conflicts/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(after["total_unresolved"], 0);

    let (status, resolved_list) = auth_get(
        &app,
        &cookie,
        "/api/v2/conflicts?resolved=true&type=duplicate_mac&ip=10.1.2.3",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resolved_list["total"], 1);
    assert_eq!(resolved_list["data"][0]["id"], unresolved_id);
    assert_eq!(resolved_list["data"][0]["resolved_by"], "testadmin");
}

#[tokio::test]
async fn test_conflict_resolve_404_409_and_preserve_invalid_details() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, missing) = auth_post(
        &app,
        &cookie,
        "/api/v2/conflicts/999999/resolve",
        &json!({"note": "missing conflict"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(missing["code"], "NOT_FOUND");

    let conflict_id = sqlx::query(
        "INSERT INTO conflicts (conflict_type, severity, ip, mac, user_old, user_new, source, details)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("user_flip")
    .bind("warning")
    .bind("10.9.9.9")
    .bind("AA:BB:CC:DD:EE:99")
    .bind("alice")
    .bind("bob")
    .bind("Radius")
    .bind("not-json-details")
    .execute(db.pool())
    .await
    .expect("insert invalid-details conflict failed")
    .last_insert_rowid();

    let (status, resolved) = auth_post(
        &app,
        &cookie,
        &format!("/api/v2/conflicts/{conflict_id}/resolve"),
        &json!({"note": "preserve invalid details"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "resolve body: {resolved}");
    let details = resolved["details"]
        .as_str()
        .expect("resolved details must be a string");
    let details_json: Value =
        serde_json::from_str(details).expect("resolved details must remain valid JSON");
    assert_eq!(details_json["previous_details_raw"], "not-json-details");
    assert_eq!(details_json["resolution_note"], "preserve invalid details");

    let (status, conflict) = auth_post(
        &app,
        &cookie,
        &format!("/api/v2/conflicts/{conflict_id}/resolve"),
        &json!({"note": "second resolve"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(conflict["code"], "CONFLICT");
}

#[tokio::test]
async fn test_conflicts_cursor_pagination() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    for idx in 0..5 {
        let offset_minutes = 10 - idx;
        sqlx::query(
            "INSERT INTO conflicts (conflict_type, severity, ip, mac, user_old, user_new, source, details, detected_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', ?))",
        )
        .bind("duplicate_mac")
        .bind("warning")
        .bind("10.77.0.1")
        .bind(format!("AA:BB:CC:DD:EE:{idx:02X}"))
        .bind(format!("old{idx}"))
        .bind(format!("new{idx}"))
        .bind("Radius")
        .bind(format!("{{\"seq\":{idx}}}"))
        .bind(format!("-{offset_minutes} minutes"))
        .execute(db.pool())
        .await
        .expect("insert paginated conflict failed");
    }

    let (status, first) = auth_get(&app, &cookie, "/api/v2/conflicts?ip=10.77.0.1&limit=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["page"], 1);

    let first_rows = first["data"]
        .as_array()
        .expect("first conflicts page must be an array");
    assert_eq!(first_rows.len(), 2);
    let next_cursor = first["next_cursor"]
        .as_str()
        .expect("first conflicts page must expose next_cursor");
    let first_ids: Vec<i64> = first_rows
        .iter()
        .map(|row| row["id"].as_i64().expect("conflict id missing"))
        .collect();

    let uri = format!(
        "/api/v2/conflicts?ip=10.77.0.1&limit=2&cursor={}",
        encode(next_cursor)
    );
    let (status, second) = auth_get(&app, &cookie, &uri).await;
    assert_eq!(status, StatusCode::OK);

    let second_rows = second["data"]
        .as_array()
        .expect("second conflicts page must be an array");
    assert_eq!(second_rows.len(), 2);
    let second_ids: Vec<i64> = second_rows
        .iter()
        .map(|row| row["id"].as_i64().expect("conflict id missing"))
        .collect();
    assert!(first_ids.iter().all(|id| !second_ids.contains(id)));
}

#[tokio::test]
async fn test_conflicts_deprecated_page_fallback() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    for idx in 0..4 {
        let offset_minutes = 20 - idx;
        sqlx::query(
            "INSERT INTO conflicts (conflict_type, severity, ip, mac, user_old, user_new, source, details, detected_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', ?))",
        )
        .bind("user_flip")
        .bind("critical")
        .bind("10.88.0.8")
        .bind(format!("FF:EE:DD:CC:BB:{idx:02X}"))
        .bind(format!("alpha{idx}"))
        .bind(format!("beta{idx}"))
        .bind("AdLog")
        .bind(format!("{{\"page\":{idx}}}"))
        .bind(format!("-{offset_minutes} minutes"))
        .execute(db.pool())
        .await
        .expect("insert deprecated-page conflict failed");
    }

    let (status, first) = auth_get(
        &app,
        &cookie,
        "/api/v2/conflicts?ip=10.88.0.8&limit=2&page=1",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, second) = auth_get(
        &app,
        &cookie,
        "/api/v2/conflicts?ip=10.88.0.8&limit=2&page=2",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let first_ids: Vec<i64> = first["data"]
        .as_array()
        .expect("first conflicts page must be an array")
        .iter()
        .map(|row| row["id"].as_i64().expect("conflict id missing"))
        .collect();
    let second_ids: Vec<i64> = second["data"]
        .as_array()
        .expect("second conflicts page must be an array")
        .iter()
        .map(|row| row["id"].as_i64().expect("conflict id missing"))
        .collect();

    assert_eq!(second["page"], 2);
    assert!(first_ids.iter().all(|id| !second_ids.contains(id)));
}

#[tokio::test]
async fn test_conflicts_reject_invalid_cursor() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, body) = auth_get(&app, &cookie, "/api/v2/conflicts?cursor=broken").await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");
}

#[tokio::test]
async fn test_conflicts_reject_excessive_deprecated_offset() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, body) = auth_get(&app, &cookie, "/api/v2/conflicts?page=500&limit=200").await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");
}

#[tokio::test]
async fn test_alerts_list_stats_and_history() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "history-rule",
            "rule_type": "user_change",
            "severity": "critical",
            "enabled": true,
            "action_log": true,
            "cooldown_seconds": 300
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let rule_id = created["id"].as_i64().expect("rule id missing");

    sqlx::query(
        "INSERT INTO alert_history (
            rule_id, rule_name, rule_type, severity, ip, mac, user_name, source, details, webhook_status, webhook_response, fired_at
         ) VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-5 minutes')),
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-2 minutes'))",
    )
    .bind(rule_id)
    .bind("history-rule")
    .bind("user_change")
    .bind("critical")
    .bind("10.1.2.3")
    .bind("AA:BB:CC:DD:EE:01")
    .bind("jkowalski")
    .bind("Radius")
    .bind("{\"kind\":\"critical\"}")
    .bind("sent")
    .bind("200 OK")
    .bind(rule_id)
    .bind("history-rule")
    .bind("user_change")
    .bind("warning")
    .bind("10.1.2.4")
    .bind("AA:BB:CC:DD:EE:02")
    .bind("asmith")
    .bind("AdLog")
    .bind("{\"kind\":\"warning\"}")
    .bind("failed")
    .bind("500")
    .execute(db.pool())
    .await
    .expect("insert alert history failed");

    let (status, rules) = auth_get(&app, &cookie, "/api/v2/alerts/rules").await;
    assert_eq!(status, StatusCode::OK);
    let rule_rows = rules["rules"]
        .as_array()
        .expect("rules response must contain an array");
    assert!(
        rule_rows
            .iter()
            .any(|row| row["id"].as_i64() == Some(rule_id)),
        "expected created rule in list: {rules}"
    );

    let (status, history) = auth_get(
        &app,
        &cookie,
        "/api/v2/alerts/history?severity=critical&ip=10.1.2.3",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(history["total"], 1);
    assert_eq!(history["data"][0]["rule_id"], rule_id);
    assert_eq!(history["data"][0]["webhook_status"], "sent");

    let (status, stats) = auth_get(&app, &cookie, "/api/v2/alerts/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stats["total_rules"], 1);
    assert_eq!(stats["enabled_rules"], 1);
    assert_eq!(stats["total_fired_24h"], 2);
    assert_eq!(stats["by_severity_24h"]["critical"], 1);
    assert_eq!(stats["by_severity_24h"]["warning"], 1);
    assert_eq!(stats["by_type_24h"]["user_change"], 2);
    assert!(
        (stats["webhook_success_rate_24h"]
            .as_f64()
            .expect("webhook_success_rate_24h missing")
            - 0.5)
            .abs()
            < f64::EPSILON
    );
}

#[tokio::test]
async fn test_alert_history_cursor_pagination() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "cursor-history-rule",
            "rule_type": "new_mac",
            "severity": "warning",
            "action_log": true,
            "cooldown_seconds": 60
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let rule_id = created["id"].as_i64().expect("rule id missing");

    for idx in 0..5 {
        let offset_minutes = 10 - idx;
        sqlx::query(
            "INSERT INTO alert_history (
                rule_id, rule_name, rule_type, severity, ip, mac, user_name, source, details, webhook_status, webhook_response, fired_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', ?))",
        )
        .bind(rule_id)
        .bind("cursor-history-rule")
        .bind("new_mac")
        .bind("warning")
        .bind("10.55.0.5")
        .bind(format!("AA:55:00:00:00:{idx:02X}"))
        .bind(format!("cursor_user_{idx}"))
        .bind("Radius")
        .bind(format!("{{\"seq\":{idx}}}"))
        .bind("sent")
        .bind("200")
        .bind(format!("-{offset_minutes} minutes"))
        .execute(db.pool())
        .await
        .expect("insert alert history page seed failed");
    }

    let (status, first) =
        auth_get(&app, &cookie, "/api/v2/alerts/history?ip=10.55.0.5&limit=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["page"], 1);

    let first_rows = first["data"]
        .as_array()
        .expect("first alert history page must be an array");
    assert_eq!(first_rows.len(), 2);
    let next_cursor = first["next_cursor"]
        .as_str()
        .expect("first alert history page must expose next_cursor");
    let first_ids: Vec<i64> = first_rows
        .iter()
        .map(|row| row["id"].as_i64().expect("alert history id missing"))
        .collect();

    let uri = format!(
        "/api/v2/alerts/history?ip=10.55.0.5&limit=2&cursor={}",
        encode(next_cursor)
    );
    let (status, second) = auth_get(&app, &cookie, &uri).await;
    assert_eq!(status, StatusCode::OK);

    let second_rows = second["data"]
        .as_array()
        .expect("second alert history page must be an array");
    assert_eq!(second_rows.len(), 2);
    let second_ids: Vec<i64> = second_rows
        .iter()
        .map(|row| row["id"].as_i64().expect("alert history id missing"))
        .collect();
    assert!(first_ids.iter().all(|id| !second_ids.contains(id)));
}

#[tokio::test]
async fn test_alert_history_deprecated_page_fallback() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "deprecated-history-rule",
            "rule_type": "ip_conflict",
            "severity": "critical",
            "action_log": true,
            "cooldown_seconds": 120
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let rule_id = created["id"].as_i64().expect("rule id missing");

    for idx in 0..4 {
        let offset_minutes = 20 - idx;
        sqlx::query(
            "INSERT INTO alert_history (
                rule_id, rule_name, rule_type, severity, ip, mac, user_name, source, details, webhook_status, webhook_response, fired_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', ?))",
        )
        .bind(rule_id)
        .bind("deprecated-history-rule")
        .bind("ip_conflict")
        .bind("critical")
        .bind("10.56.0.6")
        .bind(format!("AA:56:00:00:00:{idx:02X}"))
        .bind(format!("deprecated_user_{idx}"))
        .bind("AdLog")
        .bind(format!("{{\"page\":{idx}}}"))
        .bind("failed")
        .bind("500")
        .bind(format!("-{offset_minutes} minutes"))
        .execute(db.pool())
        .await
        .expect("insert deprecated-page alert history failed");
    }

    let (status, first) = auth_get(
        &app,
        &cookie,
        "/api/v2/alerts/history?ip=10.56.0.6&limit=2&page=1",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, second) = auth_get(
        &app,
        &cookie,
        "/api/v2/alerts/history?ip=10.56.0.6&limit=2&page=2",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let first_ids: Vec<i64> = first["data"]
        .as_array()
        .expect("first alert history page must be an array")
        .iter()
        .map(|row| row["id"].as_i64().expect("alert history id missing"))
        .collect();
    let second_ids: Vec<i64> = second["data"]
        .as_array()
        .expect("second alert history page must be an array")
        .iter()
        .map(|row| row["id"].as_i64().expect("alert history id missing"))
        .collect();

    assert_eq!(second["page"], 2);
    assert!(first_ids.iter().all(|id| !second_ids.contains(id)));
}

#[tokio::test]
async fn test_alert_history_reject_invalid_cursor() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, body) = auth_get(&app, &cookie, "/api/v2/alerts/history?cursor=broken").await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");
}

#[tokio::test]
async fn test_alert_history_reject_excessive_deprecated_offset() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, body) = auth_get(&app, &cookie, "/api/v2/alerts/history?page=500&limit=200").await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");
}

#[tokio::test]
async fn test_alert_rule_update_delete_and_validation() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "crud-alert-rule",
            "rule_type": "new_mac",
            "severity": "warning",
            "action_log": true,
            "cooldown_seconds": 120
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let rule_id = created["id"].as_i64().expect("rule id missing");

    let (status, updated) = auth_put(
        &app,
        &cookie,
        &format!("/api/v2/alerts/rules/{rule_id}"),
        &json!({
            "name": "crud-alert-rule-updated",
            "severity": "critical",
            "cooldown_seconds": 600,
            "enabled": false
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update body: {updated}");
    assert_eq!(updated["name"], "crud-alert-rule-updated");
    assert_eq!(updated["severity"], "critical");
    assert_eq!(updated["cooldown_seconds"], 600);
    assert_eq!(updated["enabled"], false);

    let (status, invalid_rule_type) = auth_put(
        &app,
        &cookie,
        &format!("/api/v2/alerts/rules/{rule_id}"),
        &json!({"rule_type": "nonexistent"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid_rule_type["code"], "INVALID_INPUT");

    let (status, invalid_cooldown) = auth_put(
        &app,
        &cookie,
        &format!("/api/v2/alerts/rules/{rule_id}"),
        &json!({"cooldown_seconds": 90001}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid_cooldown["code"], "INVALID_INPUT");

    let (status, invalid_create_type) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "invalid-type-rule",
            "rule_type": "totally_invalid",
            "severity": "warning",
            "action_log": true,
            "cooldown_seconds": 60
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid_create_type["code"], "INVALID_INPUT");

    let (status, invalid_create_cooldown) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "invalid-cooldown-rule",
            "rule_type": "new_subnet",
            "severity": "warning",
            "action_log": true,
            "cooldown_seconds": -1
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid_create_cooldown["code"], "INVALID_INPUT");

    let (status, rules) = auth_get(&app, &cookie, "/api/v2/alerts/rules").await;
    assert_eq!(status, StatusCode::OK);
    let rule_rows = rules["rules"]
        .as_array()
        .expect("rules response must contain an array");
    assert!(
        rule_rows.iter().any(|row| {
            row["id"].as_i64() == Some(rule_id)
                && row["name"] == "crud-alert-rule-updated"
                && row["severity"] == "critical"
        }),
        "expected updated rule in list: {rules}"
    );

    let (status, _) = auth_delete(&app, &cookie, &format!("/api/v2/alerts/rules/{rule_id}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, after_delete) = auth_get(&app, &cookie, "/api/v2/alerts/rules").await;
    assert_eq!(status, StatusCode::OK);
    let rows_after_delete = after_delete["rules"]
        .as_array()
        .expect("rules response must contain an array");
    assert!(
        rows_after_delete
            .iter()
            .all(|row| row["id"].as_i64() != Some(rule_id)),
        "deleted rule should not be listed: {after_delete}"
    );
}

#[tokio::test]
async fn test_source_down_rule_conditions_validation_and_normalization() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "source-down-default",
            "rule_type": "source_down",
            "severity": "critical",
            "conditions": "{\"source\":\"AD TLS\"}",
            "action_log": true,
            "cooldown_seconds": 300
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create body: {created}");
    assert_eq!(
        serde_json::from_str::<Value>(created["conditions"].as_str().unwrap()).unwrap(),
        json!({"source":"AD TLS","silence_seconds":300})
    );
    let rule_id = created["id"].as_i64().expect("rule id missing");

    let (status, updated) = auth_put(
        &app,
        &cookie,
        &format!("/api/v2/alerts/rules/{rule_id}"),
        &json!({
            "conditions": "{\"source\":\"DHCP TLS\",\"silence_seconds\":600}"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update body: {updated}");
    assert_eq!(
        serde_json::from_str::<Value>(updated["conditions"].as_str().unwrap()).unwrap(),
        json!({"source":"DHCP TLS","silence_seconds":600})
    );

    let (status, missing_conditions) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "source-down-missing",
            "rule_type": "source_down",
            "severity": "warning",
            "action_log": true,
            "cooldown_seconds": 300
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(missing_conditions["code"], "INVALID_INPUT");

    let (status, invalid_source) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "source-down-invalid-source",
            "rule_type": "source_down",
            "severity": "warning",
            "conditions": "{\"source\":\"Unknown Adapter\",\"silence_seconds\":300}",
            "action_log": true,
            "cooldown_seconds": 300
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid_source["code"], "INVALID_INPUT");

    let (status, invalid_silence) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "source-down-invalid-silence",
            "rule_type": "source_down",
            "severity": "warning",
            "conditions": "{\"source\":\"AD TLS\",\"silence_seconds\":30}",
            "action_log": true,
            "cooldown_seconds": 300
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid_silence["code"], "INVALID_INPUT");

    let (status, boundary_silence) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "source-down-boundary-silence",
            "rule_type": "source_down",
            "severity": "warning",
            "conditions": "{\"source\":\"AD TLS\",\"silence_seconds\":3600}",
            "action_log": true,
            "cooldown_seconds": 300
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "boundary body: {boundary_silence}"
    );

    let (status, invalid_high_silence) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "source-down-invalid-high-silence",
            "rule_type": "source_down",
            "severity": "warning",
            "conditions": "{\"source\":\"AD TLS\",\"silence_seconds\":3601}",
            "action_log": true,
            "cooldown_seconds": 300
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid_high_silence["code"], "INVALID_INPUT");

    let (status, unknown_field) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "source-down-unknown-field",
            "rule_type": "source_down",
            "severity": "warning",
            "conditions": "{\"source\":\"AD TLS\",\"silence_seconds\":300,\"extra_field\":true}",
            "action_log": true,
            "cooldown_seconds": 300
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(unknown_field["code"], "INVALID_INPUT");

    let (status, invalid_json) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "source-down-invalid-json",
            "rule_type": "source_down",
            "severity": "warning",
            "conditions": "not-json",
            "action_log": true,
            "cooldown_seconds": 300
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid_json["code"], "INVALID_INPUT");

    let (status, plain_rule) = auth_post(
        &app,
        &cookie,
        "/api/v2/alerts/rules",
        &json!({
            "name": "plain-rule",
            "rule_type": "new_mac",
            "severity": "warning",
            "action_log": true,
            "cooldown_seconds": 120
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let plain_rule_id = plain_rule["id"].as_i64().expect("plain rule id missing");

    let (status, switch_without_conditions) = auth_put(
        &app,
        &cookie,
        &format!("/api/v2/alerts/rules/{plain_rule_id}"),
        &json!({
            "rule_type": "source_down"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(switch_without_conditions["code"], "INVALID_INPUT");

    let (status, switched_away) = auth_put(
        &app,
        &cookie,
        &format!("/api/v2/alerts/rules/{rule_id}"),
        &json!({
            "rule_type": "new_mac"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "switch-away body: {switched_away}");
    assert!(
        switched_away["conditions"].is_null(),
        "switch-away body: {switched_away}"
    );
}

#[tokio::test]
async fn test_phase4_viewer_can_read_timeline_conflicts_and_alerts() {
    let (app, db) = build_test_app().await;
    create_test_user(
        db.as_ref(),
        "phase4_viewer",
        "testpassword123",
        UserRole::Viewer,
    )
    .await;

    sqlx::query(
        "INSERT INTO conflicts (conflict_type, severity, ip, mac, user_old, user_new, source, details)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("duplicate_mac")
    .bind("warning")
    .bind("10.1.2.3")
    .bind("AA:BB:CC:DD:EE:01")
    .bind("jkowalski")
    .bind("asmith")
    .bind("Radius")
    .bind("{\"context\":\"viewer-read\"}")
    .execute(db.pool())
    .await
    .expect("insert viewer conflict seed failed");

    let rule_id = sqlx::query(
        "INSERT INTO alert_rules (name, enabled, rule_type, severity, action_log, cooldown_seconds)
         VALUES (?, true, ?, ?, true, 300)",
    )
    .bind("viewer-read-rule")
    .bind("new_subnet")
    .bind("warning")
    .execute(db.pool())
    .await
    .expect("insert viewer alert rule failed")
    .last_insert_rowid();
    sqlx::query(
        "INSERT INTO alert_history (
            rule_id, rule_name, rule_type, severity, ip, user_name, source, webhook_status, fired_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-1 minutes'))",
    )
    .bind(rule_id)
    .bind("viewer-read-rule")
    .bind("new_subnet")
    .bind("warning")
    .bind("10.1.2.3")
    .bind("jkowalski")
    .bind("Radius")
    .bind("sent")
    .execute(db.pool())
    .await
    .expect("insert viewer alert history failed");

    let cookie = login_and_get_cookie(&app, "phase4_viewer", "testpassword123").await;

    for uri in [
        "/api/v2/timeline/ip/10.1.2.3",
        "/api/v2/timeline/user/jkowalski",
        "/api/v2/timeline/mac/AA:BB:CC:DD:EE:01",
        "/api/v2/conflicts",
        "/api/v2/conflicts/stats",
        "/api/v2/alerts/history",
        "/api/v2/alerts/stats",
    ] {
        let (status, _) = auth_get(&app, &cookie, uri).await;
        assert_eq!(status, StatusCode::OK, "viewer read uri={uri}");
    }
}

#[tokio::test]
async fn test_phase4_rbac_mutation_guards_for_conflicts_and_alerts() {
    let (app, db) = build_test_app().await;
    create_test_user(
        db.as_ref(),
        "phase4_operator",
        "testpassword123",
        UserRole::Operator,
    )
    .await;
    create_test_user(
        db.as_ref(),
        "phase4_viewer2",
        "testpassword123",
        UserRole::Viewer,
    )
    .await;

    let conflict_id = sqlx::query(
        "INSERT INTO conflicts (conflict_type, severity, ip, mac, user_old, user_new, source, details)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("duplicate_mac")
    .bind("critical")
    .bind("10.1.2.3")
    .bind("AA:BB:CC:DD:EE:01")
    .bind("jkowalski")
    .bind("asmith")
    .bind("Radius")
    .bind("{\"context\":\"rbac\"}")
    .execute(db.pool())
    .await
    .expect("insert rbac conflict failed")
    .last_insert_rowid();

    let admin_cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let operator_cookie = login_and_get_cookie(&app, "phase4_operator", "testpassword123").await;
    let viewer_cookie = login_and_get_cookie(&app, "phase4_viewer2", "testpassword123").await;

    let (status, me) = auth_get(&app, &operator_cookie, "/api/auth/me").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["user"]["username"], "phase4_operator");
    assert_eq!(me["user"]["role"], "Operator");

    let (status, _) = auth_get(&app, &viewer_cookie, "/api/v2/alerts/rules").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = auth_get(&app, &operator_cookie, "/api/v2/alerts/rules").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = auth_post(
        &app,
        &viewer_cookie,
        &format!("/api/v2/conflicts/{conflict_id}/resolve"),
        &json!({"note": "viewer should not resolve"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = auth_post(
        &app,
        &operator_cookie,
        &format!("/api/v2/conflicts/{conflict_id}/resolve"),
        &json!({"note": "operator resolves"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "operator resolve body: {body}");

    let rule_payload = json!({
        "name": "rbac-alert-rule",
        "rule_type": "new_mac",
        "severity": "warning",
        "action_log": true,
        "cooldown_seconds": 120
    });

    let (status, _) = auth_post(&app, &viewer_cookie, "/api/v2/alerts/rules", &rule_payload).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = auth_post(
        &app,
        &operator_cookie,
        "/api/v2/alerts/rules",
        &rule_payload,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, created) =
        auth_post(&app, &admin_cookie, "/api/v2/alerts/rules", &rule_payload).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["name"], "rbac-alert-rule");
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
async fn test_map_topology_structure() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/map/topology").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["subnets"].is_array());
    assert!(body["adapters"].is_array());
    assert!(body["stats"].is_object());
    assert!(body["stats"]["total_ips"].is_number());
}

#[tokio::test]
async fn test_map_flows() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/map/flows?minutes=30").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["flows"].is_array());
    assert_eq!(body["window_minutes"], json!(30));
}

#[tokio::test]
async fn test_report_schedule_crud() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (create_status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/reports/schedules",
        &json!({
            "name": "Weekly Ops Report",
            "report_type": "weekly",
            "schedule_cron": "0 8 * * 1",
            "enabled": true,
            "channel_ids": [],
            "include_sections": ["summary","conflicts","alerts"]
        }),
    )
    .await;
    assert_eq!(create_status, StatusCode::CREATED);
    let id = created["id"].as_i64().unwrap_or_default();
    assert!(id > 0);

    let (list_status, listed) = auth_get(&app, &cookie, "/api/v2/reports/schedules").await;
    assert_eq!(list_status, StatusCode::OK);
    let rows = listed["schedules"].as_array().cloned().unwrap_or_default();
    assert!(rows
        .iter()
        .any(|r| r["id"].as_i64().unwrap_or_default() == id));

    let (update_status, updated) = auth_put(
        &app,
        &cookie,
        &format!("/api/v2/reports/schedules/{id}"),
        &json!({
            "name": "Weekly Security Report",
            "report_type": "weekly",
            "schedule_cron": "0 8 * * 2",
            "enabled": false,
            "channel_ids": [],
            "include_sections": ["summary","compliance"]
        }),
    )
    .await;
    assert_eq!(update_status, StatusCode::OK);
    assert_eq!(updated["name"], "Weekly Security Report");
    assert_eq!(updated["enabled"], false);

    let (delete_status, _) =
        auth_delete(&app, &cookie, &format!("/api/v2/reports/schedules/{id}")).await;
    assert_eq!(delete_status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_report_schedule_send_now_no_channels() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (create_status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/reports/schedules",
        &json!({
            "name": "No Channels Report",
            "report_type": "daily",
            "schedule_cron": "0 8 * * 1",
            "enabled": true,
            "channel_ids": [],
            "include_sections": ["summary"]
        }),
    )
    .await;
    assert_eq!(create_status, StatusCode::CREATED);
    let id = created["id"].as_i64().unwrap_or_default();
    assert!(id > 0);

    let (send_status, body) = auth_post(
        &app,
        &cookie,
        &format!("/api/v2/reports/schedules/{id}/send-now"),
        &json!({}),
    )
    .await;
    assert_eq!(send_status, StatusCode::OK);
    assert_eq!(body["success"], true);
    assert_eq!(body["delivered"].as_i64().unwrap_or(-1), 0);
}

#[tokio::test]
async fn test_report_schedule_lifecycle() {
    ensure_test_encryption_key();
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (channel_status, channel_created) = auth_post(
        &app,
        &cookie,
        "/api/v2/notifications/channels",
        &json!({
            "name": "Schedule email",
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
    assert_eq!(channel_status, StatusCode::CREATED);
    let channel_id = channel_created["id"].as_i64().unwrap_or_default();
    assert!(channel_id > 0);

    let (create_status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/reports/schedules",
        &json!({
            "name": "Ops Daily",
            "report_type": "daily",
            "schedule_cron": "0 8 * * 1",
            "enabled": true,
            "channel_ids": [channel_id],
            "include_sections": ["summary","alerts"]
        }),
    )
    .await;
    assert_eq!(create_status, StatusCode::CREATED);
    let id = created["id"].as_i64().unwrap_or_default();
    assert!(id > 0);

    let (list_status, listed) = auth_get(&app, &cookie, "/api/v2/reports/schedules").await;
    assert_eq!(list_status, StatusCode::OK);
    let rows = listed["schedules"].as_array().cloned().unwrap_or_default();
    assert!(rows
        .iter()
        .any(|r| r["id"].as_i64().unwrap_or_default() == id));

    let (update_status, _) = auth_put(
        &app,
        &cookie,
        &format!("/api/v2/reports/schedules/{id}"),
        &json!({
            "name": "Ops Weekly",
            "report_type": "weekly",
            "schedule_cron": "0 8 * * 1",
            "enabled": true,
            "channel_ids": [channel_id],
            "include_sections": ["summary","conflicts","alerts"]
        }),
    )
    .await;
    assert_eq!(update_status, StatusCode::OK);

    let (delete_status, _) =
        auth_delete(&app, &cookie, &format!("/api/v2/reports/schedules/{id}")).await;
    assert_eq!(delete_status, StatusCode::NO_CONTENT);

    let (list_status, listed) = auth_get(&app, &cookie, "/api/v2/reports/schedules").await;
    assert_eq!(list_status, StatusCode::OK);
    let rows = listed["schedules"].as_array().cloned().unwrap_or_default();
    assert!(!rows
        .iter()
        .any(|r| r["id"].as_i64().unwrap_or_default() == id));
}

#[tokio::test]
async fn test_report_schedule_send_now() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (create_status, created) = auth_post(
        &app,
        &cookie,
        "/api/v2/reports/schedules",
        &json!({
            "name": "No channel send-now",
            "report_type": "daily",
            "schedule_cron": "0 8 * * 1",
            "enabled": true,
            "channel_ids": [],
            "include_sections": ["summary"]
        }),
    )
    .await;
    assert_eq!(create_status, StatusCode::CREATED);
    let id = created["id"].as_i64().unwrap_or_default();
    assert!(id > 0);
    let (status, body) = auth_post(
        &app,
        &cookie,
        &format!("/api/v2/reports/schedules/{id}/send-now"),
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["delivered"], json!(0));
}

#[tokio::test]
async fn test_report_schedule_validation() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/reports/schedules",
        &json!({
            "name": "Invalid type",
            "report_type": "invalid",
            "schedule_cron": "0 8 * * 1",
            "enabled": true,
            "channel_ids": [],
            "include_sections": ["summary"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = auth_post(
        &app,
        &cookie,
        "/api/v2/reports/schedules",
        &json!({
            "name": "",
            "report_type": "daily",
            "schedule_cron": "0 8 * * 1",
            "enabled": true,
            "channel_ids": [],
            "include_sections": ["summary"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
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
    let (status, _) = auth_put(
        &app,
        &cookie,
        "/api/v2/ldap/config",
        &json!({"search_filter":"(|(uid=*)"}),
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
async fn test_metrics_requires_auth_or_token() {
    let (app, _) = build_test_app().await;
    let req = Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(Body::empty())
        .expect("build metrics request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("execute metrics request failed");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_metrics_accepts_viewer_session() {
    let (engine_url, _handle) = spawn_mock_engine_metrics().await;
    let (app, db) = build_test_app_with_engine_url(engine_url).await;
    let viewer = db
        .create_user("metricsviewer", "testpassword123", UserRole::Viewer)
        .await
        .expect("create viewer failed");
    db.set_force_password_change(viewer.id, false)
        .await
        .expect("set_force_password_change failed");
    let cookie = login_and_get_cookie(&app, "metricsviewer", "testpassword123").await;
    let (status, headers, body) = auth_get_raw(&app, &cookie, "/metrics").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default(),
        "text/plain; version=0.0.4; charset=utf-8"
    );
    let text = String::from_utf8(body).expect("metrics body should be UTF-8");
    assert!(text.contains("trueid_active_mappings 7"));
}

#[tokio::test]
async fn test_metrics_accepts_static_token() {
    let (engine_url, _handle) = spawn_mock_engine_metrics().await;
    let (app, _) =
        build_test_app_with_settings(engine_url, Some("metrics-secret".to_string())).await;
    let req = Request::builder()
        .method("GET")
        .uri("/metrics?token=metrics-secret")
        .body(Body::empty())
        .expect("build metrics token request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("execute metrics token request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect metrics body failed")
        .to_bytes();
    let text = String::from_utf8(body.to_vec()).expect("metrics body should be UTF-8");
    assert!(text.contains("trueid_active_mappings 7"));
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
    let code = totp
        .generate_current()
        .expect("failed to generate current code");
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
    let code = totp
        .generate_current()
        .expect("failed to generate current code");
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
    assert!(
        rows.is_empty(),
        "expected empty discovered subnets, got: {body}"
    );
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
    assert!(
        ct.contains("text/event-stream"),
        "unexpected content-type: {ct}"
    );
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
    assert!(
        summary.contains("mail.example.com"),
        "summary missing host: {summary}"
    );
    assert!(
        !summary.contains("super-secret"),
        "summary leaked secret: {summary}"
    );

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
    assert!(
        summary.contains(":465"),
        "summary missing updated port: {summary}"
    );
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
        body.as_array().map(|a| a.is_empty()).unwrap_or(false),
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
    assert!(
        body["results"].is_array(),
        "expected results array, got: {body}"
    );
}

#[tokio::test]
async fn test_retention_stats() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/admin/retention/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["tables"].is_array(),
        "expected tables array, got: {body}"
    );
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
    assert!(
        imported >= 48,
        "expected imported >= 48, got: {imported}, body: {body}"
    );

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
async fn test_change_password_revokes_old_refresh_session() {
    let (app, db) = build_test_app().await;
    let admin_cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, created) = auth_post(
        &app,
        &admin_cookie,
        "/api/v1/users",
        &json!({
            "username": "pw_rotate_user",
            "password": "PasswordA123!",
            "role": "Viewer"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let user_id = created["id"].as_i64().unwrap_or_default();

    let old_cookie = login_and_get_cookie(&app, "pw_rotate_user", "PasswordA123!").await;
    let (status, _headers, _) = auth_post_raw(
        &app,
        &old_cookie,
        "/api/auth/change-password",
        &json!({
            "current_password": "PasswordA123!",
            "new_password": "PasswordB123!"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = auth_post(&app, &old_cookie, "/api/auth/refresh", &json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let new_cookie = login_and_get_cookie(&app, "pw_rotate_user", "PasswordB123!").await;
    let (status, me) = auth_get(&app, &new_cookie, "/api/auth/me").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["user"]["username"], json!("pw_rotate_user"));

    let _ = auth_delete(&app, &admin_cookie, &format!("/api/v1/users/{user_id}")).await;
    db.revoke_all_sessions(user_id)
        .await
        .expect("cleanup revoke sessions failed");
}

#[tokio::test]
async fn test_admin_reset_password_revokes_old_refresh_session() {
    let (app, _) = build_test_app().await;
    let admin_cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, created) = auth_post(
        &app,
        &admin_cookie,
        "/api/v1/users",
        &json!({
            "username": "reset_target",
            "password": "PasswordA123!",
            "role": "Viewer"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let user_id = created["id"].as_i64().unwrap_or_default();

    let old_cookie = login_and_get_cookie(&app, "reset_target", "PasswordA123!").await;
    let (status, _) = auth_post(
        &app,
        &admin_cookie,
        &format!("/api/v2/admin/users/{user_id}/reset-password"),
        &json!({
            "new_password": "PasswordB123!"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = auth_post(&app, &old_cookie, "/api/auth/refresh", &json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let new_cookie = login_and_get_cookie(&app, "reset_target", "PasswordB123!").await;
    let (status, me) = auth_get(&app, &new_cookie, "/api/auth/me").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["user"]["username"], json!("reset_target"));

    let _ = auth_delete(&app, &admin_cookie, &format!("/api/v1/users/{user_id}")).await;
}

#[tokio::test]
async fn test_session_absolute_timeout() {
    let (app, db) = build_test_app().await;
    let admin_cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, mut policy) = auth_get(
        &app,
        &admin_cookie,
        "/api/v2/admin/security/password-policy",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let default_hours = policy["session_absolute_max_hours"]
        .as_i64()
        .unwrap_or(24)
        .max(1);
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
async fn test_admin_totp_policy_blocks_privileged_routes_until_totp_enabled() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, mut policy) =
        auth_get(&app, &cookie, "/api/v2/admin/security/password-policy").await;
    assert_eq!(status, StatusCode::OK);
    policy["totp_required_for_admins"] = json!(true);
    let (status, _) = auth_put(
        &app,
        &cookie,
        "/api/v2/admin/security/password-policy",
        &policy,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = auth_get(&app, &cookie, "/api/v2/admin/security/sessions").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("TOTP setup required"),
        "expected admin TOTP policy error, got: {body}"
    );

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
    let code = totp
        .generate_current()
        .expect("failed to generate current code");
    let (status, _) = auth_post(
        &app,
        &cookie,
        "/api/auth/totp/verify",
        &json!({ "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = auth_get(&app, &cookie, "/api/v2/admin/security/sessions").await;
    assert_eq!(status, StatusCode::OK);
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

#[tokio::test]
async fn test_api_key_rate_limit_headers() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v1/api-keys",
        &json!({
            "description": "rate-limit-header-key",
            "role": "Viewer",
            "rate_limit_rpm": 200,
            "rate_limit_burst": 50
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let key = created["key"].as_str().unwrap_or_default().to_string();
    assert!(!key.is_empty(), "expected created API key in response");

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/mappings")
        .header("x-api-key", key)
        .body(Body::empty())
        .expect("build API key stats request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("execute API key stats request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().contains_key("x-ratelimit-limit"),
        "missing x-ratelimit-limit header"
    );
    assert!(
        resp.headers().contains_key("x-ratelimit-remaining"),
        "missing x-ratelimit-remaining header"
    );
    assert!(
        resp.headers().contains_key("x-ratelimit-reset"),
        "missing x-ratelimit-reset header"
    );
}

#[tokio::test]
async fn test_api_key_usage_tracking() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v1/api-keys",
        &json!({
            "description": "usage-tracking-key",
            "role": "Viewer",
            "rate_limit_rpm": 300,
            "rate_limit_burst": 80
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let key = created["key"].as_str().unwrap_or_default().to_string();
    let key_id = created["record"]["id"].as_i64().unwrap_or_default();
    assert!(key_id > 0, "expected record.id in create response");

    for _ in 0..3 {
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/mappings")
            .header("x-api-key", key.clone())
            .body(Body::empty())
            .expect("build API key request failed");
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .expect("execute API key request failed");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let (status, usage) = auth_get(
        &app,
        &cookie,
        &format!("/api/v2/api-keys/{key_id}/usage?days=7"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let total = usage["total_requests_7d"].as_i64().unwrap_or(0);
    assert!(
        total >= 3,
        "expected total_requests_7d >= 3, got {total}, body: {usage}"
    );
}

#[tokio::test]
async fn test_api_key_rate_limit_429() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v1/api-keys",
        &json!({
            "description": "tiny-limit-key",
            "role": "Viewer",
            "rate_limit_rpm": 1,
            "rate_limit_burst": 1
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let key = created["key"].as_str().unwrap_or_default().to_string();
    let mut seen_429 = false;
    for _ in 0..5 {
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/mappings")
            .header("x-api-key", key.clone())
            .body(Body::empty())
            .expect("build throttled API key request failed");
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .expect("execute throttled API key request failed");
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            seen_429 = true;
            break;
        }
    }
    assert!(seen_429, "expected at least one 429 response");
}

#[tokio::test]
async fn test_rate_limit_headers_present() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v1/api-keys",
        &json!({
            "description": "rate-limit-header-key-2",
            "role": "Viewer",
            "rate_limit_rpm": 200,
            "rate_limit_burst": 50
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let key = created["key"].as_str().unwrap_or_default().to_string();
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/mappings")
        .header("x-api-key", key)
        .body(Body::empty())
        .expect("build API key request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("execute request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("x-ratelimit-limit"));
    assert!(resp.headers().contains_key("x-ratelimit-remaining"));
}

#[tokio::test]
async fn test_rate_limit_usage_tracking() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v1/api-keys",
        &json!({
            "description": "usage-tracking-key-2",
            "role": "Viewer",
            "rate_limit_rpm": 300,
            "rate_limit_burst": 80
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let key = created["key"].as_str().unwrap_or_default().to_string();
    let key_id = created["record"]["id"].as_i64().unwrap_or_default();
    assert!(key_id > 0);
    for _ in 0..5 {
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/mappings")
            .header("x-api-key", key.clone())
            .body(Body::empty())
            .expect("build request failed");
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .expect("execute request failed");
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let (status, usage) = auth_get(
        &app,
        &cookie,
        &format!("/api/v2/api-keys/{key_id}/usage?days=1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let total = usage["total_requests_7d"].as_i64().unwrap_or(0);
    assert!(total >= 5, "expected at least 5 requests, got {total}");
}

#[tokio::test]
async fn test_rate_limit_429_enforcement() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, created) = auth_post(
        &app,
        &cookie,
        "/api/v1/api-keys",
        &json!({
            "description": "tiny-limit-key-2",
            "role": "Viewer",
            "rate_limit_rpm": 1,
            "rate_limit_burst": 1
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let key = created["key"].as_str().unwrap_or_default().to_string();
    let mut seen_429 = false;
    for _ in 0..10 {
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/mappings")
            .header("x-api-key", key.clone())
            .body(Body::empty())
            .expect("build request failed");
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .expect("execute request failed");
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            seen_429 = true;
            break;
        }
    }
    assert!(seen_429);
}

#[tokio::test]
async fn test_oidc_status_public() {
    let (app, _) = build_test_app().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/auth/oidc/status")
        .body(Body::empty())
        .expect("build oidc status request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("execute oidc status request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect oidc status body failed")
        .to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("parse oidc status json failed");
    assert_eq!(json["enabled"], json!(false));
}

#[tokio::test]
async fn test_oidc_config_default_disabled() {
    let (app, _) = build_test_app().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/auth/oidc/status")
        .body(Body::empty())
        .expect("build oidc status request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("execute oidc status request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect oidc status body failed")
        .to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("parse oidc status json failed");
    assert_eq!(json["enabled"], json!(false));
}

#[tokio::test]
async fn test_oidc_login_redirect_when_disabled() {
    let (app, _) = build_test_app().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/auth/oidc/login")
        .body(Body::empty())
        .expect("build oidc login request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("execute oidc login request failed");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_oidc_login_when_disabled() {
    let (app, _) = build_test_app().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/auth/oidc/login")
        .body(Body::empty())
        .expect("build oidc login request failed");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("execute oidc login request failed");
    assert!(resp.status() == StatusCode::BAD_REQUEST || resp.status().is_redirection());
}

#[tokio::test]
async fn test_oidc_config_crud() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, before) = auth_get(&app, &cookie, "/api/auth/oidc/config").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(before["enabled"], json!(false));

    let (status, _) = auth_put(
        &app,
        &cookie,
        "/api/auth/oidc/config",
        &json!({
            "enabled": false,
            "provider_name": "Azure AD",
            "issuer_url": "https://login.microsoftonline.com/test/v2.0",
            "client_id": "client-123",
            "client_secret": "super-secret",
            "redirect_uri": "https://trueid.example.com/api/auth/oidc/callback",
            "scopes": "openid profile email",
            "auto_create_users": true,
            "default_role": "Viewer",
            "role_claim": "groups",
            "role_mapping": "{\"grp-admin\":\"Admin\"}",
            "allow_local_login": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, after) = auth_get(&app, &cookie, "/api/auth/oidc/config").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(after["provider_name"], json!("Azure AD"));
    assert_eq!(
        after["issuer_url"],
        json!("https://login.microsoftonline.com/test/v2.0")
    );
    assert_eq!(after["client_id"], json!("client-123"));
    assert_eq!(after["enabled"], json!(false));
}

#[tokio::test]
async fn test_oidc_config_admin_crud() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, before) = auth_get(&app, &cookie, "/api/v2/admin/oidc/config").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(before["enabled"], json!(false));

    let (status, _) = auth_put(
        &app,
        &cookie,
        "/api/v2/admin/oidc/config",
        &json!({
            "enabled": false,
            "provider_name": "Azure AD",
            "issuer_url": "https://login.microsoftonline.com/test/v2.0",
            "client_id": "client-oidc-admin",
            "client_secret": "ultra-secret",
            "redirect_uri": "https://trueid.example.com/api/auth/oidc/callback",
            "scopes": "openid profile email",
            "auto_create_users": true,
            "default_role": "Viewer",
            "role_claim": "groups",
            "role_mapping": "{\"grp-admin\":\"Admin\"}",
            "allow_local_login": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, after) = auth_get(&app, &cookie, "/api/v2/admin/oidc/config").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        after["issuer_url"],
        json!("https://login.microsoftonline.com/test/v2.0")
    );
    assert_eq!(after["client_id"], json!("client-oidc-admin"));
    assert!(after.get("client_secret").is_none());
}

#[tokio::test]
async fn test_static_js_files_served() {
    let (app, _) = build_test_app_with_static().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (app_js_status, app_js_headers, _) = auth_get_raw(&app, &cookie, "/js/app.js").await;
    assert_eq!(app_js_status, StatusCode::OK);
    let app_js_ct = app_js_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(app_js_ct.contains("javascript"));
    let (utils_status, _, _) = auth_get_raw(&app, &cookie, "/js/utils.js").await;
    assert_eq!(utils_status, StatusCode::OK);
    let (missing_status, _, _) = auth_get_raw(&app, &cookie, "/js/nonexistent.js").await;
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_dashboard_html_has_css_vars() {
    let (app, _) = build_test_app_with_static().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _, body) = auth_get_raw(&app, &cookie, "/").await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(body).expect("dashboard html not utf8");
    assert!(html.contains("--green-bright"));
    assert!(html.contains("--bg-deep"));
}

#[tokio::test]
async fn test_login_page_has_matrix_canvas() {
    let (app, _) = build_test_app_with_static().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, _, body) = auth_get_raw(&app, &cookie, "/login.html").await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(body).expect("login html not utf8");
    assert!(html.contains("matrix-bg"));
}

// ── Phase 2: Rate limiting integration tests ──

/// Builds a test app with a strict login rate limit (2 requests / 60s).
async fn build_test_app_with_strict_rate_limit() -> (Router, Arc<trueid_common::db::Db>) {
    ensure_test_encryption_key();
    let db = Arc::new(init_db("sqlite::memory:").await.expect("init_db failed"));

    let user = db
        .create_user(
            "testadmin",
            "testpassword123",
            trueid_common::model::UserRole::Admin,
        )
        .await
        .expect("create_user failed");
    db.set_force_password_change(user.id, false)
        .await
        .expect("set_force_password_change failed");

    seed_test_data(&db).await;
    let runtime_config = trueid_common::app_config::AppConfig::load(db.as_ref()).await;
    let http_client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("build test http client failed");

    let state = AppState {
        db: Some(db.clone()),
        config: Arc::new(tokio::sync::RwLock::new(runtime_config)),
        engine_url: "http://127.0.0.1:8080".to_string(),
        http_client,
        jwt_config: auth::JwtConfig::from_env(true),
        engine_service_token: None,
        metrics_token: None,
        login_limiter: Arc::new(rate_limit::RateLimiter::new(2, 60)),
        per_key_limiter: Arc::new(rate_limit::PerKeyLimiter::new(1000, 1000)),
        session_limiter: Arc::new(rate_limit::PerKeyLimiter::new(1000, 1000)),
        auth_chain: Some(Arc::new(
            trueid_common::auth_provider::AuthProviderChain::default_chain(db.clone()),
        )),
    };
    (build_router(state), db)
}

fn login_request(forwarded_for: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .header("x-forwarded-for", forwarded_for)
        .body(Body::from(
            serde_json::to_string(&json!({
                "username": "testadmin",
                "password": "testpassword123"
            }))
            .expect("serialize login body"),
        ))
        .expect("build login request")
}

#[tokio::test]
async fn test_login_rate_limit_returns_429_after_exceeded() {
    let (app, _) = build_test_app_with_strict_rate_limit().await;

    // First 2 requests should succeed (limit = 2)
    let resp1 = app
        .clone()
        .oneshot(login_request("10.0.0.1"))
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK, "first login should succeed");

    let resp2 = app
        .clone()
        .oneshot(login_request("10.0.0.1"))
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "second login should succeed"
    );

    // Third request should be rate-limited
    let resp3 = app
        .clone()
        .oneshot(login_request("10.0.0.1"))
        .await
        .unwrap();
    assert_eq!(
        resp3.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "third login from same IP should be rate-limited"
    );

    // Verify retry-after header
    let retry_after = resp3
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(retry_after, "60");

    // Verify error body
    let bytes = resp3.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["code"], "RATE_LIMITED");
}

#[tokio::test]
async fn test_login_rate_limit_is_per_ip() {
    let (app, _) = build_test_app_with_strict_rate_limit().await;

    // Exhaust limit for 10.0.0.1
    let _ = app
        .clone()
        .oneshot(login_request("10.0.0.1"))
        .await
        .unwrap();
    let _ = app
        .clone()
        .oneshot(login_request("10.0.0.1"))
        .await
        .unwrap();
    let resp_limited = app
        .clone()
        .oneshot(login_request("10.0.0.1"))
        .await
        .unwrap();
    assert_eq!(resp_limited.status(), StatusCode::TOO_MANY_REQUESTS);

    // Different IP should still succeed
    let resp_other = app
        .clone()
        .oneshot(login_request("10.0.0.2"))
        .await
        .unwrap();
    assert_eq!(
        resp_other.status(),
        StatusCode::OK,
        "different IP should not be rate-limited"
    );
}

#[tokio::test]
async fn test_login_rate_limit_wrong_credentials_still_counts() {
    let (app, _) = build_test_app_with_strict_rate_limit().await;

    let bad_login = |ip: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .header("x-forwarded-for", ip)
            .body(Body::from(
                serde_json::to_string(&json!({
                    "username": "testadmin",
                    "password": "wrongpassword"
                }))
                .unwrap(),
            ))
            .unwrap()
    };

    // Failed logins still consume rate limit quota
    let _ = app.clone().oneshot(bad_login("10.0.0.3")).await.unwrap();
    let _ = app.clone().oneshot(bad_login("10.0.0.3")).await.unwrap();

    // Third attempt should be rate-limited even with correct password
    let resp = app
        .clone()
        .oneshot(login_request("10.0.0.3"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "failed logins should consume rate limit quota"
    );
}

// ── Phase 3: API contract tests ──

// ── 3a: Response schema contracts ──

#[tokio::test]
async fn test_contract_search_response_shape() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/search?q=jkowalski").await;
    assert_eq!(status, StatusCode::OK);

    // Required top-level fields
    assert!(body["page"].is_number(), "page must be a number");
    assert!(body["limit"].is_number(), "limit must be a number");
    assert!(
        body["query_time_ms"].is_number(),
        "query_time_ms must be present"
    );

    // Mappings section structure
    let mappings = &body["mappings"];
    assert!(
        mappings["data"].is_array(),
        "mappings.data must be an array"
    );
    assert!(
        mappings["total"].is_number(),
        "mappings.total must be a number"
    );

    // Mapping record required fields
    let m = &mappings["data"][0];
    assert!(m["ip"].is_string(), "mapping.ip must be a string");
    assert!(m["source"].is_string(), "mapping.source must be a string");
    assert!(
        m["last_seen"].is_string(),
        "mapping.last_seen must be a string"
    );
    assert!(
        m["confidence_score"].is_number(),
        "mapping.confidence_score must be a number"
    );
    assert!(
        m["is_active"].is_boolean(),
        "mapping.is_active must be a boolean"
    );
    assert!(
        m["current_users"].is_array(),
        "mapping.current_users must be an array"
    );

    // Events section structure
    let events = &body["events"];
    assert!(events["data"].is_array(), "events.data must be an array");
    assert!(events["total"].is_number(), "events.total must be a number");
    let e = &events["data"][0];
    assert!(e["id"].is_number(), "event.id must be a number");
    assert!(e["ip"].is_string(), "event.ip must be a string");
    assert!(e["user"].is_string(), "event.user must be a string");
    assert!(e["source"].is_string(), "event.source must be a string");
    assert!(
        e["timestamp"].is_string(),
        "event.timestamp must be a string"
    );
    assert!(e["raw_data"].is_string(), "event.raw_data must be a string");
}

#[tokio::test]
async fn test_contract_search_mappings_enrichment_fields() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;
    let (status, body) = auth_get(&app, &cookie, "/api/v2/search?ip=10.1.2.3&scope=mappings").await;
    assert_eq!(status, StatusCode::OK);

    let m = &body["mappings"]["data"][0];
    for field in &[
        "vendor",
        "subnet_id",
        "subnet_name",
        "hostname",
        "device_type",
        "multi_user",
        "groups",
        "country_code",
        "city",
        "tags",
    ] {
        assert!(
            !m[field].is_null() || m.get(field).is_some(),
            "enrichment field '{}' must be present in mapping response",
            field
        );
    }
}

#[tokio::test]
async fn test_contract_conflicts_response_shape() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    // Seed a conflict
    sqlx::query(
        "INSERT INTO conflicts (conflict_type, severity, ip, user_old, user_new, source, detected_at)
         VALUES ('ip_user_change', 'warning', '10.1.2.3', 'alice', 'bob', 'Radius', datetime('now'))",
    )
    .execute(db.pool())
    .await
    .unwrap();

    let (status, body) = auth_get(&app, &cookie, "/api/v2/conflicts").await;
    assert_eq!(status, StatusCode::OK);

    // Paginated response envelope
    assert!(body["data"].is_array());
    assert!(body["total"].is_number());
    assert!(body["page"].is_number());
    assert!(body["limit"].is_number());
    assert!(body["total_pages"].is_number());
    // next_cursor may be null or string
    assert!(body["next_cursor"].is_null() || body["next_cursor"].is_string());

    // Conflict record fields
    let c = &body["data"][0];
    assert!(c["id"].is_number());
    assert!(c["conflict_type"].is_string());
    assert!(c["severity"].is_string());
    assert!(c["detected_at"].is_string());
    assert!(c["source"].is_string());
}

#[tokio::test]
async fn test_contract_alerts_history_response_shape() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    // Seed alert rule + history
    sqlx::query(
        "INSERT INTO alert_rules (id, name, enabled, rule_type, severity, action_log, cooldown_seconds)
         VALUES (1, 'test-rule', 1, 'new_mac', 'warning', 1, 300)",
    )
    .execute(db.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO alert_history (rule_id, rule_name, rule_type, severity, ip, user_name, source, details, webhook_status)
         VALUES (1, 'test-rule', 'new_mac', 'warning', '10.1.2.3', 'alice', 'Radius', '{}', 'no_webhook')",
    )
    .execute(db.pool())
    .await
    .unwrap();

    let (status, body) = auth_get(&app, &cookie, "/api/v2/alerts/history").await;
    assert_eq!(status, StatusCode::OK);

    assert!(body["data"].is_array());
    assert!(body["total"].is_number());
    assert!(body["next_cursor"].is_null() || body["next_cursor"].is_string());

    let h = &body["data"][0];
    assert!(h["id"].is_number());
    assert!(h["rule_id"].is_number());
    assert!(h["rule_name"].is_string());
    assert!(h["rule_type"].is_string());
    assert!(h["severity"].is_string());
    assert!(h["fired_at"].is_string());
}

#[tokio::test]
async fn test_contract_alerts_stats_shape() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, body) = auth_get(&app, &cookie, "/api/v2/alerts/stats").await;
    assert_eq!(status, StatusCode::OK);

    assert!(body["total_rules"].is_number());
    assert!(body["enabled_rules"].is_number());
    assert!(body["total_fired_24h"].is_number());
    assert!(body["by_severity_24h"].is_object());
    assert!(body["by_type_24h"].is_object());
    assert!(body["webhook_success_rate_24h"].is_number());
}

#[tokio::test]
async fn test_contract_timeline_ip_response_shape() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, body) = auth_get(&app, &cookie, "/api/v2/timeline/ip/10.1.2.3").await;
    assert_eq!(status, StatusCode::OK);

    assert!(body["ip"].is_string());
    assert!(body["current_mapping"].is_object());
    assert!(body["events"]["data"].is_array());
    assert!(body["events"]["total"].is_number());
    assert!(body["events"]["next_cursor"].is_null() || body["events"]["next_cursor"].is_string());
    assert!(body["user_changes"].is_array());
    assert!(body["conflicts_count"].is_number());

    let cm = &body["current_mapping"];
    assert!(cm["user"].is_string());
    assert!(cm["source"].is_string());
    assert!(cm["last_seen"].is_string());
    assert!(cm["is_active"].is_boolean());
}

#[tokio::test]
async fn test_contract_timeline_user_response_shape() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, body) = auth_get(&app, &cookie, "/api/v2/timeline/user/jkowalski").await;
    assert_eq!(status, StatusCode::OK);

    assert!(body["user"].is_string());
    assert!(body["active_mappings"].is_array());
    assert!(body["events"]["data"].is_array());
    assert!(body["ip_addresses_used"].is_array());
}

#[tokio::test]
async fn test_contract_timeline_mac_response_shape() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, body) = auth_get(
        &app,
        &cookie,
        &format!("/api/v2/timeline/mac/{}", encode("AA:BB:CC:DD:EE:01")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert!(body["mac"].is_string());
    assert!(body["current_mappings"].is_array());
    assert!(body["ip_history"].is_array());
}

// ── 3b: Cursor pagination contracts ──

#[tokio::test]
async fn test_contract_cursor_pagination_chaining_conflicts() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    // Seed 5 conflicts to test cursor chaining
    for i in 0..5 {
        sqlx::query(
            "INSERT INTO conflicts (conflict_type, severity, ip, user_old, user_new, source, detected_at)
             VALUES ('ip_user_change', 'warning', ?, ?, ?, 'Radius', datetime('now', ? || ' seconds'))",
        )
        .bind(format!("10.0.0.{}", i + 1))
        .bind(format!("old-user-{i}"))
        .bind(format!("new-user-{i}"))
        .bind(format!("-{}", 300 - i * 10))
        .execute(db.pool())
        .await
        .unwrap();
    }

    // Page 1: limit=2
    let (s1, p1) = auth_get(&app, &cookie, "/api/v2/conflicts?limit=2").await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(p1["data"].as_array().unwrap().len(), 2);
    assert!(p1["total"].as_i64().unwrap() >= 5);
    let cursor1 = p1["next_cursor"]
        .as_str()
        .expect("first page should have next_cursor");

    // Page 2: use cursor from page 1
    let (s2, p2) = auth_get(
        &app,
        &cookie,
        &format!("/api/v2/conflicts?limit=2&cursor={cursor1}"),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(p2["data"].as_array().unwrap().len(), 2);

    // No overlap between pages
    let ids1: Vec<i64> = p1["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_i64().unwrap())
        .collect();
    let ids2: Vec<i64> = p2["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_i64().unwrap())
        .collect();
    assert!(
        ids1.iter().all(|id| !ids2.contains(id)),
        "cursor pages must not overlap: {:?} vs {:?}",
        ids1,
        ids2
    );
}

#[tokio::test]
async fn test_contract_cursor_pagination_chaining_alerts() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    sqlx::query(
        "INSERT INTO alert_rules (id, name, enabled, rule_type, severity, action_log, cooldown_seconds)
         VALUES (1, 'test-rule', 1, 'new_mac', 'warning', 1, 300)",
    )
    .execute(db.pool())
    .await
    .unwrap();

    for i in 0..5 {
        sqlx::query(
            "INSERT INTO alert_history (rule_id, rule_name, rule_type, severity, ip, source, details, webhook_status, fired_at)
             VALUES (1, 'test-rule', 'new_mac', 'warning', ?, 'Radius', '{}', 'sent', datetime('now', ? || ' seconds'))",
        )
        .bind(format!("10.0.0.{}", i + 1))
        .bind(format!("-{}", 300 - i * 10))
        .execute(db.pool())
        .await
        .unwrap();
    }

    let (s1, p1) = auth_get(&app, &cookie, "/api/v2/alerts/history?limit=2").await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(p1["data"].as_array().unwrap().len(), 2);
    let cursor = p1["next_cursor"].as_str().expect("should have cursor");

    let (s2, p2) = auth_get(
        &app,
        &cookie,
        &format!("/api/v2/alerts/history?limit=2&cursor={cursor}"),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(p2["data"].as_array().unwrap().len(), 2);

    // Verify ordering: DESC by fired_at
    let ts1 = p1["data"][0]["fired_at"].as_str().unwrap();
    let ts2 = p1["data"][1]["fired_at"].as_str().unwrap();
    assert!(ts1 >= ts2, "alerts must be ordered DESC by fired_at");
}

#[tokio::test]
async fn test_contract_cursor_is_opaque_token() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    for i in 0..3 {
        sqlx::query(
            "INSERT INTO conflicts (conflict_type, severity, ip, source, detected_at)
             VALUES ('ip_user_change', 'warning', ?, 'Radius', datetime('now', ? || ' seconds'))",
        )
        .bind(format!("10.0.0.{}", i + 1))
        .bind(format!("-{}", 60 - i * 10))
        .execute(db.pool())
        .await
        .unwrap();
    }

    let (_, body) = auth_get(&app, &cookie, "/api/v2/conflicts?limit=1").await;
    let cursor = body["next_cursor"].as_str().unwrap();

    assert!(
        !cursor.is_empty(),
        "cursor must be a non-empty opaque token"
    );
}

#[tokio::test]
async fn test_contract_last_page_has_no_cursor() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    // Seed exactly 2 conflicts
    for i in 0..2 {
        sqlx::query(
            "INSERT INTO conflicts (conflict_type, severity, ip, source, detected_at)
             VALUES ('ip_user_change', 'warning', ?, 'Radius', datetime('now', ? || ' seconds'))",
        )
        .bind(format!("10.0.0.{}", i + 1))
        .bind(format!("-{}", 60 - i * 10))
        .execute(db.pool())
        .await
        .unwrap();
    }

    // Fetch all in one page
    let (_, body) = auth_get(&app, &cookie, "/api/v2/conflicts?limit=50").await;
    assert!(
        body["next_cursor"].is_null(),
        "last page should have null next_cursor"
    );
}

#[tokio::test]
async fn test_contract_cursor_and_page_are_mutually_exclusive() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    // "deadbeef" is syntactically valid hex but decodes to gibberish,
    // so the server should reject it as an invalid cursor (400).
    // This also implicitly verifies that cursor takes precedence over page
    // when both are provided — the server parses cursor first.
    let (status, body) = auth_get(
        &app,
        &cookie,
        "/api/v2/conflicts?cursor=deadbeef&page=2&limit=10",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid cursor should be rejected even when page is also provided"
    );
    assert_eq!(body["code"], "INVALID_INPUT");
}

// ── 3c: Export format compliance ──

#[tokio::test]
async fn test_contract_export_csv_escapes_special_chars() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    // Seed mapping with comma and quote in raw_data via user field
    // Note: CSV user column takes first user, current_users uses semicolons.
    // The csv_escape function handles RFC4180 quoting.
    let event = IdentityEvent {
        source: SourceType::Manual,
        ip: "10.99.99.1".parse().unwrap(),
        user: "user,with\"quotes".to_string(),
        timestamp: Utc::now(),
        raw_data: "data with, comma and \"quotes\"".to_string(),
        mac: Some("FF:FF:FF:FF:FF:01".to_string()),
        confidence_score: 100,
    };
    db.upsert_mapping(event, None).await.unwrap();

    let (status, headers, body) = auth_get_raw(
        &app,
        &cookie,
        "/api/v2/export/mappings?format=csv&ip=10.99.99.1",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let csv = String::from_utf8(body).unwrap();
    // The current_users column (semicolon-separated) should be quoted because
    // the username contains comma and quotes
    let data_line = csv.lines().nth(1).expect("should have data row");
    assert!(
        data_line.contains("with\"\"quotes"),
        "CSV should double-quote internal quotes per RFC4180: {data_line}"
    );

    // Content-Type check
    let ct = headers.get("content-type").unwrap().to_str().unwrap();
    assert!(ct.contains("text/csv"), "export CSV content-type: {ct}");
}

#[tokio::test]
async fn test_contract_export_csv_header_row() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, _, body) = auth_get_raw(&app, &cookie, "/api/v2/export/mappings?format=csv").await;
    assert_eq!(status, StatusCode::OK);

    let csv = String::from_utf8(body).unwrap();
    let header_line = csv.lines().next().unwrap();
    let expected_columns = [
        "ip",
        "user",
        "mac",
        "source",
        "last_seen",
        "confidence",
        "is_active",
        "vendor",
        "subnet_id",
        "subnet_name",
        "hostname",
        "device_type",
        "multi_user",
        "current_users",
        "groups",
    ];
    for col in &expected_columns {
        assert!(
            header_line.contains(col),
            "CSV header missing column '{}': {}",
            col,
            header_line
        );
    }
}

#[tokio::test]
async fn test_contract_export_events_csv_header_row() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, _, body) = auth_get_raw(&app, &cookie, "/api/v2/export/events?format=csv").await;
    assert_eq!(status, StatusCode::OK);

    let csv = String::from_utf8(body).unwrap();
    let header_line = csv.lines().next().unwrap();
    for col in &["id", "ip", "user", "source", "timestamp", "raw_data"] {
        assert!(
            header_line.contains(col),
            "events CSV header missing '{}': {}",
            col,
            header_line
        );
    }
}

#[tokio::test]
async fn test_contract_export_content_disposition_header() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    // JSON export
    let (_, json_headers, _) =
        auth_get_raw(&app, &cookie, "/api/v2/export/mappings?format=json").await;
    let json_cd = json_headers
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        json_cd.contains("attachment") && json_cd.contains(".json"),
        "JSON content-disposition: {json_cd}"
    );

    // CSV export
    let (_, csv_headers, _) =
        auth_get_raw(&app, &cookie, "/api/v2/export/mappings?format=csv").await;
    let csv_cd = csv_headers
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        csv_cd.contains("attachment") && csv_cd.contains(".csv"),
        "CSV content-disposition: {csv_cd}"
    );
}

#[tokio::test]
async fn test_contract_export_json_is_array() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (_, _, body) = auth_get_raw(&app, &cookie, "/api/v2/export/mappings?format=json").await;
    let parsed: Value = serde_json::from_slice(&body).unwrap();
    assert!(parsed.is_array(), "JSON export must be a top-level array");
    assert!(parsed.as_array().unwrap().len() >= 5);

    let (_, _, body) = auth_get_raw(&app, &cookie, "/api/v2/export/events?format=json").await;
    let parsed: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        parsed.is_array(),
        "events JSON export must be a top-level array"
    );
}

#[tokio::test]
async fn test_contract_export_csv_row_count_matches_data() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (_, _, body) = auth_get_raw(&app, &cookie, "/api/v2/export/mappings?format=csv").await;
    let csv = String::from_utf8(body).unwrap();
    let lines: Vec<&str> = csv.lines().collect();
    // Header + 5 base mappings (at least)
    assert!(
        lines.len() >= 6,
        "CSV should have header + at least 5 data rows, got {} lines",
        lines.len()
    );
}

// ── 3d: Input validation boundary tests ──

#[tokio::test]
async fn test_contract_search_limit_clamped_to_max() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    // Requesting limit=999 should be clamped to 200
    let (status, body) = auth_get(&app, &cookie, "/api/v2/search?q=test&limit=999").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["limit"].as_u64().unwrap() <= 200,
        "limit should be clamped to max 200"
    );
}

#[tokio::test]
async fn test_contract_search_page_minimum_is_one() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, body) = auth_get(&app, &cookie, "/api/v2/search?q=test&page=0").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["page"].as_u64().unwrap() >= 1,
        "page should be at least 1"
    );
}

#[tokio::test]
async fn test_contract_search_invalid_scope_rejected() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, _) = auth_get(&app, &cookie, "/api/v2/search?scope=invalid").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_contract_search_invalid_datetime_rejected() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, _) = auth_get(&app, &cookie, "/api/v2/search?from=not-a-date&q=test").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_contract_search_supports_multiple_datetime_formats() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    // RFC3339
    let (s1, _) = auth_get(
        &app,
        &cookie,
        "/api/v2/search?from=2024-01-01T00:00:00Z&q=test",
    )
    .await;
    assert_eq!(s1, StatusCode::OK, "RFC3339 format should be accepted");

    // Naive ISO (T separator)
    let (s2, _) = auth_get(
        &app,
        &cookie,
        "/api/v2/search?from=2024-01-01T00:00:00&q=test",
    )
    .await;
    assert_eq!(s2, StatusCode::OK, "naive ISO format should be accepted");

    // Naive SQL (space separator)
    let (s3, _) = auth_get(
        &app,
        &cookie,
        &format!(
            "/api/v2/search?from={}&q=test",
            encode("2024-01-01 00:00:00")
        ),
    )
    .await;
    assert_eq!(s3, StatusCode::OK, "SQL datetime format should be accepted");
}

#[tokio::test]
async fn test_contract_export_rejects_unsupported_format() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, _) = auth_get(&app, &cookie, "/api/v2/export/mappings?format=xml").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unsupported export format should be rejected"
    );
}

#[tokio::test]
async fn test_contract_conflicts_filter_by_severity() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    sqlx::query(
        "INSERT INTO conflicts (conflict_type, severity, ip, source, detected_at)
         VALUES ('ip_user_change', 'warning', '10.0.0.1', 'Radius', datetime('now'))",
    )
    .execute(db.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO conflicts (conflict_type, severity, ip, source, detected_at)
         VALUES ('duplicate_mac', 'critical', '10.0.0.2', 'Radius', datetime('now'))",
    )
    .execute(db.pool())
    .await
    .unwrap();

    let (status, body) = auth_get(&app, &cookie, "/api/v2/conflicts?severity=critical").await;
    assert_eq!(status, StatusCode::OK);

    let conflicts = body["data"].as_array().unwrap();
    assert!(
        conflicts.iter().all(|c| c["severity"] == "critical"),
        "severity filter should return only critical conflicts"
    );
}

#[tokio::test]
async fn test_contract_conflicts_filter_by_type() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    sqlx::query(
        "INSERT INTO conflicts (conflict_type, severity, ip, source, detected_at)
         VALUES ('ip_user_change', 'warning', '10.0.0.1', 'Radius', datetime('now'))",
    )
    .execute(db.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO conflicts (conflict_type, severity, ip, source, detected_at)
         VALUES ('duplicate_mac', 'critical', '10.0.0.2', 'Radius', datetime('now'))",
    )
    .execute(db.pool())
    .await
    .unwrap();

    let (status, body) = auth_get(&app, &cookie, "/api/v2/conflicts?type=duplicate_mac").await;
    assert_eq!(status, StatusCode::OK);

    let conflicts = body["data"].as_array().unwrap();
    assert!(
        conflicts
            .iter()
            .all(|c| c["conflict_type"] == "duplicate_mac"),
        "type filter should return only duplicate_mac conflicts"
    );
}

#[tokio::test]
async fn test_contract_timeline_nonexistent_ip_returns_empty() {
    let (app, _) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    let (status, body) = auth_get(&app, &cookie, "/api/v2/timeline/ip/10.99.99.99").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["current_mapping"].is_null());
    assert_eq!(body["events"]["data"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_contract_conflicts_stats_shape() {
    let (app, db) = build_test_app().await;
    let cookie = login_and_get_cookie(&app, "testadmin", "testpassword123").await;

    sqlx::query(
        "INSERT INTO conflicts (conflict_type, severity, ip, source, detected_at)
         VALUES ('ip_user_change', 'warning', '10.0.0.1', 'Radius', datetime('now'))",
    )
    .execute(db.pool())
    .await
    .unwrap();

    let (status, body) = auth_get(&app, &cookie, "/api/v2/conflicts/stats").await;
    assert_eq!(status, StatusCode::OK);

    // Runtime returns ConflictStatsResponse { total_unresolved, by_type, by_severity }
    assert!(
        body["total_unresolved"].is_number(),
        "conflicts stats must include total_unresolved"
    );
    assert!(
        body["by_type"].is_object(),
        "conflicts stats must include by_type breakdown"
    );
    assert!(
        body["by_severity"].is_object(),
        "conflicts stats must include by_severity breakdown"
    );
    assert!(
        body["total_unresolved"].as_i64().unwrap() >= 1,
        "seeded conflict should be counted"
    );
}

fn openapi_text() -> String {
    let path = format!("{}/../../docs/openapi.yaml", env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(path).expect("read docs/openapi.yaml")
}

fn yaml_block(doc: &str, anchor: &str, indent: usize) -> String {
    let marker = format!("{}{}:", " ".repeat(indent), anchor);
    let same_indent = " ".repeat(indent);
    let deeper_indent = " ".repeat(indent + 1);

    let mut collecting = false;
    let mut lines = Vec::new();
    for line in doc.lines() {
        if !collecting {
            if line == marker {
                collecting = true;
            }
            continue;
        }

        if line.starts_with(&same_indent)
            && !line.starts_with(&deeper_indent)
            && line.trim_end().ends_with(':')
        {
            break;
        }

        lines.push(line);
    }

    assert!(collecting, "missing YAML block for {anchor}");
    lines.join("\n")
}

#[test]
fn test_openapi_device_mapping_schema_guardrail() {
    let doc = openapi_text();
    let block = yaml_block(&doc, "DeviceMapping", 4);

    for needle in &["current_users:", "country_code:", "city:", "tags:"] {
        assert!(
            block.contains(needle),
            "DeviceMapping schema must contain '{needle}'"
        );
    }
    assert!(
        !block.contains("\n        user:"),
        "DeviceMapping schema must not expose stale top-level user field"
    );
}

#[test]
fn test_openapi_alert_history_and_stats_guardrails() {
    let doc = openapi_text();
    let alert_firing = yaml_block(&doc, "AlertFiring", 4);
    for needle in &["rule_id:", "mac:", "source:", "webhook_response:"] {
        assert!(
            alert_firing.contains(needle),
            "AlertFiring schema must contain '{needle}'"
        );
    }

    let alert_stats = yaml_block(&doc, "AlertStatsResponse", 4);
    for needle in &[
        "total_rules:",
        "enabled_rules:",
        "total_fired_24h:",
        "by_severity_24h:",
        "by_type_24h:",
        "webhook_success_rate_24h:",
    ] {
        assert!(
            alert_stats.contains(needle),
            "AlertStatsResponse schema must contain '{needle}'"
        );
    }
}

#[test]
fn test_openapi_conflicts_guardrails() {
    let doc = openapi_text();
    let conflict = yaml_block(&doc, "Conflict", 4);
    assert!(
        conflict.contains("conflict_type:"),
        "Conflict schema must expose conflict_type"
    );
    let conflict_type = yaml_block(&conflict, "conflict_type", 8);
    assert!(
        conflict_type.contains("description:"),
        "Conflict.conflict_type should document the response field semantics"
    );

    let stats = yaml_block(&doc, "ConflictStatsResponse", 4);
    assert!(
        stats.contains("by_severity:"),
        "ConflictStatsResponse schema must include by_severity"
    );
}

#[test]
fn test_openapi_timeline_guardrails() {
    let doc = openapi_text();

    let ip_path = yaml_block(&doc, "/api/v2/timeline/ip/{ip}", 2);
    assert!(
        ip_path.contains("$ref: '#/components/schemas/IpTimelineResponse'"),
        "IP timeline path must use typed response schema"
    );
    assert!(
        !ip_path.contains("additionalProperties: true"),
        "IP timeline path must not fall back to untyped additionalProperties"
    );

    let user_path = yaml_block(&doc, "/api/v2/timeline/user/{user}", 2);
    assert!(
        user_path.contains("$ref: '#/components/schemas/UserTimelineResponse'"),
        "User timeline path must use typed response schema"
    );
    let mac_path = yaml_block(&doc, "/api/v2/timeline/mac/{mac}", 2);
    assert!(
        mac_path.contains("$ref: '#/components/schemas/MacTimelineResponse'"),
        "MAC timeline path must use typed response schema"
    );

    let ip_response = yaml_block(&doc, "IpTimelineResponse", 4);
    for needle in &[
        "current_mapping:",
        "events:",
        "user_changes:",
        "conflicts_count:",
    ] {
        assert!(
            ip_response.contains(needle),
            "IpTimelineResponse schema must contain '{needle}'"
        );
    }

    let user_response = yaml_block(&doc, "UserTimelineResponse", 4);
    for needle in &["user:", "active_mappings:", "events:", "ip_addresses_used:"] {
        assert!(
            user_response.contains(needle),
            "UserTimelineResponse schema must contain '{needle}'"
        );
    }

    let mac_response = yaml_block(&doc, "MacTimelineResponse", 4);
    for needle in &[
        "current_mappings_total:",
        "current_mappings_next_cursor:",
        "ip_history:",
        "ip_history_truncated:",
    ] {
        assert!(
            mac_response.contains(needle),
            "MacTimelineResponse schema must contain '{needle}'"
        );
    }

    let paginated_meta = yaml_block(&doc, "PaginatedMeta", 4);
    for needle in &["total:", "page:", "limit:", "total_pages:", "next_cursor:"] {
        assert!(
            paginated_meta.contains(needle),
            "PaginatedMeta schema must contain '{needle}'"
        );
    }
    assert!(
        paginated_meta.contains("total_pages: { type: integer }"),
        "PaginatedMeta.total_pages must stay non-nullable"
    );
}

#[test]
fn test_openapi_search_and_export_guardrails() {
    let doc = openapi_text();

    let search_response = yaml_block(&doc, "SearchResponse", 4);
    assert!(
        search_response.contains("Null when the requested scope excludes mappings"),
        "SearchResponse should explain when mappings is null"
    );
    assert!(
        search_response.contains("Null when the requested scope excludes events"),
        "SearchResponse should explain when events is null"
    );

    let export_events = yaml_block(&doc, "/api/v2/export/events", 2);
    assert!(
        export_events.contains("$ref: '#/components/schemas/StoredEvent'"),
        "events export must use StoredEvent schema"
    );

    let export_mappings = yaml_block(&doc, "/api/v2/export/mappings", 2);
    for needle in &["x-trueid-truncated:", "Content-Disposition:"] {
        assert!(
            export_mappings.contains(needle),
            "mappings export must document '{needle}'"
        );
    }
}
