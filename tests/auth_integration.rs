//! Integration tests for TrueID authentication flows.
//!
//! These tests require a running TrueID instance.
//! Run explicitly: cargo test -p trueid-integration-tests -- --ignored
//!
//! Requires a running TrueID instance. Set TRUEID_TEST_URL env var
//! (default: http://127.0.0.1:3000). Bootstrap admin must be created
//! with TRUEID_ADMIN_USER=admin TRUEID_ADMIN_PASS=integration12345.
//!
//! Run: TRUEID_TEST_URL=http://127.0.0.1:3000 cargo test -p trueid-integration-tests
mod support;

use serde_json::Value;
use support::{lock_suite, TestClient};

const ADMIN_USER: &str = "admin";
const ADMIN_PASS: &str = "integration12345";

// ── Tests ──────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_health() {
    let _suite = lock_suite().await;
    let c = TestClient::new();
    let resp = c.get("/health").await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
#[ignore]
async fn test_login_success() {
    let _suite = lock_suite().await;
    let c = TestClient::new();
    let (status, body) = c.login(ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(status, 200, "Login should succeed: {body}");
    assert!(body["user"]["username"].is_string());
    assert_eq!(body["user"]["role"], "Admin");
}

#[tokio::test]
#[ignore]
async fn test_login_failure_wrong_password() {
    let _suite = lock_suite().await;
    let c = TestClient::new();
    let (status, _body) = c.login(ADMIN_USER, "wrongpassword123").await;
    assert_eq!(status, 401, "Login with wrong password should return 401");
}

#[tokio::test]
#[ignore]
async fn test_login_failure_unknown_user() {
    let _suite = lock_suite().await;
    let c = TestClient::new();
    let (status, _body) = c.login("nonexistent_user", "whatever12345").await;
    assert_eq!(status, 401, "Login with unknown user should return 401");
}

#[tokio::test]
#[ignore]
async fn test_me_without_auth() {
    let _suite = lock_suite().await;
    let c = TestClient::new();
    let resp = c.get("/api/auth/me").await;
    assert_eq!(resp.status(), 401, "/me without auth should return 401");
}

#[tokio::test]
#[ignore]
async fn test_me_after_login() {
    let _suite = lock_suite().await;
    let c = TestClient::new();
    let (status, _) = c.login(ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(status, 200);

    let resp = c.get("/api/auth/me").await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["user"]["username"], ADMIN_USER);
}

#[tokio::test]
#[ignore]
async fn test_logout() {
    let _suite = lock_suite().await;
    let c = TestClient::new();
    let (status, _) = c.login(ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(status, 200);

    // Logout.
    let resp = c.post_with_csrf("/api/auth/logout").await;
    assert!(resp.status().is_success() || resp.status() == 200);

    // /me should now fail.
    let resp = c.get("/api/auth/me").await;
    assert_eq!(resp.status(), 401, "/me after logout should return 401");
}

#[tokio::test]
#[ignore]
async fn test_token_refresh() {
    let _suite = lock_suite().await;
    let c = TestClient::new();
    let (status, _) = c.login(ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(status, 200);

    // Refresh.
    let resp = c.post_with_csrf("/api/auth/refresh").await;
    assert_eq!(resp.status(), 200, "Refresh should succeed");

    // /me should still work.
    let resp = c.get("/api/auth/me").await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
#[ignore]
async fn test_session_listing() {
    let _suite = lock_suite().await;
    let c1 = TestClient::new();
    let (s1, _) = c1.login(ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(s1, 200);

    let c2 = TestClient::new();
    let (s2, _) = c2.login(ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(s2, 200);

    let resp = c1.get("/api/auth/sessions").await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let sessions = body.as_array().expect("sessions should be array");
    assert!(sessions.len() >= 2, "Should have at least 2 sessions");
}

#[tokio::test]
#[ignore]
async fn test_logout_all() {
    let _suite = lock_suite().await;
    let c1 = TestClient::new();
    let (s1, _) = c1.login(ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(s1, 200);

    let c2 = TestClient::new();
    let (s2, _) = c2.login(ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(s2, 200);

    // Logout all from c1.
    let resp = c1.post_with_csrf("/api/auth/logout-all").await;
    assert!(resp.status().is_success());

    // c2 should be kicked out.
    let resp = c2.get("/api/auth/me").await;
    assert_eq!(resp.status(), 401, "c2 should be 401 after logout-all");
}

#[tokio::test]
#[ignore]
async fn test_protected_endpoint_without_auth() {
    let _suite = lock_suite().await;
    let c = TestClient::new();
    let resp = c.get("/api/v1/mappings").await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
#[ignore]
async fn test_admin_endpoint_with_auth() {
    let _suite = lock_suite().await;
    let c = TestClient::new();
    let (status, _) = c.login(ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(status, 200);

    let resp = c.get("/api/v1/users").await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
#[ignore]
async fn test_audit_logs_admin() {
    let _suite = lock_suite().await;
    let c = TestClient::new();
    let (status, _) = c.login(ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(status, 200);

    let resp = c.get("/api/v1/audit-logs").await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["total"].is_number());
    assert!(body["entries"].is_array());
}
