//! Integration tests for TrueID authentication flows.
//!
//! Requires a running TrueID instance. Set TRUEID_TEST_URL env var
//! (default: http://127.0.0.1:3000). Bootstrap admin must be created
//! with TRUEID_ADMIN_USER=admin TRUEID_ADMIN_PASS=integration12345.
//!
//! Run: TRUEID_TEST_URL=http://127.0.0.1:3000 cargo test -p trueid-integration-tests

use serde_json::{json, Value};

fn base_url() -> String {
    std::env::var("TRUEID_TEST_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string())
}

const ADMIN_USER: &str = "admin";
const ADMIN_PASS: &str = "integration12345";

/// Creates a reqwest client with cookie jar.
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build HTTP client")
}

/// Login helper: returns (client_with_cookies, response_body).
async fn login(c: &reqwest::Client, user: &str, pass: &str) -> (reqwest::StatusCode, Value) {
    let resp = c
        .post(format!("{}/api/auth/login", base_url()))
        .json(&json!({"username": user, "password": pass}))
        .send()
        .await
        .expect("Login request failed");
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(json!({}));
    (status, body)
}

// ── Tests ──────────────────────────────────────────────────

#[tokio::test]
async fn test_health() {
    let c = client();
    let resp = c
        .get(format!("{}/health", base_url()))
        .send()
        .await
        .expect("Health check failed");
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_login_success() {
    let c = client();
    let (status, body) = login(&c, ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(status, 200, "Login should succeed: {body}");
    assert!(body["user"]["username"].is_string());
    assert_eq!(body["user"]["role"], "Admin");
}

#[tokio::test]
async fn test_login_failure_wrong_password() {
    let c = client();
    let (status, _body) = login(&c, ADMIN_USER, "wrongpassword123").await;
    assert_eq!(status, 401, "Login with wrong password should return 401");
}

#[tokio::test]
async fn test_login_failure_unknown_user() {
    let c = client();
    let (status, _body) = login(&c, "nonexistent_user", "whatever12345").await;
    assert_eq!(status, 401, "Login with unknown user should return 401");
}

#[tokio::test]
async fn test_me_without_auth() {
    let c = client();
    let resp = c
        .get(format!("{}/api/auth/me", base_url()))
        .send()
        .await
        .expect("/me request failed");
    assert_eq!(resp.status(), 401, "/me without auth should return 401");
}

#[tokio::test]
async fn test_me_after_login() {
    let c = client();
    let (status, _) = login(&c, ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(status, 200);

    let resp = c
        .get(format!("{}/api/auth/me", base_url()))
        .send()
        .await
        .expect("/me request failed");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["user"]["username"], ADMIN_USER);
}

#[tokio::test]
async fn test_logout() {
    let c = client();
    let (status, _) = login(&c, ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(status, 200);

    // Logout.
    let resp = c
        .post(format!("{}/api/auth/logout", base_url()))
        .send()
        .await
        .expect("Logout request failed");
    assert!(resp.status().is_success() || resp.status() == 200);

    // /me should now fail.
    let resp = c
        .get(format!("{}/api/auth/me", base_url()))
        .send()
        .await
        .expect("/me after logout failed");
    assert_eq!(resp.status(), 401, "/me after logout should return 401");
}

#[tokio::test]
async fn test_token_refresh() {
    let c = client();
    let (status, _) = login(&c, ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(status, 200);

    // Refresh.
    let resp = c
        .post(format!("{}/api/auth/refresh", base_url()))
        .send()
        .await
        .expect("Refresh request failed");
    assert_eq!(resp.status(), 200, "Refresh should succeed");

    // /me should still work.
    let resp = c
        .get(format!("{}/api/auth/me", base_url()))
        .send()
        .await
        .expect("/me after refresh failed");
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_session_listing() {
    let c1 = client();
    let (s1, _) = login(&c1, ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(s1, 200);

    let c2 = client();
    let (s2, _) = login(&c2, ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(s2, 200);

    let resp = c1
        .get(format!("{}/api/auth/sessions", base_url()))
        .send()
        .await
        .expect("Sessions request failed");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let sessions = body["sessions"]
        .as_array()
        .expect("sessions should be array");
    assert!(sessions.len() >= 2, "Should have at least 2 sessions");
}

#[tokio::test]
async fn test_logout_all() {
    let c1 = client();
    let (s1, _) = login(&c1, ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(s1, 200);

    let c2 = client();
    let (s2, _) = login(&c2, ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(s2, 200);

    // Logout all from c1.
    let resp = c1
        .post(format!("{}/api/auth/logout-all", base_url()))
        .send()
        .await
        .expect("Logout-all request failed");
    assert!(resp.status().is_success());

    // c2 should be kicked out.
    let resp = c2
        .get(format!("{}/api/auth/me", base_url()))
        .send()
        .await
        .expect("/me from c2 after logout-all failed");
    assert_eq!(resp.status(), 401, "c2 should be 401 after logout-all");
}

#[tokio::test]
async fn test_protected_endpoint_without_auth() {
    let c = client();
    let resp = c
        .get(format!("{}/api/v1/mappings", base_url()))
        .send()
        .await
        .expect("Mappings request failed");
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_admin_endpoint_with_auth() {
    let c = client();
    let (status, _) = login(&c, ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(status, 200);

    let resp = c
        .get(format!("{}/api/v1/users", base_url()))
        .send()
        .await
        .expect("Users list request failed");
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_audit_logs_admin() {
    let c = client();
    let (status, _) = login(&c, ADMIN_USER, ADMIN_PASS).await;
    assert_eq!(status, 200);

    let resp = c
        .get(format!("{}/api/v1/audit-logs", base_url()))
        .send()
        .await
        .expect("Audit logs request failed");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["total"].is_number());
    assert!(body["entries"].is_array());
}
