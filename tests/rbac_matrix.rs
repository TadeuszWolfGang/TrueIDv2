//! RBAC matrix integration tests for TrueID.
//!
//! Tests that each role (Admin, Operator, Viewer) and anonymous access
//! gets the correct HTTP status for protected endpoints.
//!
//! Requires a running TrueID instance with:
//!   - Admin user: admin / integration12345
//!   - Operator user: operator / operatorpass123 (created by test)
//!   - Viewer user: viewer / viewerpass12345 (created by test)
//!
//! Run: TRUEID_TEST_URL=http://127.0.0.1:3000 cargo test -p trueid-integration-tests --test rbac_matrix

use reqwest::StatusCode;
use serde_json::{json, Value};

fn base_url() -> String {
    std::env::var("TRUEID_TEST_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string())
}

const ADMIN_USER: &str = "admin";
const ADMIN_PASS: &str = "integration12345";

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build HTTP client")
}

async fn login(c: &reqwest::Client, user: &str, pass: &str) -> StatusCode {
    let resp = c
        .post(format!("{}/api/auth/login", base_url()))
        .json(&json!({"username": user, "password": pass}))
        .send()
        .await
        .expect("Login request failed");
    resp.status()
}

/// Ensures test users exist (Operator, Viewer). Idempotent.
async fn ensure_test_users(admin_client: &reqwest::Client) {
    for (user, role) in &[("rbac_operator", "Operator"), ("rbac_viewer", "Viewer")] {
        let resp = admin_client
            .post(format!("{}/api/v1/users", base_url()))
            .json(&json!({
                "username": user,
                "password": "testpassword123",
                "role": role
            }))
            .send()
            .await
            .expect("Create user failed");
        // 201 = created, 409 = already exists — both are fine.
        let st = resp.status();
        assert!(
            st == StatusCode::CREATED || st == StatusCode::CONFLICT,
            "Unexpected status creating {user}: {st}"
        );
    }
}

/// Tests a GET endpoint for a specific client.
async fn get_status(c: &reqwest::Client, path: &str) -> u16 {
    let resp = c
        .get(format!("{}{}", base_url(), path))
        .send()
        .await
        .expect("GET request failed");
    resp.status().as_u16()
}

#[tokio::test]
async fn test_rbac_matrix() {
    // Setup: login as admin, create test users.
    let admin = client();
    assert_eq!(login(&admin, ADMIN_USER, ADMIN_PASS).await, StatusCode::OK);
    ensure_test_users(&admin).await;

    let operator = client();
    assert_eq!(login(&operator, "rbac_operator", "testpassword123").await, StatusCode::OK);

    let viewer = client();
    assert_eq!(login(&viewer, "rbac_viewer", "testpassword123").await, StatusCode::OK);

    let anon = client(); // No login.

    // ── Viewer+ endpoints (GET reads) ────────────────────
    // Admin, Operator, Viewer → 200; Anonymous → 401
    for path in &["/api/v1/mappings", "/api/v1/events", "/api/v1/stats"] {
        assert_eq!(get_status(&admin, path).await, 200, "Admin GET {path}");
        assert_eq!(get_status(&operator, path).await, 200, "Operator GET {path}");
        assert_eq!(get_status(&viewer, path).await, 200, "Viewer GET {path}");
        assert_eq!(get_status(&anon, path).await, 401, "Anon GET {path}");
    }

    // ── Admin-only endpoints ─────────────────────────────
    for path in &["/api/v1/users", "/api/v1/api-keys", "/api/v1/audit-logs"] {
        assert_eq!(get_status(&admin, path).await, 200, "Admin GET {path}");
        assert_eq!(get_status(&operator, path).await, 403, "Operator GET {path}");
        assert_eq!(get_status(&viewer, path).await, 403, "Viewer GET {path}");
        assert_eq!(get_status(&anon, path).await, 401, "Anon GET {path}");
    }

    // ── Admin-only audit stats ───────────────────────────
    assert_eq!(get_status(&admin, "/api/v1/audit-logs/stats").await, 200);
    assert_eq!(get_status(&operator, "/api/v1/audit-logs/stats").await, 403);
    assert_eq!(get_status(&viewer, "/api/v1/audit-logs/stats").await, 403);
    assert_eq!(get_status(&anon, "/api/v1/audit-logs/stats").await, 401);
}

#[tokio::test]
async fn test_api_key_auth() {
    let admin = client();
    assert_eq!(login(&admin, ADMIN_USER, ADMIN_PASS).await, StatusCode::OK);

    // Create a Viewer API key.
    let resp = admin
        .post(format!("{}/api/v1/api-keys", base_url()))
        .json(&json!({"description": "test-viewer-key", "role": "Viewer"}))
        .send()
        .await
        .expect("Create API key failed");
    assert_eq!(resp.status(), StatusCode::CREATED);
    let key_body: Value = resp.json().await.unwrap();
    let raw_key = key_body["key"].as_str().expect("key field missing");

    // Use API key to GET mappings → 200.
    let key_client = reqwest::Client::new();
    let resp = key_client
        .get(format!("{}/api/v1/mappings", base_url()))
        .header("X-API-Key", raw_key)
        .send()
        .await
        .expect("API key GET failed");
    assert_eq!(resp.status(), 200, "Viewer API key should access mappings");

    // Viewer API key cannot access admin endpoints → 403.
    let resp = key_client
        .get(format!("{}/api/v1/users", base_url()))
        .header("X-API-Key", raw_key)
        .send()
        .await
        .expect("API key GET users failed");
    assert_eq!(resp.status(), 403, "Viewer API key should NOT access /users");

    // Invalid API key → 401.
    let resp = key_client
        .get(format!("{}/api/v1/mappings", base_url()))
        .header("X-API-Key", "invalid_key_value")
        .send()
        .await
        .expect("Invalid API key request failed");
    assert_eq!(resp.status(), 401, "Invalid API key should return 401");
}

#[tokio::test]
async fn test_csrf_protection() {
    // API key requests should NOT require CSRF token.
    let admin = client();
    assert_eq!(login(&admin, ADMIN_USER, ADMIN_PASS).await, StatusCode::OK);

    // Create an Admin API key for testing.
    let resp = admin
        .post(format!("{}/api/v1/api-keys", base_url()))
        .json(&json!({"description": "csrf-test-key", "role": "Admin"}))
        .send()
        .await
        .unwrap();
    if resp.status() == StatusCode::CREATED {
        let body: Value = resp.json().await.unwrap();
        let raw_key = body["key"].as_str().unwrap();

        // POST with API key, no CSRF → should succeed (CSRF only for cookies).
        let key_client = reqwest::Client::new();
        let resp = key_client
            .post(format!("{}/api/v1/api-keys", base_url()))
            .header("X-API-Key", raw_key)
            .header("Content-Type", "application/json")
            .json(&json!({"description": "nested-key", "role": "Viewer"}))
            .send()
            .await
            .unwrap();
        // Should be 201 (created) — CSRF not required for API key auth.
        assert_eq!(resp.status().as_u16(), 201, "API key POST should not need CSRF");
    }
}
