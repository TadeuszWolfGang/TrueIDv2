//! RBAC matrix integration tests for TrueID.
//!
//! These tests require a running TrueID instance.
//! Run explicitly: cargo test -p trueid-integration-tests -- --ignored
//!
//! Tests that each role (Admin, Operator, Viewer) and anonymous access
//! gets the correct HTTP status for protected endpoints.
//!
//! Requires a running TrueID instance with:
//!   - Admin user: admin / $TRUEID_TEST_ADMIN_PASS
//!   - Operator user: rbac_operator / Testpassword123 (created by test)
//!   - Viewer user: rbac_viewer / Testpassword123 (created by test)
//!
//! Run: TRUEID_TEST_URL=http://127.0.0.1:3000 cargo test -p trueid-integration-tests --test rbac_matrix
mod support;

use reqwest::StatusCode;
use serde_json::{json, Value};
use support::{base_url, lock_suite, stateless_client, TestClient};

const ADMIN_USER: &str = "admin";
const RBAC_TEST_PASS: &str = "Testpassword123";

fn admin_pass() -> String {
    std::env::var("TRUEID_TEST_ADMIN_PASS")
        .expect("TRUEID_TEST_ADMIN_PASS must be set for ignored integration tests")
}

/// Ensures test users exist (Operator, Viewer). Idempotent.
async fn ensure_test_users(admin_client: &TestClient) {
    for (user, role) in &[("rbac_operator", "Operator"), ("rbac_viewer", "Viewer")] {
        let resp = admin_client
            .post_json_with_csrf(
                "/api/v1/users",
                &json!({
                    "username": user,
                    "password": RBAC_TEST_PASS,
                    "role": role
                }),
            )
            .await;
        // 201 = created, 409 = already exists — both are fine.
        let st = resp.status();
        assert!(
            st == StatusCode::CREATED || st == StatusCode::CONFLICT,
            "Unexpected status creating {user}: {st}"
        );
    }
}

/// Tests a GET endpoint for a specific client.
async fn get_status(c: &TestClient, path: &str) -> u16 {
    c.get(path).await.status().as_u16()
}

#[tokio::test]
#[ignore]
async fn test_rbac_matrix() {
    let _suite = lock_suite().await;
    // Setup: login as admin, create test users.
    let admin = TestClient::new();
    let admin_pass = admin_pass();
    assert_eq!(admin.login(ADMIN_USER, &admin_pass).await.0, StatusCode::OK);
    ensure_test_users(&admin).await;

    let operator = TestClient::new();
    assert_eq!(
        operator.login("rbac_operator", RBAC_TEST_PASS).await.0,
        StatusCode::OK
    );

    let viewer = TestClient::new();
    assert_eq!(
        viewer.login("rbac_viewer", RBAC_TEST_PASS).await.0,
        StatusCode::OK
    );

    let anon = TestClient::new(); // No login.

    // ── Viewer+ endpoints (GET reads) ────────────────────
    // Admin, Operator, Viewer → 200; Anonymous → 401
    for path in &["/api/v1/mappings", "/api/v1/events"] {
        assert_eq!(get_status(&admin, path).await, 200, "Admin GET {path}");
        assert_eq!(
            get_status(&operator, path).await,
            200,
            "Operator GET {path}"
        );
        assert_eq!(get_status(&viewer, path).await, 200, "Viewer GET {path}");
        assert_eq!(get_status(&anon, path).await, 401, "Anon GET {path}");
    }

    // ── Admin-only endpoints ─────────────────────────────
    for path in &["/api/v1/users", "/api/v1/api-keys", "/api/v1/audit-logs"] {
        assert_eq!(get_status(&admin, path).await, 200, "Admin GET {path}");
        assert_eq!(
            get_status(&operator, path).await,
            403,
            "Operator GET {path}"
        );
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
#[ignore]
async fn test_api_key_auth() {
    let _suite = lock_suite().await;
    let admin = TestClient::new();
    let admin_pass = admin_pass();
    assert_eq!(admin.login(ADMIN_USER, &admin_pass).await.0, StatusCode::OK);

    // Create a Viewer API key.
    let resp = admin
        .post_json_with_csrf(
            "/api/v1/api-keys",
            &json!({"description": "test-viewer-key", "role": "Viewer"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let key_body: Value = resp.json().await.unwrap();
    let raw_key = key_body["key"].as_str().expect("key field missing");

    // Use API key to GET mappings → 200.
    let key_client = stateless_client();
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
    assert_eq!(
        resp.status(),
        403,
        "Viewer API key should NOT access /users"
    );

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
#[ignore]
async fn test_csrf_protection() {
    let _suite = lock_suite().await;
    // API key requests should NOT require CSRF token.
    let admin = TestClient::new();
    let admin_pass = admin_pass();
    assert_eq!(admin.login(ADMIN_USER, &admin_pass).await.0, StatusCode::OK);

    // Create an Admin API key for testing.
    let resp = admin
        .post_json_with_csrf(
            "/api/v1/api-keys",
            &json!({"description": "csrf-test-key", "role": "Admin"}),
        )
        .await;
    if resp.status() == StatusCode::CREATED {
        let body: Value = resp.json().await.unwrap();
        let raw_key = body["key"].as_str().unwrap();

        // POST with API key, no CSRF → should succeed (CSRF only for cookies).
        let key_client = stateless_client();
        let resp = key_client
            .post(format!("{}/api/v1/api-keys", base_url()))
            .header("X-API-Key", raw_key)
            .header("Content-Type", "application/json")
            .json(&json!({"description": "nested-key", "role": "Viewer"}))
            .send()
            .await
            .unwrap();
        // Should be 201 (created) — CSRF not required for API key auth.
        assert_eq!(
            resp.status().as_u16(),
            201,
            "API key POST should not need CSRF"
        );
    }
}
