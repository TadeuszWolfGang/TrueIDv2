#![allow(dead_code)]

use reqwest::cookie::{CookieStore, Jar};
use reqwest::{Client, StatusCode, Url};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

static NEXT_TEST_IP: AtomicU32 = AtomicU32::new(10);

pub fn base_url() -> String {
    std::env::var("TRUEID_TEST_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string())
}

fn base_url_parsed() -> Url {
    Url::parse(&base_url()).expect("TRUEID_TEST_URL must be a valid URL")
}

fn next_forwarded_ip() -> String {
    let octet = NEXT_TEST_IP.fetch_add(1, Ordering::Relaxed);
    format!("198.51.100.{}", (octet % 200) + 10)
}

fn csrf_from_cookie(cookie: &str) -> String {
    cookie
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("trueid_csrf_token=").map(str::to_string))
        .unwrap_or_default()
}

pub struct SuiteLock {
    path: PathBuf,
}

impl Drop for SuiteLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

pub async fn lock_suite() -> SuiteLock {
    let path = std::env::temp_dir().join("trueid-integration-tests.lock");
    loop {
        match std::fs::create_dir(&path) {
            Ok(()) => return SuiteLock { path },
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(err) => panic!("failed to acquire integration test lock: {err}"),
        }
    }
}

pub fn stateless_client() -> Client {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build HTTP client")
}

pub struct TestClient {
    client: Client,
    jar: Arc<Jar>,
    forwarded_for: String,
}

impl TestClient {
    pub fn new() -> Self {
        let jar = Arc::new(Jar::default());
        let client = Client::builder()
            .cookie_provider(jar.clone())
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client");

        Self {
            client,
            jar,
            forwarded_for: next_forwarded_ip(),
        }
    }

    fn csrf_token(&self) -> String {
        self.jar
            .cookies(&base_url_parsed())
            .and_then(|value| value.to_str().ok().map(str::to_string))
            .map(|cookie| csrf_from_cookie(&cookie))
            .unwrap_or_default()
    }

    pub async fn login(&self, user: &str, pass: &str) -> (StatusCode, Value) {
        let resp = self
            .client
            .post(format!("{}/api/auth/login", base_url()))
            .header("x-forwarded-for", &self.forwarded_for)
            .json(&json!({"username": user, "password": pass}))
            .send()
            .await
            .expect("login request failed");
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(json!({}));
        (status, body)
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(format!("{}{}", base_url(), path))
            .send()
            .await
            .expect("GET request failed")
    }

    pub async fn post_with_csrf(&self, path: &str) -> reqwest::Response {
        self.client
            .post(format!("{}{}", base_url(), path))
            .header("x-csrf-token", self.csrf_token())
            .send()
            .await
            .expect("POST request failed")
    }

    pub async fn post_json_with_csrf(&self, path: &str, body: &Value) -> reqwest::Response {
        self.client
            .post(format!("{}{}", base_url(), path))
            .header("x-csrf-token", self.csrf_token())
            .json(body)
            .send()
            .await
            .expect("POST JSON request failed")
    }
}
