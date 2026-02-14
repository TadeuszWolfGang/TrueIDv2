//! HTTP client wrapper for TrueID API access.

use serde_json::Value;
use std::fmt::{Display, Formatter};

/// CLI error kind used for exit-code mapping.
#[derive(Debug)]
pub struct CliError {
    message: String,
    auth: bool,
}

impl CliError {
    /// Creates an error from message and auth flag.
    ///
    /// Parameters: `message` - human-readable message, `auth` - auth-related failure flag.
    /// Returns: CLI error.
    pub fn new(message: String, auth: bool) -> Self {
        Self { message, auth }
    }

    /// Creates an authentication/authorization error.
    ///
    /// Parameters: `message` - auth error details.
    /// Returns: CLI error with auth flag.
    pub fn auth(message: String) -> Self {
        Self {
            message,
            auth: true,
        }
    }

    /// Returns true when this is an auth failure.
    ///
    /// Parameters: none.
    /// Returns: auth marker.
    pub fn is_auth(&self) -> bool {
        self.auth
    }
}

impl Display for CliError {
    /// Formats CLI error for terminal output.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CliError {}

/// HTTP API client for TrueID web service.
pub struct TrueIdClient {
    base_url: String,
    api_key: Option<String>,
    http: reqwest::Client,
}

impl TrueIdClient {
    /// Creates configured TrueID HTTP client.
    ///
    /// Parameters: `base_url` - web API base URL, `api_key` - optional API key.
    /// Returns: configured HTTP client.
    pub fn new(base_url: &str, api_key: Option<&str>) -> Self {
        let http = reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .expect("Failed to build HTTP client");
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.map(|s| s.to_string()),
            http,
        }
    }

    /// Performs GET request and parses JSON body.
    ///
    /// Parameters: `path` - request path starting with `/`.
    /// Returns: JSON payload.
    pub async fn get_json(&self, path: &str) -> Result<Value, CliError> {
        let resp = self
            .request(reqwest::Method::GET, path, None)
            .await
            .map_err(|e| CliError::new(format!("request failed: {e}"), false))?;
        self.parse_json_response(resp).await
    }

    /// Performs GET request and returns plain text body.
    ///
    /// Parameters: `path` - request path starting with `/`.
    /// Returns: raw response body.
    pub async fn get_text(&self, path: &str) -> Result<String, CliError> {
        let resp = self
            .request(reqwest::Method::GET, path, None)
            .await
            .map_err(|e| CliError::new(format!("request failed: {e}"), false))?;
        self.parse_text_response(resp).await
    }

    /// Performs POST request with JSON body.
    ///
    /// Parameters: `path` - request path, `body` - JSON payload.
    /// Returns: JSON response payload.
    pub async fn post_json(&self, path: &str, body: &Value) -> Result<Value, CliError> {
        let resp = self
            .request(reqwest::Method::POST, path, Some(body))
            .await
            .map_err(|e| CliError::new(format!("request failed: {e}"), false))?;
        self.parse_json_response(resp).await
    }

    /// Performs PUT request with JSON body.
    ///
    /// Parameters: `path` - request path, `body` - JSON payload.
    /// Returns: JSON response payload.
    pub async fn put_json(&self, path: &str, body: &Value) -> Result<Value, CliError> {
        let resp = self
            .request(reqwest::Method::PUT, path, Some(body))
            .await
            .map_err(|e| CliError::new(format!("request failed: {e}"), false))?;
        self.parse_json_response(resp).await
    }

    /// Performs DELETE request.
    ///
    /// Parameters: `path` - request path.
    /// Returns: JSON response payload if present, otherwise empty JSON object.
    pub async fn delete_json(&self, path: &str) -> Result<Value, CliError> {
        let resp = self
            .request(reqwest::Method::DELETE, path, None)
            .await
            .map_err(|e| CliError::new(format!("request failed: {e}"), false))?;
        if resp.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(serde_json::json!({}));
        }
        self.parse_json_response(resp).await
    }

    /// Sends a request with optional JSON body.
    ///
    /// Parameters: `method` - HTTP method, `path` - request path, `body` - optional JSON body.
    /// Returns: HTTP response.
    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.request(method, &url);
        if let Some(key) = &self.api_key {
            req = req.header("X-API-Key", key);
        }
        if let Some(payload) = body {
            req = req.json(payload);
        }
        req.send().await
    }

    /// Validates status code and parses JSON response body.
    ///
    /// Parameters: `resp` - HTTP response.
    /// Returns: parsed JSON value.
    async fn parse_json_response(&self, resp: reqwest::Response) -> Result<Value, CliError> {
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                return Err(CliError::auth(format!("HTTP {status}: {text}")));
            }
            return Err(CliError::new(format!("HTTP {status}: {text}"), false));
        }
        resp.json::<Value>()
            .await
            .map_err(|e| CliError::new(format!("invalid JSON response: {e}"), false))
    }

    /// Validates status code and parses text response body.
    ///
    /// Parameters: `resp` - HTTP response.
    /// Returns: raw text body.
    async fn parse_text_response(&self, resp: reqwest::Response) -> Result<String, CliError> {
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| CliError::new(format!("response read failed: {e}"), false))?;
        if !status.is_success() {
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                return Err(CliError::auth(format!("HTTP {status}: {text}")));
            }
            return Err(CliError::new(format!("HTTP {status}: {text}"), false));
        }
        Ok(text)
    }
}
