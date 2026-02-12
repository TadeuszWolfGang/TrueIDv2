//! In-memory sliding-window rate limiter for TrueID web.
//!
//! Uses DashMap for concurrent, lock-free access.
//! Suitable for single-instance deployments; for multi-instance use Redis.

use dashmap::DashMap;
use std::time::Instant;

/// Sliding-window counter rate limiter.
///
/// Each key tracks (request_count, window_start).
/// When window expires the counter resets.
pub struct RateLimiter {
    limits: DashMap<String, (u32, Instant)>,
    max_requests: u32,
    window_secs: u64,
}

impl RateLimiter {
    /// Creates a new rate limiter.
    ///
    /// Parameters: `max_requests` - max allowed per window,
    /// `window_secs` - sliding window duration in seconds.
    /// Returns: `RateLimiter` instance.
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            limits: DashMap::new(),
            max_requests,
            window_secs,
        }
    }

    /// Checks if a request for `key` is allowed.
    ///
    /// Increments the counter and returns `true` if within limit,
    /// `false` if rate-limited. Resets window when expired.
    ///
    /// Parameters: `key` - identifier (e.g. IP address, API key prefix).
    /// Returns: `true` if allowed, `false` if rate-limited.
    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);

        let mut entry = self
            .limits
            .entry(key.to_string())
            .or_insert_with(|| (0, now));
        let (count, start) = entry.value_mut();

        if now.duration_since(*start) >= window {
            // Window expired — reset.
            *count = 1;
            *start = now;
            return true;
        }

        *count += 1;
        *count <= self.max_requests
    }

    /// Removes stale entries older than 2× the window duration.
    ///
    /// Call periodically (e.g. every 5 minutes) to prevent unbounded growth.
    pub fn cleanup(&self) {
        let cutoff = std::time::Duration::from_secs(self.window_secs * 2);
        let now = Instant::now();
        self.limits
            .retain(|_, (_, start)| now.duration_since(*start) < cutoff);
    }
}
