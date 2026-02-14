//! In-memory sliding-window rate limiter for TrueID web.
//!
//! Uses DashMap for concurrent, lock-free access.
//! Suitable for single-instance deployments; for multi-instance use Redis.

use dashmap::DashMap;
use std::time::{Duration, Instant};

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

/// Token-bucket limiter with per-key dynamic limits.
pub struct PerKeyLimiter {
    buckets: DashMap<String, TokenBucket>,
    default_rpm: u32,
    default_burst: u32,
}

#[derive(Clone)]
struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl PerKeyLimiter {
    /// Creates a per-key token bucket limiter.
    ///
    /// Parameters: `default_rpm` - fallback requests per minute, `default_burst` - fallback burst.
    /// Returns: initialized limiter.
    pub fn new(default_rpm: u32, default_burst: u32) -> Self {
        Self {
            buckets: DashMap::new(),
            default_rpm: default_rpm.max(1),
            default_burst: default_burst.max(1),
        }
    }

    /// Checks if request is allowed for key and limits.
    ///
    /// Parameters: `key_id` - stable bucket key, `rpm` - desired rpm, `burst` - desired burst.
    /// Returns: `Ok(remaining_tokens)` or `Err(retry_after_seconds)`.
    pub fn check(&self, key_id: &str, rpm: u32, burst: u32) -> Result<u32, u64> {
        let now = Instant::now();
        let effective_rpm = if rpm == 0 { self.default_rpm } else { rpm };
        let effective_burst = if burst == 0 { self.default_burst } else { burst };
        let max_tokens = f64::from(effective_burst);
        let refill_rate = f64::from(effective_rpm) / 60.0;

        let mut bucket = self.buckets.entry(key_id.to_string()).or_insert_with(|| TokenBucket {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: now,
        });

        if (bucket.max_tokens - max_tokens).abs() > f64::EPSILON
            || (bucket.refill_rate - refill_rate).abs() > f64::EPSILON
        {
            bucket.max_tokens = max_tokens;
            bucket.refill_rate = refill_rate;
            if bucket.tokens > max_tokens {
                bucket.tokens = max_tokens;
            }
        }

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            bucket.tokens = (bucket.tokens + elapsed * bucket.refill_rate).min(bucket.max_tokens);
            bucket.last_refill = now;
        }

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(bucket.tokens.floor().max(0.0) as u32);
        }

        let missing = 1.0 - bucket.tokens;
        let retry_after = (missing / bucket.refill_rate).ceil() as u64;
        Err(retry_after.max(1))
    }

    /// Cleans stale token buckets not used recently.
    ///
    /// Parameters: none.
    /// Returns: nothing.
    pub fn cleanup(&self) {
        let cutoff = Duration::from_secs(600);
        let now = Instant::now();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < cutoff);
    }
}
