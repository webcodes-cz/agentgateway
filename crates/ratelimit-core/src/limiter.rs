//! Token bucket rate limiter implementation
//!
//! Lock-free implementation using atomics for high-performance concurrent access.

use crate::config::Config;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Rate limiter with per-key token buckets
#[derive(Debug)]
pub struct RateLimiter {
    config: Config,
    buckets: Arc<DashMap<String, Arc<TokenBucket>>>,
}

/// Token bucket for tracking request counts within a time window
#[derive(Debug)]
struct TokenBucket {
    /// Maximum requests per window
    capacity: u32,
    /// Current available tokens (atomic for lock-free access)
    tokens: AtomicU32,
    /// Window start timestamp (unix seconds)
    window_start: AtomicU64,
    /// Window duration in seconds
    window_seconds: u64,
}

/// Decision from rate limit check
#[derive(Debug, Clone)]
pub struct LimitDecision {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Configured limit for this rule
    pub limit: u32,
    /// Remaining requests in current window
    pub remaining: u32,
    /// Seconds until window resets (for Retry-After header)
    pub reset_seconds: u64,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration
    pub fn new(config: Config) -> Self {
        Self {
            config,
            buckets: Arc::new(DashMap::new()),
        }
    }

    /// Check if a request should be allowed
    ///
    /// # Arguments
    /// * `domain` - Rate limit domain (must match config.domain)
    /// * `descriptors` - Key-value pairs for rule matching
    ///
    /// # Returns
    /// `LimitDecision` with allow/deny and rate limit headers info
    pub fn check_limit(
        &self,
        domain: &str,
        descriptors: &HashMap<String, String>,
    ) -> LimitDecision {
        // Validate domain
        if domain != self.config.domain {
            // Unknown domain - fail open (allow)
            return LimitDecision {
                allowed: true,
                limit: 0,
                remaining: 0,
                reset_seconds: 0,
            };
        }

        // Find matching limit rule
        let (limit, window_seconds) = match self.config.find_limit(descriptors) {
            Some((l, w)) => (l, w),
            None => {
                // No matching rule - fail open (allow)
                return LimitDecision {
                    allowed: true,
                    limit: 0,
                    remaining: 0,
                    reset_seconds: 0,
                };
            }
        };

        // Generate bucket key from descriptors
        let key = self.make_key(descriptors);

        // Get or create bucket
        let bucket = self
            .buckets
            .entry(key)
            .or_insert_with(|| Arc::new(TokenBucket::new(limit, window_seconds)))
            .clone();

        // Try to consume token
        let now = Self::now();
        bucket.try_consume(now)
    }

    /// Build a cache key from descriptors (sorted for consistency)
    fn make_key(&self, descriptors: &HashMap<String, String>) -> String {
        let mut pairs: Vec<_> = descriptors.iter().collect();
        pairs.sort_by_key(|(k, _)| *k);

        pairs
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<_>>()
            .join("|")
    }

    /// Get current unix timestamp
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Get current number of tracked buckets (for metrics)
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Evict expired buckets to prevent memory growth
    ///
    /// Call this periodically (e.g., every minute) to clean up
    /// buckets that haven't been accessed recently.
    pub fn evict_expired(&self) {
        let now = Self::now();
        self.buckets.retain(|_, bucket| {
            let window_start = bucket.window_start.load(Ordering::Relaxed);
            let age = now.saturating_sub(window_start);
            // Keep if still in window or recently expired (2x window)
            age < bucket.window_seconds * 2
        });
    }

    /// Get a reference to the config
    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl TokenBucket {
    /// Create a new token bucket with full capacity
    fn new(capacity: u32, window_seconds: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            capacity,
            tokens: AtomicU32::new(capacity),
            window_start: AtomicU64::new(now),
            window_seconds,
        }
    }

    /// Try to consume a token, resetting window if expired
    ///
    /// Uses compare-exchange for lock-free operation.
    fn try_consume(&self, now: u64) -> LimitDecision {
        loop {
            let window_start = self.window_start.load(Ordering::Relaxed);
            let elapsed = now.saturating_sub(window_start);

            // Check if window expired - reset bucket
            if elapsed >= self.window_seconds {
                // Try to atomically reset window
                if self
                    .window_start
                    .compare_exchange(
                        window_start,
                        now,
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    // Successfully reset window, refill tokens
                    self.tokens.store(self.capacity, Ordering::Relaxed);
                }
                // Retry with new window state
                continue;
            }

            // Try to consume token
            let tokens = self.tokens.load(Ordering::Relaxed);
            if tokens == 0 {
                // Over limit - no tokens available
                let reset_seconds = self.window_seconds.saturating_sub(elapsed);
                return LimitDecision {
                    allowed: false,
                    limit: self.capacity,
                    remaining: 0,
                    reset_seconds,
                };
            }

            // Try to atomically decrement token count
            if self
                .tokens
                .compare_exchange(
                    tokens,
                    tokens - 1,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                // Success - token consumed
                let remaining = tokens - 1;
                let reset_seconds = self.window_seconds.saturating_sub(elapsed);
                return LimitDecision {
                    allowed: true,
                    limit: self.capacity,
                    remaining,
                    reset_seconds,
                };
            }

            // CAS failed (concurrent modification), retry
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_basic() {
        let bucket = TokenBucket::new(5, 60);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // First 5 requests should succeed
        for i in 0..5 {
            let decision = bucket.try_consume(now);
            assert!(decision.allowed, "Request {} should be allowed", i);
            assert_eq!(decision.remaining, 4 - i);
            assert_eq!(decision.limit, 5);
        }

        // 6th request should fail
        let decision = bucket.try_consume(now);
        assert!(!decision.allowed);
        assert_eq!(decision.remaining, 0);
        assert!(decision.reset_seconds > 0);
    }

    #[test]
    fn test_window_reset() {
        let bucket = TokenBucket::new(2, 1); // 2 requests per second
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Consume all tokens
        assert!(bucket.try_consume(now).allowed);
        assert!(bucket.try_consume(now).allowed);
        assert!(!bucket.try_consume(now).allowed); // Over limit

        // After window expires, should reset
        let future = now + 2;
        let decision = bucket.try_consume(future);
        assert!(decision.allowed);
        assert_eq!(decision.remaining, 1); // Capacity - 1
    }

    #[test]
    fn test_rate_limiter_unknown_domain() {
        let config = crate::config::Config::from_yaml(
            r#"
            domain: "known-domain"
            limits:
              - descriptors:
                  key: "*"
                requests: 1
                window_seconds: 60
            "#,
        )
        .unwrap();

        let limiter = RateLimiter::new(config);
        let descriptors = HashMap::new();

        // Unknown domain should fail open (allow)
        let decision = limiter.check_limit("unknown-domain", &descriptors);
        assert!(decision.allowed);
    }

    #[test]
    fn test_rate_limiter_no_matching_rule() {
        let config = crate::config::Config::from_yaml(
            r#"
            domain: "test"
            limits:
              - descriptors:
                  tool: "specific-tool"
                requests: 1
                window_seconds: 60
            "#,
        )
        .unwrap();

        let limiter = RateLimiter::new(config);

        let mut descriptors = HashMap::new();
        descriptors.insert("tool".to_string(), "other-tool".to_string());

        // No matching rule should fail open (allow)
        let decision = limiter.check_limit("test", &descriptors);
        assert!(decision.allowed);
    }

    #[test]
    fn test_rate_limiter_different_keys() {
        let config = crate::config::Config::from_yaml(
            r#"
            domain: "test"
            limits:
              - descriptors:
                  account: "*"
                requests: 2
                window_seconds: 60
            "#,
        )
        .unwrap();

        let limiter = RateLimiter::new(config);

        // Account A
        let mut desc_a = HashMap::new();
        desc_a.insert("account".to_string(), "account-a".to_string());

        // Account B
        let mut desc_b = HashMap::new();
        desc_b.insert("account".to_string(), "account-b".to_string());

        // Each account has independent bucket
        assert!(limiter.check_limit("test", &desc_a).allowed);
        assert!(limiter.check_limit("test", &desc_a).allowed);
        assert!(!limiter.check_limit("test", &desc_a).allowed); // A over limit

        // B should still have full quota
        assert!(limiter.check_limit("test", &desc_b).allowed);
        assert!(limiter.check_limit("test", &desc_b).allowed);
        assert!(!limiter.check_limit("test", &desc_b).allowed); // B over limit
    }

    #[test]
    fn test_bucket_count() {
        let config = crate::config::Config::from_yaml(
            r#"
            domain: "test"
            limits:
              - descriptors:
                  account: "*"
                requests: 100
                window_seconds: 60
            "#,
        )
        .unwrap();

        let limiter = RateLimiter::new(config);

        assert_eq!(limiter.bucket_count(), 0);

        let mut desc = HashMap::new();
        desc.insert("account".to_string(), "acc-1".to_string());
        limiter.check_limit("test", &desc);
        assert_eq!(limiter.bucket_count(), 1);

        desc.insert("account".to_string(), "acc-2".to_string());
        limiter.check_limit("test", &desc);
        assert_eq!(limiter.bucket_count(), 2);
    }
}
