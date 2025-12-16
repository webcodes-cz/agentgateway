//! ratelimit-core: Core rate limiting library for InferRouter
//!
//! This crate provides the core rate limiting logic extracted from sidecar-ratelimit-rs.
//! It can be used either as a standalone sidecar (via gRPC) or embedded in-process.
//!
//! # Example
//!
//! ```rust,ignore
//! use ratelimit_core::{RateLimiter, Config, check_ratelimit, RateLimitDecision};
//! use std::collections::HashMap;
//!
//! // Load config
//! let config = Config::from_yaml(r#"
//!     domain: "my-domain"
//!     limits:
//!       - descriptors: { model: "*", account: "*" }
//!         requests: 100
//!         window_seconds: 60
//! "#).unwrap();
//!
//! // Create limiter
//! let limiter = RateLimiter::new(config);
//!
//! // Check rate limit
//! let mut descriptors = HashMap::new();
//! descriptors.insert("model".to_string(), "gpt-4".to_string());
//! descriptors.insert("account".to_string(), "user-123".to_string());
//!
//! let decision = limiter.check_limit("my-domain", &descriptors);
//! match decision.allowed {
//!     true => println!("Request allowed, {} remaining", decision.remaining),
//!     false => println!("Rate limited, retry in {} seconds", decision.reset_seconds),
//! }
//! ```

pub mod config;
pub mod limiter;

// Re-export public types
pub use config::{Config, LimitRule};
pub use limiter::{LimitDecision, RateLimiter};

use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

/// Rate limit decision result (Phase 6 interface contract)
#[derive(Debug, Clone)]
pub enum RateLimitDecision {
    /// Request allowed
    Allow {
        /// Current count in window
        current: u32,
        /// Configured limit
        limit: u32,
        /// Remaining requests in window
        remaining: u32,
    },
    /// Request rate limited (HTTP 429)
    LimitExceeded {
        /// Time until rate limit resets (maps to Retry-After header)
        retry_after: Duration,
        /// Configured limit
        limit: u32,
    },
}

impl RateLimitDecision {
    /// Create an Allow decision from limiter internals
    pub fn allow(limit: u32, remaining: u32) -> Self {
        RateLimitDecision::Allow {
            current: limit.saturating_sub(remaining),
            limit,
            remaining,
        }
    }

    /// Create a LimitExceeded decision
    pub fn limit_exceeded(limit: u32, retry_after_secs: u64) -> Self {
        RateLimitDecision::LimitExceeded {
            retry_after: Duration::from_secs(retry_after_secs),
            limit,
        }
    }

    /// Check if the request is allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitDecision::Allow { .. })
    }
}

/// Error type for rate limit operations
#[derive(Error, Debug)]
pub enum RateLimitError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Check rate limit for a request
///
/// This is the public API entry point for Phase 6 in-process integration.
///
/// # Arguments
/// * `limiter` - The rate limiter instance
/// * `domain` - Rate limit domain (e.g., "inferrouter-llm")
/// * `descriptors` - Key-value pairs for rule matching (e.g., model, account)
///
/// # Returns
/// * `RateLimitDecision` - Allow or LimitExceeded
///
/// # Example
/// ```rust,ignore
/// let decision = check_ratelimit(&limiter, "inferrouter-llm", &descriptors);
/// if !decision.is_allowed() {
///     return HttpResponse::TooManyRequests();
/// }
/// ```
pub fn check_ratelimit(
    limiter: &RateLimiter,
    domain: &str,
    descriptors: &HashMap<String, String>,
) -> RateLimitDecision {
    let decision = limiter.check_limit(domain, descriptors);

    if decision.allowed {
        RateLimitDecision::Allow {
            current: decision.limit.saturating_sub(decision.remaining),
            limit: decision.limit,
            remaining: decision.remaining,
        }
    } else {
        RateLimitDecision::LimitExceeded {
            retry_after: Duration::from_secs(decision.reset_seconds),
            limit: decision.limit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_ratelimit_allow() {
        let config = Config::from_yaml(
            r#"
            domain: "test-domain"
            limits:
              - descriptors:
                  model: "*"
                  account: "*"
                requests: 10
                window_seconds: 60
            "#,
        )
        .unwrap();

        let limiter = RateLimiter::new(config);

        let mut descriptors = HashMap::new();
        descriptors.insert("model".to_string(), "gpt-4".to_string());
        descriptors.insert("account".to_string(), "user-123".to_string());

        let decision = check_ratelimit(&limiter, "test-domain", &descriptors);

        assert!(decision.is_allowed());
        match decision {
            RateLimitDecision::Allow {
                current,
                limit,
                remaining,
            } => {
                assert_eq!(limit, 10);
                assert_eq!(remaining, 9);
                assert_eq!(current, 1);
            }
            _ => panic!("Expected Allow decision"),
        }
    }

    #[test]
    fn test_check_ratelimit_exceeded() {
        let config = Config::from_yaml(
            r#"
            domain: "test-domain"
            limits:
              - descriptors:
                  model: "*"
                requests: 2
                window_seconds: 60
            "#,
        )
        .unwrap();

        let limiter = RateLimiter::new(config);

        let mut descriptors = HashMap::new();
        descriptors.insert("model".to_string(), "gpt-4".to_string());

        // Exhaust the limit
        assert!(check_ratelimit(&limiter, "test-domain", &descriptors).is_allowed());
        assert!(check_ratelimit(&limiter, "test-domain", &descriptors).is_allowed());

        // Third request should be limited
        let decision = check_ratelimit(&limiter, "test-domain", &descriptors);
        assert!(!decision.is_allowed());

        match decision {
            RateLimitDecision::LimitExceeded { retry_after, limit } => {
                assert_eq!(limit, 2);
                assert!(retry_after.as_secs() > 0);
            }
            _ => panic!("Expected LimitExceeded decision"),
        }
    }

    #[test]
    fn test_unknown_domain_allows() {
        let config = Config::from_yaml(
            r#"
            domain: "known-domain"
            limits:
              - descriptors:
                  model: "*"
                requests: 1
                window_seconds: 60
            "#,
        )
        .unwrap();

        let limiter = RateLimiter::new(config);

        let mut descriptors = HashMap::new();
        descriptors.insert("model".to_string(), "gpt-4".to_string());

        // Unknown domain should allow (fail-open)
        let decision = check_ratelimit(&limiter, "unknown-domain", &descriptors);
        assert!(decision.is_allowed());
    }
}
