//! Phase 6B: In-process AuthZ and RateLimit configuration
//!
//! This module provides configuration types for running authorization and rate limiting
//! directly in-process within Agentgateway, rather than via external sidecar services.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Mode for AuthZ handling
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthzMode {
    /// Use external sidecar service (default, legacy behavior)
    #[default]
    Sidecar,
    /// Use in-process authorization (Phase 6B)
    #[cfg(feature = "inproc")]
    Inproc,
    /// Disable authorization entirely (dev/testing only)
    Disabled,
}

/// Mode for RateLimit handling
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitMode {
    /// Use external sidecar service (default, legacy behavior)
    #[default]
    Sidecar,
    /// Use in-process rate limiting (Phase 6B)
    #[cfg(feature = "inproc")]
    Inproc,
    /// Disable rate limiting entirely (dev/testing only)
    Disabled,
}

/// Raw configuration for in-process authorization (parsed from YAML)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RawAuthzConfig {
    /// Mode: "sidecar" (default), "inproc", or "disabled"
    pub mode: AuthzMode,
    /// Header containing API key (default: "X-API-Key")
    pub header: Option<String>,
    /// Backhaul configuration for API key validation
    pub backhaul: Option<RawAuthzBackhaul>,
    /// Cache configuration
    pub cache: Option<RawAuthzCache>,
    /// Fail-open on internal errors (default: false for authz)
    #[serde(default)]
    pub fail_open: bool,
}

/// Backhaul configuration for authz
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawAuthzBackhaul {
    /// URL of the main API for API key validation
    pub url: String,
    /// Service token for authentication
    pub service_token: Option<String>,
    /// Timeout in milliseconds (default: 180)
    #[serde(default = "defaults::backhaul_timeout_ms")]
    pub timeout_ms: u64,
}

/// Cache configuration for authz
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RawAuthzCache {
    /// L1 (in-memory) cache TTL in seconds (default: 60)
    #[serde(default = "defaults::l1_ttl_seconds")]
    pub l1_ttl_seconds: u64,
    /// L2 (Redis) cache configuration
    pub l2: Option<RawL2Cache>,
}

/// L2 (Redis) cache configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawL2Cache {
    /// Whether L2 cache is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Redis URL
    pub redis_url: Option<String>,
    /// TTL in seconds (default: 120)
    #[serde(default = "defaults::l2_ttl_seconds")]
    pub ttl_seconds: u64,
}

/// Raw configuration for in-process rate limiting (parsed from YAML)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RawRateLimitConfig {
    /// Mode: "sidecar" (default), "inproc", or "disabled"
    pub mode: RateLimitMode,
    /// Fail-open on internal errors (default: true for ratelimit)
    #[serde(default = "defaults::ratelimit_fail_open")]
    pub fail_open: bool,
    /// Maximum number of rate limit keys to track
    #[serde(default = "defaults::max_keys")]
    pub max_keys: usize,
    /// Rate limit domains and their rules
    #[serde(default)]
    pub domains: Vec<RawRateLimitDomain>,
}

/// Rate limit domain configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawRateLimitDomain {
    /// Domain name (e.g., "inferrouter-llm", "inferrouter-mcp")
    pub name: String,
    /// Rate limit rules for this domain
    #[serde(default)]
    pub limits: Vec<RawRateLimitRule>,
}

/// Rate limit rule configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawRateLimitRule {
    /// Descriptors to match (e.g., {"model": "*", "account": "*"})
    pub descriptors: std::collections::HashMap<String, String>,
    /// Number of requests allowed
    pub requests: u32,
    /// Window size in seconds
    pub window_seconds: u64,
}

mod defaults {
    pub fn backhaul_timeout_ms() -> u64 {
        180
    }
    pub fn l1_ttl_seconds() -> u64 {
        60
    }
    pub fn l2_ttl_seconds() -> u64 {
        120
    }
    pub fn ratelimit_fail_open() -> bool {
        true
    }
    pub fn max_keys() -> usize {
        10000
    }
}

// ============================================================================
// Internal configuration (resolved from raw config)
// ============================================================================

/// Resolved AuthZ configuration
#[derive(Debug, Clone)]
pub struct AuthzConfig {
    pub mode: AuthzMode,
    pub header: String,
    pub backhaul_url: Option<String>,
    pub service_token: Option<String>,
    pub backhaul_timeout: Duration,
    pub l1_ttl: Duration,
    pub l2_redis_url: Option<String>,
    pub l2_ttl: Duration,
    pub fail_open: bool,
}

impl Default for AuthzConfig {
    fn default() -> Self {
        Self {
            mode: AuthzMode::Sidecar,
            header: "X-API-Key".to_string(),
            backhaul_url: None,
            service_token: None,
            backhaul_timeout: Duration::from_millis(180),
            l1_ttl: Duration::from_secs(60),
            l2_redis_url: None,
            l2_ttl: Duration::from_secs(120),
            fail_open: false,
        }
    }
}

impl From<RawAuthzConfig> for AuthzConfig {
    fn from(raw: RawAuthzConfig) -> Self {
        let (backhaul_url, service_token, backhaul_timeout) = raw
            .backhaul
            .map(|b| {
                (
                    Some(b.url),
                    b.service_token,
                    Duration::from_millis(b.timeout_ms),
                )
            })
            .unwrap_or((None, None, Duration::from_millis(180)));

        let cache = raw.cache.unwrap_or_default();
        let (l2_redis_url, l2_ttl) = cache
            .l2
            .filter(|l2| l2.enabled)
            .map(|l2| (l2.redis_url, Duration::from_secs(l2.ttl_seconds)))
            .unwrap_or((None, Duration::from_secs(120)));

        Self {
            mode: raw.mode,
            header: raw.header.unwrap_or_else(|| "X-API-Key".to_string()),
            backhaul_url,
            service_token,
            backhaul_timeout,
            l1_ttl: Duration::from_secs(cache.l1_ttl_seconds),
            l2_redis_url,
            l2_ttl,
            fail_open: raw.fail_open,
        }
    }
}

/// Resolved RateLimit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub mode: RateLimitMode,
    pub fail_open: bool,
    pub max_keys: usize,
    pub domains: Vec<RateLimitDomain>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            mode: RateLimitMode::Sidecar,
            fail_open: true,
            max_keys: 10000,
            domains: vec![],
        }
    }
}

impl From<RawRateLimitConfig> for RateLimitConfig {
    fn from(raw: RawRateLimitConfig) -> Self {
        Self {
            mode: raw.mode,
            fail_open: raw.fail_open,
            max_keys: raw.max_keys,
            domains: raw.domains.into_iter().map(RateLimitDomain::from).collect(),
        }
    }
}

/// Resolved rate limit domain
#[derive(Debug, Clone)]
pub struct RateLimitDomain {
    pub name: String,
    pub limits: Vec<RateLimitRule>,
}

impl From<RawRateLimitDomain> for RateLimitDomain {
    fn from(raw: RawRateLimitDomain) -> Self {
        Self {
            name: raw.name,
            limits: raw.limits.into_iter().map(RateLimitRule::from).collect(),
        }
    }
}

/// Resolved rate limit rule
#[derive(Debug, Clone)]
pub struct RateLimitRule {
    pub descriptors: std::collections::HashMap<String, String>,
    pub requests: u32,
    pub window_seconds: u64,
}

impl From<RawRateLimitRule> for RateLimitRule {
    fn from(raw: RawRateLimitRule) -> Self {
        Self {
            descriptors: raw.descriptors,
            requests: raw.requests,
            window_seconds: raw.window_seconds,
        }
    }
}

// ============================================================================
// Helper to check if JWT was already validated (Phase 6B regression fix)
// ============================================================================

/// Check if JWT was already validated by JWT policy.
///
/// The JWT policy runs before in-process authz, validates the token,
/// removes the Authorization header, and inserts Claims into request extensions.
/// If Claims exist in extensions, JWT auth already succeeded.
///
/// This function exists to prevent regression of the bug where we tried to detect
/// JWT by looking at the Authorization header, which is removed by JWT policy.
pub fn is_jwt_validated<T>(extensions: &http::Extensions) -> bool
where
    T: Send + Sync + 'static,
{
    extensions.get::<T>().is_some()
}

// ============================================================================
// Helper to extract API key from request headers
// ============================================================================

/// Extract API key from request headers
pub fn extract_api_key(
    headers: &http::HeaderMap,
    header_name: &str,
) -> Option<String> {
    let header_lower = header_name.to_ascii_lowercase();

    // Try configured header first
    if let Some(value) = headers.get(header_name) {
        if let Ok(s) = value.to_str() {
            let trimmed = s.trim();
            // If Authorization header, strip "Bearer " prefix
            if header_lower == "authorization" {
                let key = trimmed
                    .strip_prefix("Bearer ")
                    .or_else(|| trimmed.strip_prefix("bearer "))
                    .unwrap_or(trimmed);
                if !key.is_empty() {
                    return Some(key.to_string());
                }
            } else if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    // Fallback: if configured header is Authorization and empty, try X-API-Key
    if header_lower == "authorization" {
        if let Some(value) = headers.get("x-api-key") {
            if let Ok(s) = value.to_str() {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }

    None
}

// ============================================================================
// Runtime state for in-process AuthZ and RateLimit (Phase 6B)
// ============================================================================

#[cfg(feature = "inproc")]
pub mod runtime {
    use super::*;

    /// Runtime state for in-process authorization
    pub struct AuthzRuntime {
        /// L1 in-memory cache
        pub cache: authz_core::L1Cache,
        /// HTTP client for backhaul requests
        pub http: reqwest::Client,
    }

    impl AuthzRuntime {
        /// Create a new AuthzRuntime
        pub fn new() -> Self {
            Self {
                cache: authz_core::L1Cache::new(),
                http: reqwest::Client::new(),
            }
        }

        /// Convert our AuthzConfig to authz_core::AuthzConfig
        pub fn build_core_config(config: &AuthzConfig) -> authz_core::AuthzConfig {
            authz_core::AuthzConfig {
                l1_ttl: config.l1_ttl,
                l2_ttl: config.l2_ttl.as_secs(),
                backhaul_url: config.backhaul_url.clone(),
                service_token: config.service_token.clone(),
                backhaul_timeout: config.backhaul_timeout,
                api_key_header: config.header.clone(),
            }
        }

        /// Check authorization for an API key
        pub async fn check_authz(
            &self,
            api_key: &str,
            config: &AuthzConfig,
        ) -> authz_core::AuthzDecision {
            let core_config = Self::build_core_config(config);
            authz_core::check_authz(
                api_key,
                &core_config,
                &self.cache,
                None, // No Redis for now (TODO: add L2 support)
                &self.http,
                &authz_core::NoopMetrics,
            )
            .await
        }
    }

    impl Default for AuthzRuntime {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Runtime state for in-process rate limiting
    pub struct RateLimitRuntime {
        /// Rate limiter instance (one per domain)
        limiters: std::collections::HashMap<String, ratelimit_core::RateLimiter>,
    }

    impl RateLimitRuntime {
        /// Create a new RateLimitRuntime from config
        pub fn new(config: &RateLimitConfig) -> Self {
            let mut limiters = std::collections::HashMap::new();

            for domain in &config.domains {
                // Build YAML config for this domain
                let yaml_config = Self::build_domain_yaml(&domain, config.fail_open, config.max_keys);
                if let Ok(core_config) = ratelimit_core::Config::from_yaml(&yaml_config) {
                    limiters.insert(
                        domain.name.clone(),
                        ratelimit_core::RateLimiter::new(core_config),
                    );
                }
            }

            Self { limiters }
        }

        /// Build YAML config for a domain
        fn build_domain_yaml(domain: &RateLimitDomain, fail_open: bool, max_keys: usize) -> String {
            let mut yaml = format!(
                "domain: \"{}\"\nfail_open: {}\nmax_keys: {}\nlimits:\n",
                domain.name, fail_open, max_keys
            );

            for rule in &domain.limits {
                yaml.push_str("  - descriptors:\n");
                for (k, v) in &rule.descriptors {
                    yaml.push_str(&format!("      {}: \"{}\"\n", k, v));
                }
                yaml.push_str(&format!("    requests: {}\n", rule.requests));
                yaml.push_str(&format!("    window_seconds: {}\n", rule.window_seconds));
            }

            yaml
        }

        /// Check rate limit for a request
        pub fn check_ratelimit(
            &self,
            domain: &str,
            descriptors: &std::collections::HashMap<String, String>,
        ) -> ratelimit_core::RateLimitDecision {
            if let Some(limiter) = self.limiters.get(domain) {
                ratelimit_core::check_ratelimit(limiter, domain, descriptors)
            } else {
                // Unknown domain - allow (fail-open behavior)
                ratelimit_core::RateLimitDecision::Allow {
                    current: 0,
                    limit: 0,
                    remaining: 0,
                }
            }
        }
    }

    impl Default for RateLimitRuntime {
        fn default() -> Self {
            Self {
                limiters: std::collections::HashMap::new(),
            }
        }
    }

    /// Combined runtime state for both AuthZ and RateLimit
    pub struct InprocRuntime {
        pub authz: AuthzRuntime,
        pub ratelimit: RateLimitRuntime,
    }

    impl InprocRuntime {
        /// Create a new InprocRuntime from config
        pub fn new(_authz_config: &AuthzConfig, ratelimit_config: &RateLimitConfig) -> Self {
            Self {
                authz: AuthzRuntime::new(),
                ratelimit: RateLimitRuntime::new(ratelimit_config),
            }
        }
    }
}

#[cfg(feature = "inproc")]
pub use runtime::{AuthzRuntime, InprocRuntime, RateLimitRuntime};

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    #[test]
    fn test_extract_api_key_x_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "test-key-123".parse().unwrap());

        assert_eq!(
            extract_api_key(&headers, "X-API-Key"),
            Some("test-key-123".to_string())
        );
    }

    #[test]
    fn test_extract_api_key_authorization_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-key-456".parse().unwrap());

        assert_eq!(
            extract_api_key(&headers, "Authorization"),
            Some("test-key-456".to_string())
        );
    }

    #[test]
    fn test_extract_api_key_fallback() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "fallback-key".parse().unwrap());

        // When Authorization is configured but missing, fall back to X-API-Key
        assert_eq!(
            extract_api_key(&headers, "Authorization"),
            Some("fallback-key".to_string())
        );
    }

    #[test]
    fn test_extract_api_key_empty() {
        let headers = HeaderMap::new();
        assert_eq!(extract_api_key(&headers, "X-API-Key"), None);
    }

    // ========================================================================
    // Phase 6B regression test: JWT passthrough via extensions (not header)
    // ========================================================================
    //
    // This test guards against the bug where we tried to detect JWT by looking
    // at the Authorization header, which is removed by JWT policy BEFORE our
    // in-process authz check runs.
    //
    // The correct approach is to check for Claims in request extensions.
    // ========================================================================

    /// Dummy Claims type for testing (simulates jwt::Claims)
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct TestJwtClaims {
        sub: String,
    }

    #[test]
    fn test_jwt_passthrough_via_extensions_not_header() {
        use super::is_jwt_validated;

        // Scenario: JWT policy has run, validated the token, removed Authorization
        // header, and inserted Claims into extensions.

        let mut extensions = http::Extensions::new();

        // Before: no Claims in extensions -> not JWT validated
        assert!(
            !is_jwt_validated::<TestJwtClaims>(&extensions),
            "Should return false when no Claims in extensions"
        );

        // After JWT policy: Claims inserted into extensions
        extensions.insert(TestJwtClaims {
            sub: "user-123".to_string(),
        });

        // Now: Claims exist -> JWT validated (even without Authorization header)
        assert!(
            is_jwt_validated::<TestJwtClaims>(&extensions),
            "Should return true when Claims exist in extensions (JWT already validated)"
        );
    }

    #[test]
    fn test_jwt_passthrough_authorization_header_irrelevant() {
        use super::is_jwt_validated;

        // This test verifies that the presence/absence of Authorization header
        // does NOT affect JWT detection. Only Claims in extensions matters.

        let mut headers = HeaderMap::new();
        let mut extensions = http::Extensions::new();

        // Case 1: Authorization header present, but no Claims
        // This would happen if JWT validation failed or JWT policy didn't run
        headers.insert("authorization", "Bearer eyJhbGc...".parse().unwrap());
        assert!(
            !is_jwt_validated::<TestJwtClaims>(&extensions),
            "Authorization header alone should NOT indicate JWT validated"
        );

        // Case 2: No Authorization header, but Claims present
        // This is the normal case after JWT policy runs (header removed, claims inserted)
        headers.remove("authorization");
        extensions.insert(TestJwtClaims {
            sub: "user-456".to_string(),
        });
        assert!(
            is_jwt_validated::<TestJwtClaims>(&extensions),
            "Claims in extensions should indicate JWT validated, regardless of header"
        );
    }
}
