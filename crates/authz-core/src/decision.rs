//! Core authorization decision logic
//!
//! Implements the L1 -> L2 -> Backhaul cascade for API key validation.

use crate::cache::{sha256_hex, L1Cache};
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, warn};

fn extract_metadata(body: &serde_json::Value) -> HashMap<String, String> {
    let mut metadata: HashMap<String, String> = HashMap::new();
    let Some(obj) = body.get("metadata").and_then(|m| m.as_object()) else {
        return metadata;
    };
    for (k, v) in obj {
        if v.is_null() {
            continue;
        }
        if let Some(s) = v.as_str() {
            metadata.insert(k.to_string(), s.to_string());
        } else {
            metadata.insert(k.to_string(), v.to_string());
        }
    }
    metadata
}

/// Configuration for authorization checks
#[derive(Clone, Debug)]
pub struct AuthzConfig {
    /// L1 cache TTL
    pub l1_ttl: Duration,
    /// L2 Redis TTL in seconds (only used when writing to Redis)
    pub l2_ttl: u64,
    /// Main API URL for backhaul validation
    pub backhaul_url: Option<String>,
    /// Service token for backhaul authentication
    pub service_token: Option<String>,
    /// Backhaul request timeout
    pub backhaul_timeout: Duration,
    /// Header name used for API key (for backhaul request)
    pub api_key_header: String,
}

impl Default for AuthzConfig {
    fn default() -> Self {
        Self {
            l1_ttl: Duration::from_secs(60),
            l2_ttl: 120,
            backhaul_url: None,
            service_token: None,
            backhaul_timeout: Duration::from_millis(180),
            api_key_header: "Authorization".to_string(),
        }
    }
}

/// Source of the authorization decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzSource {
    /// L1 in-memory cache hit
    L1Cache,
    /// L2 Redis cache hit
    L2Cache,
    /// Validated via backhaul to main API
    Backhaul,
}

/// Authorization decision result
#[derive(Debug, Clone)]
pub enum AuthzDecision {
    /// Request allowed
    Allow {
        /// Where the decision came from
        source: AuthzSource,
        /// Optional metadata (e.g., account_id from backhaul)
        metadata: HashMap<String, String>,
    },
    /// Request denied
    Deny {
        /// Reason for denial
        reason: String,
        /// HTTP status code to return
        status: u16,
        /// Where the decision came from (if cached)
        source: Option<AuthzSource>,
    },
}

impl AuthzDecision {
    /// Create an Allow decision
    pub fn allow(source: AuthzSource) -> Self {
        AuthzDecision::Allow {
            source,
            metadata: HashMap::new(),
        }
    }

    /// Create an Allow decision with metadata
    pub fn allow_with_metadata(source: AuthzSource, metadata: HashMap<String, String>) -> Self {
        AuthzDecision::Allow { source, metadata }
    }

    /// Create a Deny decision
    pub fn deny(reason: impl Into<String>, status: u16) -> Self {
        AuthzDecision::Deny {
            reason: reason.into(),
            status,
            source: None,
        }
    }

    /// Create a Deny decision from cache
    pub fn deny_cached(reason: impl Into<String>, status: u16, source: AuthzSource) -> Self {
        AuthzDecision::Deny {
            reason: reason.into(),
            status,
            source: Some(source),
        }
    }

    /// Check if the decision allows the request
    pub fn is_allowed(&self) -> bool {
        matches!(self, AuthzDecision::Allow { .. })
    }

    /// Get the source if this is an Allow decision
    pub fn source(&self) -> Option<AuthzSource> {
        match self {
            AuthzDecision::Allow { source, .. } => Some(*source),
            AuthzDecision::Deny { source, .. } => *source,
        }
    }
}

/// Metrics callback trait for recording authorization decisions
///
/// Implement this to integrate with your metrics system (Prometheus, etc.)
pub trait AuthzMetrics: Send + Sync {
    /// Record a decision outcome
    fn record_decision(&self, outcome: &str);
    /// Record decision latency
    fn record_latency(&self, seconds: f64);
    /// Record backhaul RTT
    fn record_backhaul_rtt(&self, seconds: f64);
}

/// No-op metrics implementation for testing
pub struct NoopMetrics;

impl AuthzMetrics for NoopMetrics {
    fn record_decision(&self, _outcome: &str) {}
    fn record_latency(&self, _seconds: f64) {}
    fn record_backhaul_rtt(&self, _seconds: f64) {}
}

/// Check authorization for an API key
///
/// Implements the L1 -> L2 -> Backhaul cascade:
/// 1. Check L1 in-memory cache
/// 2. Check L2 Redis cache (if configured)
/// 3. Fall back to backhaul validation (if configured)
/// 4. Fail-closed (deny) if all sources fail
///
/// # Arguments
/// * `api_key` - The API key to validate (already extracted from request)
/// * `config` - Authorization configuration
/// * `cache` - L1 in-memory cache
/// * `redis` - Optional L2 Redis connection (wrapped in Option for interior mutability)
/// * `http` - HTTP client for backhaul
/// * `metrics` - Metrics recorder
///
/// # Returns
/// `AuthzDecision` - Allow or Deny with reason
pub async fn check_authz(
    api_key: &str,
    config: &AuthzConfig,
    cache: &L1Cache,
    mut redis: Option<redis::aio::ConnectionManager>,
    http: &Client,
    metrics: &dyn AuthzMetrics,
) -> AuthzDecision {
    let start = std::time::Instant::now();
    let hashed = sha256_hex(api_key);

    // L1 cache check
    if let Some(entry) = cache.get(&hashed) {
        let outcome = if entry.allow { "allow_l1" } else { "deny_l1" };
        metrics.record_decision(outcome);
        metrics.record_latency(start.elapsed().as_secs_f64());

        if entry.allow {
            debug!(api_key_hash = %hashed, "L1 cache hit: allow");
            return AuthzDecision::allow_with_metadata(AuthzSource::L1Cache, entry.metadata);
        } else {
            debug!(api_key_hash = %hashed, "L1 cache hit: deny");
            return AuthzDecision::deny_cached("denied", 401, AuthzSource::L1Cache);
        }
    }

    // L2 Redis cache check
    if let Some(ref mut conn) = redis {
        let redis_key = format!("apikey:{}", hashed);
        let result: Result<Option<String>, _> =
            redis::Cmd::get(&redis_key).query_async(conn).await;

        if let Ok(Some(value)) = result {
            if value.starts_with("allow:") {
                metrics.record_decision("allow_l2");
                let mut metadata: HashMap<String, String> = HashMap::new();
                if let Some(raw_meta) = value.strip_prefix("allow:") {
                    let raw_meta = raw_meta.trim();
                    if !raw_meta.is_empty() {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(raw_meta) {
                            if parsed.is_object() {
                                // Stored as a raw JSON object (recommended)
                                if let Some(obj) = parsed.as_object() {
                                    for (k, v) in obj {
                                        if v.is_null() {
                                            continue;
                                        }
                                        if let Some(s) = v.as_str() {
                                            metadata.insert(k.to_string(), s.to_string());
                                        } else {
                                            metadata.insert(k.to_string(), v.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                cache.put(hashed.clone(), true, metadata.clone(), config.l1_ttl);
                metrics.record_latency(start.elapsed().as_secs_f64());
                debug!(api_key_hash = %hashed, "L2 cache hit: allow");
                return AuthzDecision::allow_with_metadata(AuthzSource::L2Cache, metadata);
            } else if value == "deny" {
                metrics.record_decision("deny_l2");
                cache.put(hashed.clone(), false, HashMap::new(), config.l1_ttl);
                metrics.record_latency(start.elapsed().as_secs_f64());
                debug!(api_key_hash = %hashed, "L2 cache hit: deny");
                return AuthzDecision::deny_cached("denied", 401, AuthzSource::L2Cache);
            }
        }
    }

    // Backhaul validation
    if let Some(base_url) = &config.backhaul_url {
        let url = format!(
            "{}/internal/gateway/authz/api-key",
            base_url.trim_end_matches('/')
        );

        let mut req = http.post(&url);
        if let Some(token) = &config.service_token {
            req = req.header("X-Service-Token", token);
        }

        // Send API key in appropriate header
        if config.api_key_header.eq_ignore_ascii_case("authorization") {
            req = req.header("Authorization", format!("Bearer {}", api_key));
        } else {
            req = req.header("X-API-Key", api_key);
        }

        let backhaul_start = std::time::Instant::now();
        let result = req.timeout(config.backhaul_timeout).send().await;
        metrics.record_backhaul_rtt(backhaul_start.elapsed().as_secs_f64());

        match result {
            Ok(resp) => {
                if resp.status().as_u16() == 200 {
                    let body = resp
                        .json::<serde_json::Value>()
                        .await
                        .unwrap_or(serde_json::json!({"allow": false}));

                    let allow = body.get("allow").and_then(|b| b.as_bool()).unwrap_or(false);

                    if allow {
                        metrics.record_decision("allow_backhaul");

                        let metadata = extract_metadata(&body);

                        // Cache the allow result
                        cache.put(hashed.clone(), true, metadata.clone(), config.l1_ttl);

                        // Write to L2 Redis if available
                        if let Some(ref mut conn) = redis {
                            let redis_key = format!("apikey:{}", hashed);
                            let payload = if metadata.is_empty() {
                                "allow:".to_string()
                            } else {
                                format!(
                                    "allow:{}",
                                    serde_json::to_string(&metadata).unwrap_or_default()
                                )
                            };
                            let _: Result<(), _> = redis::Cmd::set_ex(
                                &redis_key,
                                payload,
                                config.l2_ttl,
                            )
                            .query_async(conn)
                            .await;
                        }

                        metrics.record_latency(start.elapsed().as_secs_f64());
                        debug!(api_key_hash = %hashed, "Backhaul: allow");
                        return AuthzDecision::allow_with_metadata(AuthzSource::Backhaul, metadata);
                    } else {
                        metrics.record_decision("deny_backhaul");

                        // Cache the deny result
                        cache.put(hashed.clone(), false, HashMap::new(), config.l1_ttl);

                        // Write to L2 Redis if available
                        if let Some(ref mut conn) = redis {
                            let redis_key = format!("apikey:{}", hashed);
                            let _: Result<(), _> = redis::Cmd::set_ex(
                                &redis_key,
                                "deny",
                                config.l2_ttl,
                            )
                            .query_async(conn)
                            .await;
                        }

                        metrics.record_latency(start.elapsed().as_secs_f64());
                        debug!(api_key_hash = %hashed, "Backhaul: deny");
                        return AuthzDecision::deny("denied", 401);
                    }
                }
                // Non-200 response - fall through to error handling
                warn!(
                    api_key_hash = %hashed,
                    status = resp.status().as_u16(),
                    "Backhaul returned non-200 status"
                );
            }
            Err(e) => {
                warn!(api_key_hash = %hashed, error = %e, "Backhaul request failed");
            }
        }
    }

    // Default deny on failure (fail-closed)
    metrics.record_decision("deny_error");
    metrics.record_latency(start.elapsed().as_secs_f64());
    warn!(api_key_hash = %hashed, "Authz unavailable - denying request");
    AuthzDecision::deny("authz unavailable", 503)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_l1_cache_hit_allow() {
        let cache = L1Cache::new();
        let config = AuthzConfig::default();
        let http = Client::new();
        let metrics = NoopMetrics;

        // Pre-populate cache
        let hashed = sha256_hex("test-key");
        cache.put(hashed, true, HashMap::new(), Duration::from_secs(60));

        let decision = check_authz("test-key", &config, &cache, None, &http, &metrics).await;

        assert!(decision.is_allowed());
        assert_eq!(decision.source(), Some(AuthzSource::L1Cache));
    }

    #[tokio::test]
    async fn test_l1_cache_hit_deny() {
        let cache = L1Cache::new();
        let config = AuthzConfig::default();
        let http = Client::new();
        let metrics = NoopMetrics;

        // Pre-populate cache with deny
        let hashed = sha256_hex("bad-key");
        cache.put(hashed, false, HashMap::new(), Duration::from_secs(60));

        let decision = check_authz("bad-key", &config, &cache, None, &http, &metrics).await;

        assert!(!decision.is_allowed());
        assert_eq!(decision.source(), Some(AuthzSource::L1Cache));
    }

    #[tokio::test]
    async fn test_no_cache_no_backhaul_denies() {
        let cache = L1Cache::new();
        let config = AuthzConfig {
            backhaul_url: None, // No backhaul configured
            ..Default::default()
        };
        let http = Client::new();
        let metrics = NoopMetrics;

        let decision = check_authz("unknown-key", &config, &cache, None, &http, &metrics).await;

        assert!(!decision.is_allowed());
        match decision {
            AuthzDecision::Deny { reason, status, .. } => {
                assert_eq!(status, 503);
                assert_eq!(reason, "authz unavailable");
            }
            _ => panic!("Expected Deny"),
        }
    }

    #[test]
    fn test_authz_decision_helpers() {
        let allow = AuthzDecision::allow(AuthzSource::L1Cache);
        assert!(allow.is_allowed());

        let deny = AuthzDecision::deny("invalid", 401);
        assert!(!deny.is_allowed());
    }
}
