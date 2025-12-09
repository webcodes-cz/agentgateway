//! Token Limit Enforcement for Agentgateway
//!
//! This module provides account limit state caching and enforcement for
//! InferRouter's billing system. AG acts as a "policeman" - it does NOT
//! calculate limits, only enforces blocked_* flags from the backend.
//!
//! Architecture:
//! - Backend VIEW `account_limit_state` calculates blocked_* flags
//! - AG fetches snapshot every 60s via `/internal/limits/snapshot`
//! - AG stores in HashMap for O(1) per-request lookup
//! - AG checks blocked_* flags and returns 429/402 errors
//!
//! The AG is tier-agnostic - it doesn't know or care about tier.
//! All billing logic lives in the backend.

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Configuration for limits enforcement (parsed from YAML)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RawLimitsConfig {
    /// Whether limits enforcement is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Backend URL for fetching limits snapshot
    pub backend_url: Option<String>,

    /// Service token for authentication (X-Service-Token header)
    pub service_token: Option<String>,

    /// Refresh interval in seconds (default: 60)
    #[serde(default = "defaults::refresh_interval_secs")]
    pub refresh_interval_secs: u64,

    /// Request timeout in seconds (default: 5)
    #[serde(default = "defaults::request_timeout_secs")]
    pub request_timeout_secs: u64,

    /// Fail-open on fetch errors (default: true)
    #[serde(default = "defaults::fail_open")]
    pub fail_open: bool,

    /// BYOR (Bring Your Own Router) configuration
    #[serde(default)]
    pub byor: RawByorConfig,
}

/// BYOR configuration for private gateway binding
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RawByorConfig {
    /// Whether BYOR mode is enabled (restricts gateway to single owner)
    #[serde(default)]
    pub enabled: bool,

    /// Owner account ID - only this account can use this gateway
    /// Required when byor.enabled = true
    pub owner_account_id: Option<String>,
}

mod defaults {
    pub fn refresh_interval_secs() -> u64 {
        60
    }
    pub fn request_timeout_secs() -> u64 {
        5
    }
    pub fn fail_open() -> bool {
        true
    }
}

/// Resolved limits configuration
#[derive(Debug, Clone)]
pub struct LimitsConfig {
    pub enabled: bool,
    pub backend_url: String,
    pub service_token: Option<String>,
    pub refresh_interval: Duration,
    pub request_timeout: Duration,
    pub fail_open: bool,
    pub byor: ByorConfig,
}

/// Resolved BYOR configuration
#[derive(Debug, Clone, Default)]
pub struct ByorConfig {
    pub enabled: bool,
    pub owner_account_id: Option<String>,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend_url: "https://api.inferrouter.com".to_string(),
            service_token: None,
            refresh_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(5),
            fail_open: true,
            byor: ByorConfig::default(),
        }
    }
}

impl From<RawLimitsConfig> for LimitsConfig {
    fn from(raw: RawLimitsConfig) -> Self {
        Self {
            enabled: raw.enabled,
            backend_url: raw
                .backend_url
                .unwrap_or_else(|| "https://api.inferrouter.com".to_string()),
            service_token: raw.service_token,
            refresh_interval: Duration::from_secs(raw.refresh_interval_secs),
            request_timeout: Duration::from_secs(raw.request_timeout_secs),
            fail_open: raw.fail_open,
            byor: ByorConfig {
                enabled: raw.byor.enabled,
                owner_account_id: raw.byor.owner_account_id,
            },
        }
    }
}

/// Account limit state from backend snapshot.
///
/// NOTE: No `tier` field - AG is tier-agnostic!
/// Backend calculates blocked_* flags based on tier internally.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccountLimitState {
    pub account_id: String,

    /// True if daily/monthly token cap reached
    pub blocked_prepaid: bool,

    /// True if BYOK monthly limit reached
    pub blocked_byok: bool,

    /// True if credit balance depleted (for paid models)
    pub blocked_credit: bool,

    /// Reason for prepaid block: "daily_cap" | "monthly_cap" | null
    pub prepaid_reason: Option<String>,

    /// Tokens used today
    pub daily_used: i64,

    /// Daily token limit (-1 = unlimited)
    pub daily_limit: i64,

    /// Tokens used this month
    pub monthly_used: i64,

    /// Monthly token limit (-1 = unlimited, 0 = N/A)
    pub monthly_limit: i64,

    /// BYOK requests this month
    pub byok_used: i64,

    /// BYOK limit (-1 = unlimited)
    pub byok_limit: i64,

    /// Credit balance in EUR
    pub credit_balance: f64,

    /// Next daily reset (UTC)
    pub daily_reset_at: DateTime<Utc>,

    /// Next monthly reset (UTC)
    pub monthly_reset_at: DateTime<Utc>,
}

/// Response from /internal/limits/snapshot endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct AccountLimitSnapshot {
    pub accounts: Vec<AccountLimitState>,
    pub count: usize,
    pub timestamp: DateTime<Utc>,
}

/// Thread-safe cache of account limit states
pub struct LimitsCache {
    entries: RwLock<HashMap<String, AccountLimitState>>,
    last_refresh: RwLock<Option<DateTime<Utc>>>,
    config: LimitsConfig,
}

impl LimitsCache {
    /// Create a new LimitsCache with configuration
    pub fn new(config: LimitsConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(None),
            config,
        }
    }

    /// Check if limits enforcement is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get limit state for an account (O(1) lookup)
    pub fn get(&self, account_id: &str) -> Option<AccountLimitState> {
        self.entries.read().get(account_id).cloned()
    }

    /// Update cache from snapshot response (full replace)
    pub fn update_from_snapshot(&self, snapshot: AccountLimitSnapshot) {
        let mut entries = self.entries.write();
        entries.clear();
        for state in snapshot.accounts {
            entries.insert(state.account_id.clone(), state);
        }
        drop(entries);

        let mut last = self.last_refresh.write();
        *last = Some(snapshot.timestamp);
    }

    /// Get timestamp of last successful refresh
    pub fn last_refresh_time(&self) -> Option<DateTime<Utc>> {
        *self.last_refresh.read()
    }

    /// Check if cache is populated
    pub fn is_ready(&self) -> bool {
        self.last_refresh.read().is_some()
    }

    /// Get stats for monitoring
    pub fn stats(&self) -> (usize, Option<DateTime<Utc>>) {
        let count = self.entries.read().len();
        let last = self.last_refresh_time();
        (count, last)
    }

    /// Get configuration
    pub fn config(&self) -> &LimitsConfig {
        &self.config
    }
}

impl std::fmt::Debug for LimitsCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (count, last) = self.stats();
        f.debug_struct("LimitsCache")
            .field("entries_count", &count)
            .field("last_refresh", &last)
            .field("enabled", &self.config.enabled)
            .finish()
    }
}

/// Model type for limit checking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelType {
    /// Free internal model (prepaid caps apply)
    Free,
    /// BYOK model (BYOK limits apply)
    Byok,
    /// Paid local model (credit balance applies)
    LocalPaid,
}

impl ModelType {
    /// Detect model type from backend metadata provider field
    pub fn from_provider(provider: Option<&str>) -> Self {
        match provider {
            Some(p) if p.ends_with("_byok") => ModelType::Byok,
            Some(p) if p.contains("paid") || p.contains("premium") => ModelType::LocalPaid,
            _ => ModelType::Free,
        }
    }
}

/// Error types for limit violations
#[derive(Debug, Clone)]
pub enum LimitError {
    PrepaidCapExceeded {
        reason: String,
        daily_used: i64,
        daily_limit: i64,
        monthly_used: i64,
        monthly_limit: i64,
        reset_at: DateTime<Utc>,
    },
    ByokLimitExceeded {
        byok_used: i64,
        byok_limit: i64,
        reset_at: DateTime<Utc>,
    },
    InsufficientCredits {
        balance: f64,
    },
    /// BYOR access denied - account doesn't own this gateway
    ByorAccessDenied {
        account_id: String,
        owner_account_id: String,
    },
}

impl std::fmt::Display for LimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitError::PrepaidCapExceeded { reason, .. } => {
                write!(f, "Prepaid cap exceeded: {}", reason)
            }
            LimitError::ByokLimitExceeded { .. } => write!(f, "BYOK limit exceeded"),
            LimitError::InsufficientCredits { balance } => {
                write!(f, "Insufficient credits: {:.2} EUR", balance)
            }
            LimitError::ByorAccessDenied { .. } => {
                write!(f, "Access denied: this gateway is restricted to its owner")
            }
        }
    }
}

impl std::error::Error for LimitError {}

/// Check BYOR access - verify account owns this gateway.
///
/// Call this BEFORE check_account_limits() when BYOR is enabled.
/// Returns Ok(()) if access allowed, Err(ByorAccessDenied) if not.
pub fn check_byor_access(
    account_id: &str,
    config: &LimitsConfig,
) -> Result<(), LimitError> {
    // Skip if BYOR not enabled
    if !config.byor.enabled {
        return Ok(());
    }

    // BYOR enabled but no owner configured - misconfiguration, fail-closed
    let owner = match &config.byor.owner_account_id {
        Some(id) => id,
        None => {
            warn!("BYOR enabled but no owner_account_id configured - denying access");
            return Err(LimitError::ByorAccessDenied {
                account_id: account_id.to_string(),
                owner_account_id: "not_configured".to_string(),
            });
        }
    };

    // Check if account matches owner
    if account_id != owner {
        debug!(
            account_id,
            owner_account_id = %owner,
            "BYOR access denied - account doesn't own this gateway"
        );
        return Err(LimitError::ByorAccessDenied {
            account_id: account_id.to_string(),
            owner_account_id: owner.clone(),
        });
    }

    debug!(account_id, "BYOR access granted");
    Ok(())
}

/// Check account limits before routing request.
///
/// Returns Ok(()) on success or LimitError on failure.
/// NOTE: AG doesn't know or return tier - it's an InferRouter concept.
pub fn check_account_limits(
    account_id: &str,
    model_type: ModelType,
    cache: &LimitsCache,
) -> Result<(), LimitError> {
    // Skip if enforcement disabled
    if !cache.is_enabled() {
        debug!("Limits enforcement disabled, skipping check");
        return Ok(());
    }

    debug!(account_id, ?model_type, "Checking account limits");

    // Get limit state from cache
    let state = match cache.get(account_id) {
        Some(s) => {
            debug!(
                account_id,
                blocked_prepaid = s.blocked_prepaid,
                blocked_byok = s.blocked_byok,
                blocked_credit = s.blocked_credit,
                "Found account in limits cache"
            );
            s
        }
        None => {
            // Account not in cache - new account or cache miss
            // Fail-open: allow request, backend will track usage
            if cache.config().fail_open {
                debug!(
                    account_id,
                    "Account not in limits cache, allowing (fail-open)"
                );
                return Ok(());
            } else {
                // Fail-closed mode: block unknown accounts
                warn!(
                    account_id,
                    "Account not in limits cache, blocking (fail-closed)"
                );
                return Err(LimitError::PrepaidCapExceeded {
                    reason: "account_not_found".to_string(),
                    daily_used: 0,
                    daily_limit: 0,
                    monthly_used: 0,
                    monthly_limit: 0,
                    reset_at: Utc::now(),
                });
            }
        }
    };

    // Check prepaid caps first (applies to all models)
    if state.blocked_prepaid {
        return Err(LimitError::PrepaidCapExceeded {
            reason: state
                .prepaid_reason
                .clone()
                .unwrap_or_else(|| "prepaid_cap".to_string()),
            daily_used: state.daily_used,
            daily_limit: state.daily_limit,
            monthly_used: state.monthly_used,
            monthly_limit: state.monthly_limit,
            reset_at: state.daily_reset_at,
        });
    }

    // Check model-specific limits
    match model_type {
        ModelType::Byok => {
            if state.blocked_byok {
                return Err(LimitError::ByokLimitExceeded {
                    byok_used: state.byok_used,
                    byok_limit: state.byok_limit,
                    reset_at: state.monthly_reset_at,
                });
            }
        }
        ModelType::LocalPaid => {
            if state.blocked_credit {
                return Err(LimitError::InsufficientCredits {
                    balance: state.credit_balance,
                });
            }
        }
        ModelType::Free => {
            // Prepaid caps already checked above
        }
    }

    Ok(())
}

/// Fetch full snapshot from backend
pub async fn fetch_full_snapshot(
    config: &LimitsConfig,
) -> Result<AccountLimitSnapshot, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .timeout(config.request_timeout)
        .build()?;

    let url = format!("{}/internal/limits/snapshot", config.backend_url);

    let mut request = client.get(&url);
    if let Some(token) = &config.service_token {
        request = request.header("X-Service-Token", token);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        return Err(format!("Snapshot API returned {}", response.status()).into());
    }

    let snapshot: AccountLimitSnapshot = response.json().await?;
    Ok(snapshot)
}

/// Background task that refreshes limits cache
pub async fn limits_refresh_task(cache: Arc<LimitsCache>) {
    if !cache.is_enabled() {
        info!("Limits refresh task: enforcement disabled, exiting");
        return;
    }

    let interval = cache.config().refresh_interval;
    info!(
        ?interval,
        "Starting limits refresh task"
    );

    let mut ticker = tokio::time::interval(interval);

    loop {
        ticker.tick().await;

        let config = cache.config().clone();
        match fetch_full_snapshot(&config).await {
            Ok(snapshot) => {
                let count = snapshot.count;
                cache.update_from_snapshot(snapshot);
                info!(count, "Limits cache refreshed");
            }
            Err(e) => {
                warn!(error = %e, "Limits refresh failed, using stale cache");
                // Continue with stale data, don't panic
            }
        }
    }
}

/// Extract account_id from JWT claims for limits enforcement.
///
/// JWT structure: { "project_id": "...", "metadata": { "account_id": "<uuid>" } }
///
/// IMPORTANT: Limits enforcement requires metadata.account_id (UUID).
/// No fallback to project_id - limits are per-account, not per-project.
pub fn extract_account_id_from_claims(claims: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    // Extract account_id from metadata.account_id ONLY
    if let Some(metadata) = claims.get("metadata").and_then(|v| v.as_object()) {
        if let Some(account_id) = metadata.get("account_id").and_then(|v| v.as_str()) {
            debug!(account_id, "Extracted account_id from metadata.account_id");
            return Some(account_id.to_string());
        }
        debug!("metadata exists but no account_id field");
    }

    // NO fallback to project_id - limits are per-account (UUID), not per-project
    debug!("No account_id in claims - limits enforcement skipped (fail-open)");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_type_from_provider() {
        assert_eq!(ModelType::from_provider(Some("openai_byok")), ModelType::Byok);
        assert_eq!(ModelType::from_provider(Some("anthropic_byok")), ModelType::Byok);
        assert_eq!(ModelType::from_provider(Some("local_mesh")), ModelType::Free);
        assert_eq!(ModelType::from_provider(Some("local_paid")), ModelType::LocalPaid);
        assert_eq!(ModelType::from_provider(None), ModelType::Free);
    }

    #[test]
    fn test_extract_account_id_from_claims() {
        use serde_json::json;

        // Test with metadata.account_id
        let claims: serde_json::Map<String, serde_json::Value> = serde_json::from_value(json!({
            "project_id": "proj_123",
            "metadata": {
                "account_id": "acc_456"
            }
        })).unwrap();
        assert_eq!(extract_account_id_from_claims(&claims), Some("acc_456".to_string()));

        // Test fallback to project_id
        let claims: serde_json::Map<String, serde_json::Value> = serde_json::from_value(json!({
            "project_id": "proj_789"
        })).unwrap();
        assert_eq!(extract_account_id_from_claims(&claims), Some("proj_789".to_string()));

        // Test no account_id
        let claims: serde_json::Map<String, serde_json::Value> = serde_json::from_value(json!({
            "jti": "tok_abc"
        })).unwrap();
        assert_eq!(extract_account_id_from_claims(&claims), None);
    }

    #[test]
    fn test_check_account_limits_disabled() {
        let config = LimitsConfig {
            enabled: false,
            ..Default::default()
        };
        let cache = LimitsCache::new(config);

        // Should pass when disabled
        assert!(check_account_limits("any_account", ModelType::Free, &cache).is_ok());
    }

    #[test]
    fn test_check_account_limits_blocked_prepaid() {
        let config = LimitsConfig {
            enabled: true,
            fail_open: false,
            ..Default::default()
        };
        let cache = LimitsCache::new(config);

        // Add blocked account to cache
        let state = AccountLimitState {
            account_id: "acc_123".to_string(),
            blocked_prepaid: true,
            blocked_byok: false,
            blocked_credit: false,
            prepaid_reason: Some("daily_cap".to_string()),
            daily_used: 10000,
            daily_limit: 10000,
            monthly_used: 0,
            monthly_limit: 0,
            byok_used: 0,
            byok_limit: -1,
            credit_balance: 100.0,
            daily_reset_at: Utc::now(),
            monthly_reset_at: Utc::now(),
        };
        cache.entries.write().insert("acc_123".to_string(), state);
        *cache.last_refresh.write() = Some(Utc::now());

        let result = check_account_limits("acc_123", ModelType::Free, &cache);
        assert!(matches!(result, Err(LimitError::PrepaidCapExceeded { .. })));
    }

    #[test]
    fn test_check_account_limits_blocked_byok() {
        let config = LimitsConfig {
            enabled: true,
            fail_open: false,
            ..Default::default()
        };
        let cache = LimitsCache::new(config);

        // Add account with blocked BYOK
        let state = AccountLimitState {
            account_id: "acc_456".to_string(),
            blocked_prepaid: false,
            blocked_byok: true,
            blocked_credit: false,
            prepaid_reason: None,
            daily_used: 5000,
            daily_limit: 10000,
            monthly_used: 0,
            monthly_limit: 0,
            byok_used: 100000,
            byok_limit: 100000,
            credit_balance: 100.0,
            daily_reset_at: Utc::now(),
            monthly_reset_at: Utc::now(),
        };
        cache.entries.write().insert("acc_456".to_string(), state);
        *cache.last_refresh.write() = Some(Utc::now());

        // Free model should pass
        assert!(check_account_limits("acc_456", ModelType::Free, &cache).is_ok());

        // BYOK model should fail
        let result = check_account_limits("acc_456", ModelType::Byok, &cache);
        assert!(matches!(result, Err(LimitError::ByokLimitExceeded { .. })));
    }
}
