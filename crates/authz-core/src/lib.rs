//! authz-core: Core authorization library for InferRouter
//!
//! This crate provides the core authorization logic extracted from sidecar-authz-rs.
//! It can be used either as a standalone sidecar (via gRPC) or embedded in-process.
//!
//! # Features
//!
//! - **L1 Cache**: In-memory TTL-based cache for fast lookups
//! - **L2 Cache**: Optional Redis cache for distributed deployments
//! - **Backhaul**: HTTP validation via main API for cache misses
//! - **Fail-Closed**: Denies requests when all validation sources fail
//!
//! # Example
//!
//! ```rust,ignore
//! use authz_core::{check_authz, AuthzConfig, AuthzDecision, L1Cache, NoopMetrics};
//! use reqwest::Client;
//!
//! // Create cache and config
//! let cache = L1Cache::new();
//! let config = AuthzConfig {
//!     backhaul_url: Some("https://api.inferrouter.com".to_string()),
//!     service_token: Some("secret".to_string()),
//!     ..Default::default()
//! };
//!
//! // Create HTTP client
//! let http = Client::new();
//! let metrics = NoopMetrics;
//!
//! // Check authorization
//! let decision = check_authz(
//!     "ir_test_xxx",
//!     &config,
//!     &cache,
//!     None, // No Redis
//!     &http,
//!     &metrics,
//! ).await;
//!
//! match decision {
//!     AuthzDecision::Allow { source, .. } => {
//!         println!("Allowed from {:?}", source);
//!     }
//!     AuthzDecision::Deny { reason, status, .. } => {
//!         println!("Denied: {} (HTTP {})", reason, status);
//!     }
//! }
//! ```

pub mod cache;
pub mod decision;

// Re-export public types
pub use cache::{sha256_hex, CacheEntry, L1Cache};
pub use decision::{check_authz, AuthzConfig, AuthzDecision, AuthzMetrics, AuthzSource, NoopMetrics};

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::cache::{sha256_hex, L1Cache};
    pub use crate::decision::{
        check_authz, AuthzConfig, AuthzDecision, AuthzMetrics, AuthzSource, NoopMetrics,
    };
}
