//! Rate limit configuration parsing and matching
//!
//! Supports YAML configuration with wildcard matching for descriptors.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Rate limiter configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// gRPC server bind address (e.g., "127.0.0.1:18081")
    /// Only used when running as sidecar, ignored for in-process use.
    #[serde(default = "default_grpc_bind")]
    pub grpc_bind: String,

    /// Metrics HTTP server bind address (e.g., "127.0.0.1:19102")
    /// Only used when running as sidecar, ignored for in-process use.
    #[serde(default = "default_metrics_bind")]
    pub metrics_bind: String,

    /// Domain to enforce (e.g., "inferrouter-mcp", "inferrouter-llm")
    pub domain: String,

    /// Rate limit rules (first match wins)
    pub limits: Vec<LimitRule>,

    /// Max number of tracked keys (prevents memory leak)
    #[serde(default = "default_max_keys")]
    pub max_keys: usize,

    /// Default action on internal errors (true = allow, false = deny)
    #[serde(default)]
    pub fail_open: bool,
}

/// A single rate limit rule
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LimitRule {
    /// Descriptor pattern to match
    /// Example: {"tool": "read_file", "account": "*"}
    /// "*" matches any value
    pub descriptors: HashMap<String, String>,

    /// Maximum requests per window
    pub requests: u32,

    /// Window duration in seconds
    pub window_seconds: u64,

    /// Human-readable description (optional)
    #[serde(default)]
    pub description: String,
}

fn default_grpc_bind() -> String {
    "127.0.0.1:18081".to_string()
}

fn default_metrics_bind() -> String {
    "127.0.0.1:19102".to_string()
}

fn default_max_keys() -> usize {
    10_000
}

impl Config {
    /// Load configuration from a YAML file
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config from {}", path.display()))?;

        Self::from_yaml(&contents)
    }

    /// Parse configuration from YAML string
    ///
    /// This is the primary entry point for in-process use where config
    /// comes from AG's config.yaml rather than a separate file.
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let config: Config = serde_yaml::from_str(yaml)
            .with_context(|| "Failed to parse rate limit config YAML")?;

        // Validate
        if config.limits.is_empty() {
            anyhow::bail!("Config must have at least one limit rule");
        }

        Ok(config)
    }

    /// Find matching rule for given descriptors
    ///
    /// Returns (requests, window_seconds) for the first matching rule,
    /// or None if no rule matches.
    ///
    /// Rules are matched in order - first match wins.
    pub fn find_limit(&self, descriptors: &HashMap<String, String>) -> Option<(u32, u64)> {
        for rule in &self.limits {
            if self.matches(&rule.descriptors, descriptors) {
                return Some((rule.requests, rule.window_seconds));
            }
        }
        None
    }

    /// Check if a pattern matches the given descriptors
    fn matches(
        &self,
        pattern: &HashMap<String, String>,
        descriptors: &HashMap<String, String>,
    ) -> bool {
        // All pattern keys must be present and match
        for (key, pattern_value) in pattern {
            match descriptors.get(key) {
                Some(actual_value) => {
                    // "*" is wildcard - matches any value
                    if pattern_value != "*" && pattern_value != actual_value {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_wildcard() {
        let pattern: HashMap<String, String> = [
            ("tool".to_string(), "read_file".to_string()),
            ("account".to_string(), "*".to_string()),
        ]
        .into_iter()
        .collect();

        let descriptors: HashMap<String, String> = [
            ("tool".to_string(), "read_file".to_string()),
            ("account".to_string(), "uuid-123".to_string()),
        ]
        .into_iter()
        .collect();

        let config = Config {
            grpc_bind: String::new(),
            metrics_bind: String::new(),
            domain: "test".to_string(),
            limits: vec![],
            max_keys: 1000,
            fail_open: false,
        };

        assert!(config.matches(&pattern, &descriptors));
    }

    #[test]
    fn test_match_exact() {
        let pattern: HashMap<String, String> = [
            ("tool".to_string(), "read_file".to_string()),
            ("account".to_string(), "uuid-123".to_string()),
        ]
        .into_iter()
        .collect();

        let descriptors = pattern.clone();

        let config = Config {
            grpc_bind: String::new(),
            metrics_bind: String::new(),
            domain: "test".to_string(),
            limits: vec![],
            max_keys: 1000,
            fail_open: false,
        };

        assert!(config.matches(&pattern, &descriptors));
    }

    #[test]
    fn test_match_no_match() {
        let pattern: HashMap<String, String> =
            [("tool".to_string(), "write_file".to_string())]
                .into_iter()
                .collect();

        let descriptors: HashMap<String, String> =
            [("tool".to_string(), "read_file".to_string())]
                .into_iter()
                .collect();

        let config = Config {
            grpc_bind: String::new(),
            metrics_bind: String::new(),
            domain: "test".to_string(),
            limits: vec![],
            max_keys: 1000,
            fail_open: false,
        };

        assert!(!config.matches(&pattern, &descriptors));
    }

    #[test]
    fn test_match_missing_key() {
        let pattern: HashMap<String, String> = [
            ("tool".to_string(), "read_file".to_string()),
            ("account".to_string(), "*".to_string()),
        ]
        .into_iter()
        .collect();

        // Missing "account" key
        let descriptors: HashMap<String, String> =
            [("tool".to_string(), "read_file".to_string())]
                .into_iter()
                .collect();

        let config = Config {
            grpc_bind: String::new(),
            metrics_bind: String::new(),
            domain: "test".to_string(),
            limits: vec![],
            max_keys: 1000,
            fail_open: false,
        };

        assert!(!config.matches(&pattern, &descriptors));
    }

    #[test]
    fn test_from_yaml() {
        let yaml = r#"
domain: "inferrouter-llm"
limits:
  - descriptors:
      model: "*"
      account: "*"
    requests: 100
    window_seconds: 60
    description: "Default LLM limit"
  - descriptors:
      model: "gpt-4"
      account: "*"
    requests: 10
    window_seconds: 60
    description: "Strict limit for GPT-4"
"#;

        let config = Config::from_yaml(yaml).unwrap();

        assert_eq!(config.domain, "inferrouter-llm");
        assert_eq!(config.limits.len(), 2);
        assert_eq!(config.limits[0].requests, 100);
        assert_eq!(config.limits[1].requests, 10);
    }

    #[test]
    fn test_find_limit_first_match_wins() {
        let yaml = r#"
domain: "test"
limits:
  - descriptors:
      model: "gpt-4"
    requests: 10
    window_seconds: 60
  - descriptors:
      model: "*"
    requests: 100
    window_seconds: 60
"#;

        let config = Config::from_yaml(yaml).unwrap();

        let mut descriptors = HashMap::new();
        descriptors.insert("model".to_string(), "gpt-4".to_string());

        // Should match first rule (10 req/min) not second (100 req/min)
        let (requests, window) = config.find_limit(&descriptors).unwrap();
        assert_eq!(requests, 10);
        assert_eq!(window, 60);
    }

    #[test]
    fn test_find_limit_fallback_to_wildcard() {
        let yaml = r#"
domain: "test"
limits:
  - descriptors:
      model: "gpt-4"
    requests: 10
    window_seconds: 60
  - descriptors:
      model: "*"
    requests: 100
    window_seconds: 60
"#;

        let config = Config::from_yaml(yaml).unwrap();

        let mut descriptors = HashMap::new();
        descriptors.insert("model".to_string(), "claude-3".to_string());

        // Should match second rule (wildcard)
        let (requests, window) = config.find_limit(&descriptors).unwrap();
        assert_eq!(requests, 100);
        assert_eq!(window, 60);
    }
}
