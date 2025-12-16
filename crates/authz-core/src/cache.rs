//! L1 in-memory cache for API key validation results
//!
//! Provides a simple TTL-based cache to reduce backhaul calls.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Cached authorization result
#[derive(Clone, Debug)]
pub struct CacheEntry {
    /// Whether the API key is allowed
    pub allow: bool,
    /// Optional metadata from validation (e.g., account_id)
    pub metadata: HashMap<String, String>,
    /// When this entry expires
    pub expires_at: Instant,
}

/// Thread-safe L1 in-memory cache with TTL
#[derive(Clone, Default)]
pub struct L1Cache {
    inner: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

impl L1Cache {
    /// Create a new empty cache
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a cached entry if it exists and hasn't expired
    pub fn get(&self, key: &str) -> Option<CacheEntry> {
        let now = Instant::now();
        if let Some(entry) = self.inner.lock().unwrap().get(key) {
            if entry.expires_at > now {
                return Some(entry.clone());
            }
        }
        None
    }

    /// Store a result in the cache with the given TTL
    pub fn put(&self, key: String, allow: bool, metadata: HashMap<String, String>, ttl: Duration) {
        let entry = CacheEntry {
            allow,
            metadata,
            expires_at: Instant::now() + ttl,
        };
        self.inner.lock().unwrap().insert(key, entry);
    }

    /// Remove an entry from the cache (e.g., on invalidation)
    pub fn del(&self, key: &str) {
        self.inner.lock().unwrap().remove(key);
    }

    /// Get the number of entries in the cache (for metrics)
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    /// Remove all expired entries (call periodically for cleanup)
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.inner
            .lock()
            .unwrap()
            .retain(|_, entry| entry.expires_at > now);
    }
}

/// Compute SHA-256 hash of input string, returned as lowercase hex
///
/// Used to hash API keys for cache keys (avoid storing raw keys)
pub fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let out = hasher.finalize();
    base16ct::lower::encode_string(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_put_get() {
        let cache = L1Cache::new();

        cache.put(
            "key1".to_string(),
            true,
            HashMap::new(),
            Duration::from_secs(60),
        );

        let entry = cache.get("key1").expect("should exist");
        assert!(entry.allow);
    }

    #[test]
    fn test_cache_expiry() {
        let cache = L1Cache::new();

        // Put with very short TTL
        cache.put(
            "key1".to_string(),
            true,
            HashMap::new(),
            Duration::from_millis(1),
        );

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(5));

        // Should be expired
        assert!(cache.get("key1").is_none());
    }

    #[test]
    fn test_cache_delete() {
        let cache = L1Cache::new();

        cache.put(
            "key1".to_string(),
            true,
            HashMap::new(),
            Duration::from_secs(60),
        );
        assert!(cache.get("key1").is_some());

        cache.del("key1");
        assert!(cache.get("key1").is_none());
    }

    #[test]
    fn test_sha256_hex() {
        // Known test vector
        let hash = sha256_hex("hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_cache_metadata() {
        let cache = L1Cache::new();

        let mut metadata = HashMap::new();
        metadata.insert("account_id".to_string(), "acc-123".to_string());

        cache.put("key1".to_string(), true, metadata, Duration::from_secs(60));

        let entry = cache.get("key1").expect("should exist");
        assert_eq!(entry.metadata.get("account_id"), Some(&"acc-123".to_string()));
    }

    #[test]
    fn test_evict_expired() {
        let cache = L1Cache::new();

        // Add entries with different TTLs
        cache.put(
            "short".to_string(),
            true,
            HashMap::new(),
            Duration::from_millis(1),
        );
        cache.put(
            "long".to_string(),
            true,
            HashMap::new(),
            Duration::from_secs(60),
        );

        assert_eq!(cache.len(), 2);

        // Wait and evict
        std::thread::sleep(Duration::from_millis(5));
        cache.evict_expired();

        // Only long TTL entry should remain
        assert_eq!(cache.len(), 1);
        assert!(cache.get("long").is_some());
    }
}
