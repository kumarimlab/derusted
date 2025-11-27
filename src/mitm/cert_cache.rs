//! Certificate Cache
//!
//! LRU cache for generated certificates to avoid regenerating certificates
//! for frequently accessed domains.

use lru::LruCache;
use rcgen::Certificate;
use std::num::NonZeroUsize;

/// Certificate cache with LRU eviction policy
pub struct CertCache {
    cache: LruCache<String, Certificate>,
    hits: u64,
    misses: u64,
}

impl CertCache {
    /// Create a new certificate cache with the specified capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(capacity).unwrap()),
            hits: 0,
            misses: 0,
        }
    }

    /// Get a certificate from the cache
    pub fn get(&mut self, domain: &str) -> Option<&Certificate> {
        match self.cache.get(domain) {
            Some(cert) => {
                self.hits += 1;
                Some(cert)
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    /// Insert a certificate into the cache
    pub fn insert(&mut self, domain: String, cert: Certificate) {
        self.cache.put(domain, cert);
    }

    /// Get the number of certificates in the cache
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Get the cache capacity
    pub fn capacity(&self) -> usize {
        self.cache.cap().get()
    }

    /// Get the cache hit rate (hits / total requests)
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    /// Get the number of cache hits
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Get the number of cache misses
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Clear the cache
    pub fn clear(&mut self) {
        self.cache.clear();
        self.hits = 0;
        self.misses = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::CertificateParams;

    fn generate_test_cert() -> Certificate {
        let params = CertificateParams::default();
        params.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap()
    }

    #[test]
    fn test_cache_insert_and_get() {
        let mut cache = CertCache::new(10);

        let cert = generate_test_cert();
        cache.insert("example.com".to_string(), cert);

        assert_eq!(cache.len(), 1);
        assert!(cache.get("example.com").is_some());
        assert!(cache.get("nonexistent.com").is_none());
    }

    #[test]
    fn test_cache_hit_rate() {
        let mut cache = CertCache::new(10);

        let cert = generate_test_cert();
        cache.insert("example.com".to_string(), cert);

        // 1 hit
        cache.get("example.com");
        // 2 misses
        cache.get("nonexistent1.com");
        cache.get("nonexistent2.com");

        // Hit rate should be 1/3 = 0.333...
        assert!((cache.hit_rate() - 0.333).abs() < 0.01);
        assert_eq!(cache.hits(), 1);
        assert_eq!(cache.misses(), 2);
    }

    #[test]
    fn test_cache_lru_eviction() {
        let mut cache = CertCache::new(2); // Small cache

        let cert1 = generate_test_cert();
        let cert2 = generate_test_cert();
        let cert3 = generate_test_cert();

        cache.insert("domain1.com".to_string(), cert1);
        cache.insert("domain2.com".to_string(), cert2);
        cache.insert("domain3.com".to_string(), cert3);

        // Cache size should be 2 (domain1 evicted)
        assert_eq!(cache.len(), 2);
        assert!(cache.get("domain1.com").is_none());
        assert!(cache.get("domain2.com").is_some());
        assert!(cache.get("domain3.com").is_some());
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = CertCache::new(10);

        let cert = generate_test_cert();
        cache.insert("example.com".to_string(), cert);
        cache.get("example.com");

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.hits(), 1);

        cache.clear();

        assert_eq!(cache.len(), 0);
        assert_eq!(cache.hits(), 0);
        assert_eq!(cache.misses(), 0);
    }
}
