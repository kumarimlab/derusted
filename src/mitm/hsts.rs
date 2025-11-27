//! HSTS (HTTP Strict Transport Security) Handler
//!
//! This module handles HSTS headers for MITM interception:
//! - Honor HSTS by default (proxy won't intercept HSTS sites)
//! - Optional HSTS stripping (for testing/inspection needs)
//! - Configurable via policy

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// HSTS policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HstsPolicy {
    /// Honor HSTS headers (default: true)
    /// When true, proxy won't intercept connections to HSTS domains
    pub honor_hsts: bool,

    /// Strip HSTS headers from responses (default: false)
    /// When true, removes Strict-Transport-Security header
    /// DANGEROUS: Only use for testing/debugging
    pub strip_hsts_headers: bool,

    /// Max age for HSTS cache (seconds, default: 31536000 = 1 year)
    pub max_cache_age: u64,

    /// Preload HSTS list (default: true)
    /// Use Chromium's preload list for known HSTS domains
    pub use_preload_list: bool,
}

impl Default for HstsPolicy {
    fn default() -> Self {
        Self {
            honor_hsts: true,          // Honor HSTS by default (secure)
            strip_hsts_headers: false, // Don't strip by default (secure)
            max_cache_age: 31536000,   // 1 year
            use_preload_list: true,    // Use preload list
        }
    }
}

impl HstsPolicy {
    /// Create policy that honors HSTS (secure default)
    pub fn honor() -> Self {
        Self::default()
    }

    /// Create policy that strips HSTS (for testing only)
    pub fn strip_for_testing() -> Self {
        Self {
            honor_hsts: false,
            strip_hsts_headers: true,
            ..Default::default()
        }
    }

    /// Create policy from environment variables
    pub fn from_env() -> Self {
        let mut policy = Self::default();

        if let Ok(val) = std::env::var("DERUSTED_HSTS_HONOR") {
            policy.honor_hsts = val.parse().unwrap_or(true);
        }

        if let Ok(val) = std::env::var("DERUSTED_HSTS_STRIP") {
            policy.strip_hsts_headers = val.parse().unwrap_or(false);
        }

        if let Ok(val) = std::env::var("DERUSTED_HSTS_MAX_AGE") {
            policy.max_cache_age = val.parse().unwrap_or(31536000);
        }

        if let Ok(val) = std::env::var("DERUSTED_HSTS_PRELOAD") {
            policy.use_preload_list = val.parse().unwrap_or(true);
        }

        policy
    }
}

/// HSTS entry in cache
#[derive(Debug, Clone)]
struct HstsEntry {
    /// When this entry expires (Unix timestamp)
    expires_at: i64,

    /// Include subdomains
    include_subdomains: bool,

    /// From preload list (never expires)
    preloaded: bool,
}

/// HSTS Manager
pub struct HstsManager {
    /// Policy configuration
    policy: HstsPolicy,

    /// HSTS cache (domain -> entry)
    cache: Arc<RwLock<HashMap<String, HstsEntry>>>,
}

impl HstsManager {
    /// Create new HSTS manager with default policy
    pub fn new() -> Self {
        Self::with_policy(HstsPolicy::default())
    }

    /// Create HSTS manager with custom policy
    pub fn with_policy(policy: HstsPolicy) -> Self {
        let mut cache = HashMap::new();

        // Load preload list if enabled
        if policy.use_preload_list {
            Self::load_preload_list(&mut cache);
        }

        Self {
            policy,
            cache: Arc::new(RwLock::new(cache)),
        }
    }

    /// Create from environment variables
    pub fn from_env() -> Self {
        Self::with_policy(HstsPolicy::from_env())
    }

    /// Check if domain is HSTS-protected
    pub async fn is_hsts_domain(&self, domain: &str) -> bool {
        if !self.policy.honor_hsts {
            return false; // HSTS disabled
        }

        let cache = self.cache.read().await;

        // Check exact match
        if let Some(entry) = cache.get(domain) {
            if entry.preloaded || entry.expires_at > chrono::Utc::now().timestamp() {
                debug!(domain = %domain, "Domain is HSTS-protected");
                return true;
            }
        }

        // Check all parent domains with includeSubDomains (recurse to apex)
        let mut current_domain = domain;
        while let Some(parent) = Self::parent_domain(current_domain) {
            if let Some(entry) = cache.get(parent) {
                if entry.include_subdomains {
                    if entry.preloaded || entry.expires_at > chrono::Utc::now().timestamp() {
                        debug!(
                            domain = %domain,
                            parent = %parent,
                            "Domain is HSTS-protected via parent"
                        );
                        return true;
                    }
                }
            }
            current_domain = parent;
        }

        false
    }

    /// Add HSTS entry from Strict-Transport-Security header
    pub async fn add_from_header(&self, domain: &str, header_value: &str) {
        if !self.policy.honor_hsts {
            return; // HSTS disabled
        }

        // Parse max-age
        let max_age = Self::parse_max_age(header_value);
        if max_age == 0 {
            warn!(
                domain = %domain,
                header = %header_value,
                "HSTS header with max-age=0, removing from cache"
            );
            self.cache.write().await.remove(domain);
            return;
        }

        // Parse includeSubDomains
        let include_subdomains = header_value.contains("includeSubDomains");

        let expires_at = chrono::Utc::now().timestamp() + max_age as i64;

        let entry = HstsEntry {
            expires_at,
            include_subdomains,
            preloaded: false,
        };

        info!(
            domain = %domain,
            max_age = max_age,
            include_subdomains = include_subdomains,
            "Added HSTS entry"
        );

        self.cache.write().await.insert(domain.to_string(), entry);
    }

    /// Process response headers (strip HSTS if configured)
    pub fn process_response_headers(&self, headers: &mut HashMap<String, String>) {
        if self.policy.strip_hsts_headers {
            if headers.remove("strict-transport-security").is_some() {
                warn!("HSTS header stripped (testing mode)");
            }
        }
    }

    /// Get parent domain
    fn parent_domain(domain: &str) -> Option<&str> {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            // subdomain.example.com -> example.com
            Some(&domain[domain.find('.').unwrap() + 1..])
        } else {
            None
        }
    }

    /// Parse max-age from header value
    fn parse_max_age(header_value: &str) -> u64 {
        for directive in header_value.split(';') {
            let directive = directive.trim();
            if let Some(value) = directive.strip_prefix("max-age=") {
                if let Ok(age) = value.trim().parse::<u64>() {
                    return age;
                }
            }
        }
        0
    }

    /// Load HSTS preload list
    fn load_preload_list(cache: &mut HashMap<String, HstsEntry>) {
        // Chromium's HSTS preload list (subset of most common domains)
        // Full list: https://hstspreload.org/
        let preload_domains = vec![
            "google.com",
            "gmail.com",
            "youtube.com",
            "facebook.com",
            "twitter.com",
            "github.com",
            "wikipedia.org",
            "cloudflare.com",
            "amazon.com",
            "apple.com",
            "microsoft.com",
            "netflix.com",
            "linkedin.com",
            "reddit.com",
            "instagram.com",
            "paypal.com",
            "dropbox.com",
            "stackoverflow.com",
            "zoom.us",
            "slack.com",
        ];

        let count = preload_domains.len();

        for domain in &preload_domains {
            cache.insert(
                domain.to_string(),
                HstsEntry {
                    expires_at: i64::MAX, // Never expires
                    include_subdomains: true,
                    preloaded: true,
                },
            );
        }

        info!(count = count, "Loaded HSTS preload list");
    }

    /// Get policy
    pub fn policy(&self) -> &HstsPolicy {
        &self.policy
    }

    /// Get cache size (for monitoring)
    pub async fn cache_size(&self) -> usize {
        self.cache.read().await.len()
    }

    /// Clear expired entries
    pub async fn cleanup_expired(&self) {
        let mut cache = self.cache.write().await;
        let now = chrono::Utc::now().timestamp();

        cache.retain(|domain, entry| {
            if entry.preloaded {
                true // Keep preloaded entries
            } else if entry.expires_at > now {
                true // Keep valid entries
            } else {
                debug!(domain = %domain, "HSTS entry expired");
                false
            }
        });
    }
}

impl Default for HstsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hsts_policy_defaults() {
        let policy = HstsPolicy::default();
        assert!(policy.honor_hsts);
        assert!(!policy.strip_hsts_headers);
        assert_eq!(policy.max_cache_age, 31536000);
        assert!(policy.use_preload_list);
    }

    #[tokio::test]
    async fn test_hsts_policy_strip_for_testing() {
        let policy = HstsPolicy::strip_for_testing();
        assert!(!policy.honor_hsts);
        assert!(policy.strip_hsts_headers);
    }

    #[tokio::test]
    async fn test_hsts_manager_preload_list() {
        let manager = HstsManager::new();

        // Check preloaded domains
        assert!(manager.is_hsts_domain("google.com").await);
        assert!(manager.is_hsts_domain("github.com").await);
        assert!(manager.is_hsts_domain("facebook.com").await);

        // Non-preloaded domain
        assert!(!manager.is_hsts_domain("example.com").await);
    }

    #[tokio::test]
    async fn test_hsts_manager_add_from_header() {
        let manager = HstsManager::new();

        // Add HSTS entry
        manager
            .add_from_header("example.com", "max-age=31536000; includeSubDomains")
            .await;

        // Check if domain is now HSTS-protected
        assert!(manager.is_hsts_domain("example.com").await);
        assert!(manager.is_hsts_domain("sub.example.com").await);
    }

    #[tokio::test]
    async fn test_hsts_manager_max_age_zero() {
        let manager = HstsManager::new();

        // Add entry first
        manager
            .add_from_header("example.com", "max-age=31536000")
            .await;
        assert!(manager.is_hsts_domain("example.com").await);

        // Remove with max-age=0
        manager.add_from_header("example.com", "max-age=0").await;
        assert!(!manager.is_hsts_domain("example.com").await);
    }

    #[tokio::test]
    async fn test_hsts_manager_disabled() {
        let policy = HstsPolicy {
            honor_hsts: false,
            ..Default::default()
        };
        let manager = HstsManager::with_policy(policy);

        // Even preloaded domains should not be protected when disabled
        assert!(!manager.is_hsts_domain("google.com").await);
    }

    #[tokio::test]
    async fn test_hsts_strip_headers() {
        let policy = HstsPolicy::strip_for_testing();
        let manager = HstsManager::with_policy(policy);

        let mut headers = HashMap::new();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );
        headers.insert("content-type".to_string(), "text/html".to_string());

        manager.process_response_headers(&mut headers);

        // HSTS header should be removed
        assert!(!headers.contains_key("strict-transport-security"));
        // Other headers should remain
        assert!(headers.contains_key("content-type"));
    }

    #[test]
    fn test_parse_max_age() {
        assert_eq!(HstsManager::parse_max_age("max-age=31536000"), 31536000);
        assert_eq!(HstsManager::parse_max_age("max-age=0"), 0);
        assert_eq!(
            HstsManager::parse_max_age("max-age=31536000; includeSubDomains"),
            31536000
        );
        assert_eq!(HstsManager::parse_max_age("invalid"), 0);
    }

    #[test]
    fn test_parent_domain() {
        assert_eq!(
            HstsManager::parent_domain("sub.example.com"),
            Some("example.com")
        );
        assert_eq!(
            HstsManager::parent_domain("deep.sub.example.com"),
            Some("sub.example.com")
        );
        assert_eq!(HstsManager::parent_domain("example.com"), None);
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let manager = HstsManager::new();

        // Add entry that expires immediately
        manager.cache.write().await.insert(
            "expired.com".to_string(),
            HstsEntry {
                expires_at: 0,
                include_subdomains: false,
                preloaded: false,
            },
        );

        // Add valid entry
        manager.cache.write().await.insert(
            "valid.com".to_string(),
            HstsEntry {
                expires_at: chrono::Utc::now().timestamp() + 3600,
                include_subdomains: false,
                preloaded: false,
            },
        );

        manager.cleanup_expired().await;

        // Expired entry should be removed
        assert!(!manager.cache.read().await.contains_key("expired.com"));
        // Valid entry should remain
        assert!(manager.cache.read().await.contains_key("valid.com"));
    }

    #[tokio::test]
    async fn test_hsts_includesubdomains_multi_level() {
        let manager = HstsManager::new();

        // Add HSTS entry for apex domain with includeSubDomains
        manager
            .add_from_header("example.com", "max-age=31536000; includeSubDomains")
            .await;

        // Test multi-level subdomain chain: foo.bar.example.com should be protected
        // because example.com has includeSubDomains, even though bar.example.com
        // is not explicitly in the cache
        assert!(
            manager.is_hsts_domain("foo.bar.example.com").await,
            "foo.bar.example.com should be protected via example.com includeSubDomains"
        );

        // Verify all levels are protected
        assert!(manager.is_hsts_domain("example.com").await);
        assert!(manager.is_hsts_domain("bar.example.com").await);
        assert!(manager.is_hsts_domain("foo.bar.example.com").await);
        assert!(manager.is_hsts_domain("baz.foo.bar.example.com").await);
    }
}
