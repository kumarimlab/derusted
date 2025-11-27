//! Smart Bypass System - Configurable bypass for pinned/sensitive domains
//!
//! This module provides:
//! - Configurable static bypass rules (user-provided)
//! - Optional dynamic bypass on certificate pinning detection
//! - Alerts and metrics for bypass events
//! - TTL-based persistence for dynamic rules
//!
//! ## Design Philosophy
//!
//! This is a **framework**, not a policy. Users decide what to bypass.
//! No opinionated defaults are included - configuration is required.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// Import bypass_config types (they're defined in a separate file in same directory)
pub use crate::mitm::bypass_config::{
    AlertConfig, BypassConfig, ConfigError, DynamicBypassConfig, ExampleBypassRules,
    StaticBypassRule,
};

/// Reason for bypassing MITM
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BypassReason {
    /// Static rule (pre-configured)
    StaticRule,

    /// Certificate pinning detected
    CertificatePinning,

    /// Localhost (127.0.0.1, ::1)
    Localhost,

    /// HSTS with includeSubDomains
    HstsPolicy,

    /// User-configured bypass
    UserConfigured,

    /// Emergency bypass (manual)
    Emergency,
}

impl std::fmt::Display for BypassReason {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::StaticRule => write!(f, "Static Rule"),
            Self::CertificatePinning => write!(f, "Certificate Pinning"),
            Self::Localhost => write!(f, "Localhost"),
            Self::HstsPolicy => write!(f, "HSTS Policy"),
            Self::UserConfigured => write!(f, "User Configured"),
            Self::Emergency => write!(f, "Emergency"),
        }
    }
}

/// Bypass rule (internal representation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassRule {
    /// Domain pattern (exact or wildcard)
    pub pattern: String,

    /// Reason for bypass
    pub reason: BypassReason,

    /// Is this a static (permanent) rule?
    pub is_static: bool,

    /// TTL for dynamic rules (seconds)
    pub ttl: Option<u64>,

    /// When was this rule added (Unix timestamp)
    pub added_at: i64,

    /// Optional description
    pub description: Option<String>,
}

impl BypassRule {
    /// Check if rule has expired
    pub fn is_expired(&self) -> bool {
        if self.is_static {
            return false;
        }

        if let Some(ttl) = self.ttl {
            let now = chrono::Utc::now().timestamp();
            let age = now - self.added_at;
            age > ttl as i64
        } else {
            false
        }
    }
}

/// Bypass manager - Configurable bypass system
pub struct BypassManager {
    /// Configuration
    config: BypassConfig,

    /// Static rules (never expire)
    static_rules: Arc<HashSet<String>>,

    /// Dynamic rules (with TTL)
    dynamic_rules: Arc<RwLock<HashMap<String, BypassRule>>>,

    /// Alert callback (for monitoring/alerting)
    alert_fn: Option<Arc<dyn Fn(BypassReason, String) + Send + Sync>>,

    /// Last cleanup timestamp
    last_cleanup: Arc<RwLock<i64>>,
}

impl BypassManager {
    /// Create new bypass manager with configuration
    pub fn new(config: BypassConfig) -> Self {
        let static_rules = Self::load_static_rules_from_config(&config);

        Self {
            config,
            static_rules: Arc::new(static_rules),
            dynamic_rules: Arc::new(RwLock::new(HashMap::new())),
            alert_fn: None,
            last_cleanup: Arc::new(RwLock::new(chrono::Utc::now().timestamp())),
        }
    }

    /// Create bypass manager from environment variables
    pub fn from_env() -> Self {
        let config = BypassConfig::from_env();
        Self::new(config)
    }

    /// Create bypass manager from config file
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, ConfigError> {
        let config = BypassConfig::from_file(path)?;
        Ok(Self::new(config))
    }

    /// Create empty bypass manager (disabled)
    pub fn disabled() -> Self {
        let mut config = BypassConfig::default();
        config.enabled = false;
        Self::new(config)
    }

    /// Set alert callback
    pub fn set_alert_fn<F>(&mut self, f: F)
    where
        F: Fn(BypassReason, String) + Send + Sync + 'static,
    {
        self.alert_fn = Some(Arc::new(f));
    }

    /// Check if bypass system is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if host should be bypassed
    pub async fn should_bypass(&self, host: &str) -> Option<BypassReason> {
        // If bypass system is disabled, never bypass
        if !self.config.enabled {
            return None;
        }

        // Check static rules first
        if self.static_rules.contains(host) {
            debug!(host = %host, "Static bypass rule matched (exact)");
            self.send_alert_if_enabled(BypassReason::StaticRule, host.to_string());
            return Some(BypassReason::StaticRule);
        }

        // Check wildcard static rules
        for rule in self.static_rules.iter() {
            if Self::matches_wildcard(rule, host) {
                debug!(host = %host, rule = %rule, "Static bypass rule matched (wildcard)");
                self.send_alert_if_enabled(BypassReason::StaticRule, host.to_string());
                return Some(BypassReason::StaticRule);
            }
        }

        // Check dynamic rules (if enabled)
        if self.config.allow_dynamic {
            let dynamic = self.dynamic_rules.read().await;
            if let Some(rule) = dynamic.get(host) {
                if !rule.is_expired() {
                    debug!(
                        host = %host,
                        reason = ?rule.reason,
                        "Dynamic bypass rule matched"
                    );
                    self.send_alert_if_enabled(rule.reason.clone(), host.to_string());
                    return Some(rule.reason.clone());
                }
            }
        }

        // Periodic cleanup of expired rules
        self.cleanup_if_needed().await;

        None
    }

    /// Add dynamic bypass rule
    pub async fn add_dynamic_rule(&self, host: String, reason: BypassReason, ttl: u64) {
        if !self.config.enabled {
            debug!("Bypass system disabled, ignoring dynamic rule addition");
            return;
        }

        if !self.config.allow_dynamic {
            warn!(
                host = %host,
                "Dynamic bypass attempted but not allowed by policy"
            );
            return;
        }

        let rule = BypassRule {
            pattern: host.clone(),
            reason: reason.clone(),
            is_static: false,
            ttl: Some(ttl),
            added_at: chrono::Utc::now().timestamp(),
            description: None,
        };

        let mut dynamic = self.dynamic_rules.write().await;

        // Check max rules limit
        if dynamic.len() >= self.config.dynamic.max_rules {
            warn!(
                host = %host,
                max_rules = self.config.dynamic.max_rules,
                "Maximum dynamic rules reached, not adding new rule"
            );
            return;
        }

        dynamic.insert(host.clone(), rule);

        info!(
            host = %host,
            reason = ?reason,
            ttl = ttl,
            "Dynamic bypass rule added"
        );

        if self.config.alerts.alert_on_dynamic {
            self.send_alert(reason, host);
        }
    }

    /// Add static bypass rule programmatically
    pub fn add_static_rule(&mut self, pattern: String, reason: BypassReason) {
        if !self.config.enabled {
            debug!("Bypass system disabled, ignoring static rule addition");
            return;
        }

        Arc::get_mut(&mut self.static_rules)
            .expect("Cannot modify static rules after Arc is shared")
            .insert(pattern.clone());

        info!(
            pattern = %pattern,
            reason = ?reason,
            "Static bypass rule added programmatically"
        );
    }

    /// Load example rules (opt-in)
    pub fn load_example_rules(&mut self) {
        if !self.config.enabled {
            debug!("Bypass system disabled, not loading example rules");
            return;
        }

        let example_rules = ExampleBypassRules::all();
        let rules_set = Arc::get_mut(&mut self.static_rules)
            .expect("Cannot modify static rules after Arc is shared");

        for rule in example_rules {
            rules_set.insert(rule.pattern.clone());
        }

        info!(count = rules_set.len(), "Loaded example bypass rules");
    }

    /// Remove expired dynamic rules
    pub async fn cleanup_expired(&self) {
        if !self.config.allow_dynamic {
            return;
        }

        let mut dynamic = self.dynamic_rules.write().await;
        let before_count = dynamic.len();

        dynamic.retain(|_, rule| !rule.is_expired());

        let after_count = dynamic.len();
        let removed = before_count - after_count;

        if removed > 0 {
            debug!(removed = removed, "Cleaned up expired dynamic bypass rules");
        }

        // Update last cleanup time
        let mut last_cleanup = self.last_cleanup.write().await;
        *last_cleanup = chrono::Utc::now().timestamp();
    }

    /// Cleanup if interval has passed
    async fn cleanup_if_needed(&self) {
        let last_cleanup = *self.last_cleanup.read().await;
        let now = chrono::Utc::now().timestamp();
        let elapsed = now - last_cleanup;

        if elapsed > self.config.dynamic.cleanup_interval as i64 {
            self.cleanup_expired().await;
        }
    }

    /// Send alert (if callback set and alerts enabled)
    fn send_alert_if_enabled(&self, reason: BypassReason, host: String) {
        if !self.config.alerts.enabled {
            return;
        }

        // Check specific alert settings
        let should_alert = match reason {
            BypassReason::StaticRule => self.config.alerts.alert_on_static,
            BypassReason::CertificatePinning => self.config.alerts.alert_on_pinning,
            BypassReason::UserConfigured => self.config.alerts.alert_on_dynamic,
            _ => true,
        };

        if should_alert {
            self.send_alert(reason, host);
        }
    }

    /// Send alert unconditionally
    fn send_alert(&self, reason: BypassReason, host: String) {
        if let Some(ref alert_fn) = self.alert_fn {
            alert_fn(reason, host);
        }
    }

    /// Load static rules from configuration
    fn load_static_rules_from_config(config: &BypassConfig) -> HashSet<String> {
        let mut rules = HashSet::new();

        // Load user-provided static rules
        for rule in &config.static_rules {
            rules.insert(rule.pattern.clone());
        }

        // Optionally load example rules
        if config.include_example_rules {
            for rule in ExampleBypassRules::all() {
                rules.insert(rule.pattern);
            }
        }

        if !rules.is_empty() {
            debug!(count = rules.len(), "Loaded static bypass rules");
        }

        rules
    }

    /// Check if pattern matches host (wildcard support)
    fn matches_wildcard(pattern: &str, host: &str) -> bool {
        if pattern.starts_with("*.") {
            let domain = &pattern[2..];
            host.ends_with(domain) || host == domain
        } else {
            pattern == host
        }
    }

    /// Get bypass statistics
    pub async fn stats(&self) -> BypassStats {
        let dynamic = self.dynamic_rules.read().await;

        BypassStats {
            enabled: self.config.enabled,
            static_rules_count: self.static_rules.len(),
            dynamic_rules_count: dynamic.len(),
            allow_dynamic: self.config.allow_dynamic,
            max_dynamic_rules: self.config.dynamic.max_rules,
        }
    }

    /// Get configuration
    pub fn config(&self) -> &BypassConfig {
        &self.config
    }
}

/// Bypass statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassStats {
    pub enabled: bool,
    pub static_rules_count: usize,
    pub dynamic_rules_count: usize,
    pub allow_dynamic: bool,
    pub max_dynamic_rules: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_disabled_bypass_manager() {
        let manager = BypassManager::disabled();

        assert!(!manager.is_enabled());
        assert!(manager.should_bypass("any.domain.com").await.is_none());
    }

    #[tokio::test]
    async fn test_static_bypass_exact_match() {
        let mut config = BypassConfig::default();
        config.static_rules.push(StaticBypassRule {
            pattern: "example.com".to_string(),
            reason: "UserConfigured".to_string(),
            description: None,
        });

        let manager = BypassManager::new(config);

        assert!(manager.should_bypass("example.com").await.is_some());
        assert!(manager.should_bypass("other.com").await.is_none());
    }

    #[tokio::test]
    async fn test_static_bypass_wildcard() {
        let mut config = BypassConfig::default();
        config.static_rules.push(StaticBypassRule {
            pattern: "*.example.com".to_string(),
            reason: "UserConfigured".to_string(),
            description: None,
        });

        let manager = BypassManager::new(config);

        assert!(manager
            .should_bypass("subdomain.example.com")
            .await
            .is_some());
        assert!(manager.should_bypass("example.com").await.is_some());
        assert!(manager.should_bypass("other.com").await.is_none());
    }

    #[tokio::test]
    async fn test_dynamic_bypass_with_policy() {
        let mut config = BypassConfig::default();
        config.allow_dynamic = true;

        let manager = BypassManager::new(config);

        manager
            .add_dynamic_rule(
                "pinned.example.com".to_string(),
                BypassReason::CertificatePinning,
                3600,
            )
            .await;

        assert!(manager.should_bypass("pinned.example.com").await.is_some());
    }

    #[tokio::test]
    async fn test_dynamic_bypass_without_policy() {
        let mut config = BypassConfig::default();
        config.allow_dynamic = false; // Disabled

        let manager = BypassManager::new(config);

        manager
            .add_dynamic_rule(
                "pinned.example.com".to_string(),
                BypassReason::CertificatePinning,
                3600,
            )
            .await;

        // Should not bypass (policy disabled)
        assert!(manager.should_bypass("pinned.example.com").await.is_none());
    }

    #[tokio::test]
    async fn test_bypass_stats() {
        let mut config = BypassConfig::default();
        config.static_rules.push(StaticBypassRule {
            pattern: "example.com".to_string(),
            reason: "UserConfigured".to_string(),
            description: None,
        });
        config.allow_dynamic = true;

        let manager = BypassManager::new(config);

        let stats = manager.stats().await;
        assert_eq!(stats.static_rules_count, 1);
        assert_eq!(stats.dynamic_rules_count, 0);
        assert!(stats.allow_dynamic);
    }

    #[test]
    fn test_wildcard_matching() {
        assert!(BypassManager::matches_wildcard(
            "*.example.com",
            "sub.example.com"
        ));
        assert!(BypassManager::matches_wildcard(
            "*.example.com",
            "example.com"
        ));
        assert!(!BypassManager::matches_wildcard(
            "*.example.com",
            "other.com"
        ));
        assert!(BypassManager::matches_wildcard(
            "example.com",
            "example.com"
        ));
        assert!(!BypassManager::matches_wildcard(
            "example.com",
            "sub.example.com"
        ));
    }
}
