//! Certificate Pinning Detection
//!
//! This module detects certificate pinning failures and can automatically
//! add domains to the bypass list to prevent repeated errors.
//!
//! ## How it works
//! 1. Monitor TLS handshake failures
//! 2. Detect patterns that indicate certificate pinning
//! 3. Optionally auto-add to bypass list (if configured)
//! 4. Alert/log pinning events

use crate::mitm::bypass::{BypassManager, BypassReason};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Pinning detection policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinningPolicy {
    /// Detect pinning failures (default: true)
    pub detect_pinning: bool,

    /// Auto-add pinned domains to bypass (default: false)
    /// IMPORTANT: Only enable if you understand the security implications
    pub auto_bypass: bool,

    /// Number of failures before considering pinned (default: 3)
    pub failure_threshold: u32,

    /// Time window for failure counting (seconds, default: 300 = 5 minutes)
    pub failure_window: u64,

    /// Alert on pinning detection (default: true)
    pub alert_on_pinning: bool,
}

impl Default for PinningPolicy {
    fn default() -> Self {
        Self {
            detect_pinning: true,
            auto_bypass: false, // Secure default: don't auto-bypass
            failure_threshold: 3,
            failure_window: 300,
            alert_on_pinning: true,
        }
    }
}

impl PinningPolicy {
    /// Create policy with secure defaults (no auto-bypass)
    pub fn secure() -> Self {
        Self::default()
    }

    /// Create policy with auto-bypass enabled
    /// DANGEROUS: Only use for testing or if you understand the implications
    pub fn with_auto_bypass() -> Self {
        Self {
            auto_bypass: true,
            ..Default::default()
        }
    }

    /// Create policy from environment variables
    pub fn from_env() -> Self {
        let mut policy = Self::default();

        if let Ok(val) = std::env::var("DERUSTED_PINNING_DETECT") {
            policy.detect_pinning = val.parse().unwrap_or(true);
        }

        if let Ok(val) = std::env::var("DERUSTED_PINNING_AUTO_BYPASS") {
            policy.auto_bypass = val.parse().unwrap_or(false);
        }

        if let Ok(val) = std::env::var("DERUSTED_PINNING_THRESHOLD") {
            policy.failure_threshold = val.parse().unwrap_or(3);
        }

        if let Ok(val) = std::env::var("DERUSTED_PINNING_WINDOW") {
            policy.failure_window = val.parse().unwrap_or(300);
        }

        if let Ok(val) = std::env::var("DERUSTED_PINNING_ALERT") {
            policy.alert_on_pinning = val.parse().unwrap_or(true);
        }

        policy
    }
}

/// Pinning failure record
#[derive(Debug, Clone)]
struct PinningFailure {
    /// Number of consecutive failures
    count: u32,

    /// First failure timestamp
    first_failure: i64,

    /// Last failure timestamp
    last_failure: i64,

    /// Error message from last failure
    error: String,
}

/// Pinning detection result
#[derive(Debug, Clone)]
pub struct PinningDetection {
    /// Was pinning detected?
    pub detected: bool,

    /// Domain that triggered pinning
    pub domain: String,

    /// Number of failures
    pub failure_count: u32,

    /// Was auto-bypassed?
    pub auto_bypassed: bool,
}

/// Pinning Detector
pub struct PinningDetector {
    /// Detection policy
    policy: PinningPolicy,

    /// Failure tracking (domain -> failure record)
    failures: Arc<RwLock<HashMap<String, PinningFailure>>>,

    /// Bypass manager (for auto-bypass)
    bypass_manager: Option<Arc<BypassManager>>,

    /// Alert callback
    alert_fn: Option<Arc<dyn Fn(String, String) + Send + Sync>>,
}

impl PinningDetector {
    /// Create new detector with default policy
    pub fn new() -> Self {
        Self::with_policy(PinningPolicy::default())
    }

    /// Create detector with custom policy
    pub fn with_policy(policy: PinningPolicy) -> Self {
        Self {
            policy,
            failures: Arc::new(RwLock::new(HashMap::new())),
            bypass_manager: None,
            alert_fn: None,
        }
    }

    /// Create from environment variables
    pub fn from_env() -> Self {
        Self::with_policy(PinningPolicy::from_env())
    }

    /// Set bypass manager (for auto-bypass)
    pub fn with_bypass_manager(mut self, bypass_manager: Arc<BypassManager>) -> Self {
        self.bypass_manager = Some(bypass_manager);
        self
    }

    /// Set alert callback
    pub fn with_alert_fn<F>(mut self, alert_fn: F) -> Self
    where
        F: Fn(String, String) + Send + Sync + 'static,
    {
        self.alert_fn = Some(Arc::new(alert_fn));
        self
    }

    /// Record TLS handshake failure
    pub async fn record_failure(&self, domain: &str, error: &str) -> PinningDetection {
        if !self.policy.detect_pinning {
            return PinningDetection {
                detected: false,
                domain: domain.to_string(),
                failure_count: 0,
                auto_bypassed: false,
            };
        }

        let now = chrono::Utc::now().timestamp();
        let mut failures = self.failures.write().await;

        let failure = failures
            .entry(domain.to_string())
            .or_insert(PinningFailure {
                count: 0,
                first_failure: now,
                last_failure: now,
                error: String::new(),
            });

        // Check if within time window
        if now - failure.first_failure > self.policy.failure_window as i64 {
            // Reset counter if outside window
            failure.count = 1;
            failure.first_failure = now;
            failure.last_failure = now;
            failure.error = error.to_string();

            debug!(
                domain = %domain,
                "TLS failure recorded (reset counter)"
            );

            return PinningDetection {
                detected: false,
                domain: domain.to_string(),
                failure_count: 1,
                auto_bypassed: false,
            };
        }

        // Increment counter
        failure.count += 1;
        failure.last_failure = now;
        failure.error = error.to_string();

        debug!(
            domain = %domain,
            count = failure.count,
            threshold = self.policy.failure_threshold,
            "TLS failure recorded"
        );

        // Check threshold
        if failure.count >= self.policy.failure_threshold {
            warn!(
                domain = %domain,
                count = failure.count,
                error = %error,
                "Certificate pinning detected"
            );

            // Alert if configured
            if self.policy.alert_on_pinning {
                if let Some(alert_fn) = &self.alert_fn {
                    alert_fn(domain.to_string(), error.to_string());
                }
            }

            // Auto-bypass if configured
            let auto_bypassed = if self.policy.auto_bypass {
                if let Some(bypass_manager) = &self.bypass_manager {
                    bypass_manager
                        .add_dynamic_rule(
                            domain.to_string(),
                            BypassReason::CertificatePinning,
                            3600, // 1 hour TTL
                        )
                        .await;
                    info!(
                        domain = %domain,
                        "Auto-bypassed pinned domain"
                    );
                    true
                } else {
                    warn!("Auto-bypass enabled but no BypassManager configured");
                    false
                }
            } else {
                false
            };

            return PinningDetection {
                detected: true,
                domain: domain.to_string(),
                failure_count: failure.count,
                auto_bypassed,
            };
        }

        PinningDetection {
            detected: false,
            domain: domain.to_string(),
            failure_count: failure.count,
            auto_bypassed: false,
        }
    }

    /// Check if domain has pinning failures
    pub async fn has_failures(&self, domain: &str) -> bool {
        let failures = self.failures.read().await;
        failures.contains_key(domain)
    }

    /// Get failure count for domain
    pub async fn get_failure_count(&self, domain: &str) -> u32 {
        let failures = self.failures.read().await;
        failures.get(domain).map(|f| f.count).unwrap_or(0)
    }

    /// Clear failures for domain
    pub async fn clear_failures(&self, domain: &str) {
        let mut failures = self.failures.write().await;
        if failures.remove(domain).is_some() {
            debug!(domain = %domain, "Cleared pinning failures");
        }
    }

    /// Clear all failures
    pub async fn clear_all_failures(&self) {
        let mut failures = self.failures.write().await;
        failures.clear();
        info!("Cleared all pinning failures");
    }

    /// Cleanup expired failure records
    pub async fn cleanup_expired(&self) {
        let mut failures = self.failures.write().await;
        let now = chrono::Utc::now().timestamp();
        let window = self.policy.failure_window as i64;

        failures.retain(|domain, failure| {
            if now - failure.last_failure > window {
                debug!(domain = %domain, "Expired pinning failure record");
                false
            } else {
                true
            }
        });
    }

    /// Get policy
    pub fn policy(&self) -> &PinningPolicy {
        &self.policy
    }

    /// Get statistics
    pub async fn stats(&self) -> PinningStats {
        let failures = self.failures.read().await;
        let total_domains = failures.len();
        let pinned_domains = failures
            .values()
            .filter(|f| f.count >= self.policy.failure_threshold)
            .count();

        PinningStats {
            total_domains,
            pinned_domains,
        }
    }
}

impl Default for PinningDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Pinning detection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinningStats {
    /// Total domains with failures
    pub total_domains: usize,

    /// Domains considered pinned (>= threshold)
    pub pinned_domains: usize,
}

/// Common pinning error patterns
pub struct PinningPatterns;

impl PinningPatterns {
    /// Check if error message indicates pinning
    pub fn is_pinning_error(error: &str) -> bool {
        let error_lower = error.to_lowercase();

        // Common pinning error patterns
        let patterns = [
            "certificate verify failed",
            "certificate validation failed",
            "ssl handshake failed",
            "tls handshake failed",
            "certificate not trusted",
            "unknown ca",
            "self signed certificate",
            "certificate signature failure",
        ];

        for pattern in &patterns {
            if error_lower.contains(pattern) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pinning_policy_defaults() {
        let policy = PinningPolicy::default();
        assert!(policy.detect_pinning);
        assert!(!policy.auto_bypass); // Secure default
        assert_eq!(policy.failure_threshold, 3);
        assert_eq!(policy.failure_window, 300);
        assert!(policy.alert_on_pinning);
    }

    #[tokio::test]
    async fn test_pinning_detector_threshold() {
        let detector = PinningDetector::new();

        // First failure - not detected
        let result = detector
            .record_failure("pinned.com", "cert verify failed")
            .await;
        assert!(!result.detected);
        assert_eq!(result.failure_count, 1);

        // Second failure - not detected
        let result = detector
            .record_failure("pinned.com", "cert verify failed")
            .await;
        assert!(!result.detected);
        assert_eq!(result.failure_count, 2);

        // Third failure - detected
        let result = detector
            .record_failure("pinned.com", "cert verify failed")
            .await;
        assert!(result.detected);
        assert_eq!(result.failure_count, 3);
    }

    #[tokio::test]
    async fn test_pinning_detector_window() {
        let mut policy = PinningPolicy::default();
        policy.failure_window = 1; // 1 second window
        let detector = PinningDetector::with_policy(policy);

        // Record failure
        detector.record_failure("example.com", "error").await;
        assert_eq!(detector.get_failure_count("example.com").await, 1);

        // Wait for window to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Should reset counter
        let result = detector.record_failure("example.com", "error").await;
        assert_eq!(result.failure_count, 1);
    }

    #[tokio::test]
    async fn test_pinning_detector_clear_failures() {
        let detector = PinningDetector::new();

        detector.record_failure("example.com", "error").await;
        assert!(detector.has_failures("example.com").await);

        detector.clear_failures("example.com").await;
        assert!(!detector.has_failures("example.com").await);
    }

    #[tokio::test]
    async fn test_pinning_detector_cleanup_expired() {
        let mut policy = PinningPolicy::default();
        policy.failure_window = 1; // 1 second window
        let detector = PinningDetector::with_policy(policy);

        detector.record_failure("example.com", "error").await;
        assert!(detector.has_failures("example.com").await);

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        detector.cleanup_expired().await;
        assert!(!detector.has_failures("example.com").await);
    }

    #[tokio::test]
    async fn test_pinning_stats() {
        let detector = PinningDetector::new();

        // Record failures for multiple domains
        for _ in 0..3 {
            detector.record_failure("pinned1.com", "error").await;
        }
        for _ in 0..2 {
            detector.record_failure("pinned2.com", "error").await;
        }

        let stats = detector.stats().await;
        assert_eq!(stats.total_domains, 2);
        assert_eq!(stats.pinned_domains, 1); // Only pinned1.com >= threshold
    }

    #[test]
    fn test_pinning_patterns() {
        assert!(PinningPatterns::is_pinning_error(
            "certificate verify failed"
        ));
        assert!(PinningPatterns::is_pinning_error("TLS handshake failed"));
        assert!(PinningPatterns::is_pinning_error("Certificate not trusted"));
        assert!(!PinningPatterns::is_pinning_error("connection timeout"));
        assert!(!PinningPatterns::is_pinning_error("dns resolution failed"));
    }
}
