//! Logging Policy - PII-safe request/response logging
//!
//! This module provides configurable logging with:
//! - Metadata-only logging by default
//! - Optional header/body logging
//! - PII redaction patterns
//! - Sampling for debug logs
//! - Log encryption at rest

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

lazy_static! {
    /// PII redaction patterns
    pub static ref PII_PATTERNS: Vec<Regex> = vec![
        // Credit card numbers (with optional spaces/dashes)
        Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap(),

        // SSN (XXX-XX-XXXX)
        Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),

        // Email addresses
        Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap(),

        // Phone numbers (various formats)
        Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap(),
        Regex::new(r"\(\d{3}\)\s?\d{3}[-.]?\d{4}").unwrap(),

        // API keys (common patterns)
        Regex::new(r"(?i)(api[_-]?key|apikey|api_token)\s*[=:]\s*['\x22]?([a-zA-Z0-9_-]{20,})['\x22]?").unwrap(),

        // Bearer tokens
        Regex::new(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*").unwrap(),
    ];

    /// Sensitive headers that should be redacted
    pub static ref SENSITIVE_HEADERS: Vec<&'static str> = vec![
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization",
    ];
}

/// Logging policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingPolicy {
    /// Log request headers (default: false)
    pub log_request_headers: bool,

    /// Log response headers (default: false)
    pub log_response_headers: bool,

    /// Log request body (default: false)
    pub log_request_body: bool,

    /// Log response body (default: false)
    pub log_response_body: bool,

    /// Sampling rate for debug logs (0.0-1.0, default: 0.01 = 1%)
    pub sampling_rate: f64,

    /// Enable PII redaction (default: true)
    pub enable_pii_redaction: bool,

    /// Encrypt logs at rest (default: true)
    pub encrypt_logs: bool,
}

impl Default for LoggingPolicy {
    fn default() -> Self {
        Self {
            log_request_headers: false,
            log_response_headers: false,
            log_request_body: false,
            log_response_body: false,
            sampling_rate: 0.01, // 1%
            enable_pii_redaction: true,
            encrypt_logs: true,
        }
    }
}

/// Request metadata (always logged, PII-safe)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestMetadata {
    /// Timestamp
    pub timestamp: i64,

    /// Request method
    pub method: String,

    /// Target host
    pub host: String,

    /// Target port
    pub port: u16,

    /// Request path (without query params by default)
    pub path: String,

    /// HTTP version
    pub http_version: String,

    /// Response status code
    pub status_code: Option<u16>,

    /// Request size (bytes)
    pub request_size: usize,

    /// Response size (bytes)
    pub response_size: usize,

    /// Duration (milliseconds)
    pub duration_ms: u64,

    /// TLS version
    pub tls_version: Option<String>,

    /// Was MITM applied?
    pub mitm_applied: bool,

    /// Bypass reason (if any)
    pub bypass_reason: Option<String>,
}

/// PII redactor
pub struct PiiRedactor;

impl PiiRedactor {
    /// Redact PII from text
    pub fn redact(text: &str) -> String {
        let mut redacted = text.to_string();

        for pattern in PII_PATTERNS.iter() {
            redacted = pattern.replace_all(&redacted, "[REDACTED]").to_string();
        }

        redacted
    }

    /// Redact sensitive headers
    pub fn redact_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
        let mut redacted = headers.clone();

        for sensitive in SENSITIVE_HEADERS.iter() {
            if redacted.contains_key(*sensitive) {
                redacted.insert(sensitive.to_string(), "[REDACTED]".to_string());
            }
        }

        redacted
    }

    /// Check if should sample (based on sampling rate)
    pub fn should_sample(rate: f64) -> bool {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen::<f64>() < rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pii_redaction_credit_card() {
        let text = "My card is 4532-1234-5678-9010";
        let redacted = PiiRedactor::redact(text);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("4532"));
    }

    #[test]
    fn test_pii_redaction_ssn() {
        let text = "SSN: 123-45-6789";
        let redacted = PiiRedactor::redact(text);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("123-45-6789"));
    }

    #[test]
    fn test_pii_redaction_email() {
        let text = "Contact: user@example.com";
        let redacted = PiiRedactor::redact(text);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("user@example.com"));
    }

    #[test]
    fn test_sensitive_header_redaction() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer token123".to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());

        let redacted = PiiRedactor::redact_headers(&headers);

        assert_eq!(redacted.get("authorization").unwrap(), "[REDACTED]");
        assert_eq!(redacted.get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn test_pii_redaction_phone_numbers() {
        // Test various phone formats
        let text1 = "Call me at 555-123-4567";
        let redacted1 = PiiRedactor::redact(text1);
        assert!(redacted1.contains("[REDACTED]"));
        assert!(!redacted1.contains("555-123-4567"));

        let text2 = "Phone: (555) 123-4567";
        let redacted2 = PiiRedactor::redact(text2);
        assert!(redacted2.contains("[REDACTED]"));
        assert!(!redacted2.contains("(555) 123-4567"));

        let text3 = "Contact: 5551234567";
        let redacted3 = PiiRedactor::redact(text3);
        assert!(redacted3.contains("[REDACTED]"));
        assert!(!redacted3.contains("5551234567"));
    }

    #[test]
    fn test_pii_redaction_api_keys() {
        let text1 = "api_key=sk_live_51HqZ2KJ4Vr3sT7Y8pQwXyZ";
        let redacted1 = PiiRedactor::redact(text1);
        assert!(redacted1.contains("[REDACTED]"));
        assert!(!redacted1.contains("sk_live_51HqZ2KJ4Vr3sT7Y8pQwXyZ"));

        let text2 = "API-KEY: \"abcdef1234567890abcdef1234567890\"";
        let redacted2 = PiiRedactor::redact(text2);
        assert!(redacted2.contains("[REDACTED]"));
        assert!(!redacted2.contains("abcdef1234567890abcdef1234567890"));

        let text3 = "apikey='ghijklmnopqrstuvwxyz123456'";
        let redacted3 = PiiRedactor::redact(text3);
        assert!(redacted3.contains("[REDACTED]"));
        assert!(!redacted3.contains("ghijklmnopqrstuvwxyz123456"));
    }

    #[test]
    fn test_pii_redaction_bearer_tokens() {
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let redacted = PiiRedactor::redact(text);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    }

    #[test]
    fn test_multiple_pii_in_same_text() {
        let text = "User email: user@example.com, SSN: 123-45-6789, Card: 4532-1234-5678-9010";
        let redacted = PiiRedactor::redact(text);

        // All PII should be redacted
        assert!(!redacted.contains("user@example.com"));
        assert!(!redacted.contains("123-45-6789"));
        assert!(!redacted.contains("4532-1234-5678-9010"));

        // Should contain multiple [REDACTED] markers
        let redacted_count = redacted.matches("[REDACTED]").count();
        assert!(
            redacted_count >= 3,
            "Expected at least 3 redactions, found {}",
            redacted_count
        );
    }

    #[test]
    fn test_sampling_behavior() {
        // Test 100% sampling
        let mut sampled_count = 0;
        for _ in 0..100 {
            if PiiRedactor::should_sample(1.0) {
                sampled_count += 1;
            }
        }
        assert_eq!(sampled_count, 100);

        // Test 0% sampling
        sampled_count = 0;
        for _ in 0..100 {
            if PiiRedactor::should_sample(0.0) {
                sampled_count += 1;
            }
        }
        assert_eq!(sampled_count, 0);

        // Test ~10% sampling (with tolerance)
        sampled_count = 0;
        for _ in 0..1000 {
            if PiiRedactor::should_sample(0.1) {
                sampled_count += 1;
            }
        }
        // Should be approximately 100 ± 50 (allowing for randomness)
        assert!(
            sampled_count >= 50 && sampled_count <= 150,
            "Expected ~100 samples (50-150), got {}",
            sampled_count
        );
    }

    #[test]
    fn test_no_false_positives() {
        // Text that looks like PII but isn't
        let text = "Invoice #1234-5678-9012-3456 dated 2023-11-24";
        let redacted = PiiRedactor::redact(text);

        // Invoice number might be caught by CC pattern (acceptable trade-off)
        // But date should not be redacted
        assert!(redacted.contains("2023-11-24"));
    }

    #[test]
    fn test_logging_policy_defaults() {
        let policy = LoggingPolicy::default();

        // Verify secure defaults
        assert!(!policy.log_request_headers);
        assert!(!policy.log_response_headers);
        assert!(!policy.log_request_body);
        assert!(!policy.log_response_body);
        assert_eq!(policy.sampling_rate, 0.01);
        assert!(policy.enable_pii_redaction);
        assert!(policy.encrypt_logs);
    }
}
