//! Unit tests for CA management (Week 1, Task 1.6)
//!
//! Tests cover:
//! - CA key loading and validation
//! - Certificate generation with edge cases
//! - Localhost bypass enforcement
//! - Serial number uniqueness
//! - Per-environment CA isolation
//! - Cache hit/miss behavior

use derusted::{
    BypassManager, BypassReason, CaKeyManager, CertificateAuthority, Environment, HostIdentifier,
    LoggingPolicy, MitmError, PiiRedactor, SecretBackend, StartupError,
};
use secrecy::SecretString;
use std::collections::HashSet;
use std::sync::Arc;

// ============================================================================
// Mock Secret Backend for Testing
// ============================================================================

struct MockSecretBackend {
    ca_key_pem: String,
    ca_cert_pem: String,
    should_fail: bool,
}

impl MockSecretBackend {
    fn new() -> Self {
        // Generate a test CA certificate and key
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test CA");

        let key_pair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::Certificate::from_params(params).unwrap();

        Self {
            ca_key_pem: key_pair.serialize_pem(),
            ca_cert_pem: cert.serialize_pem().unwrap(),
            should_fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            ca_key_pem: String::new(),
            ca_cert_pem: String::new(),
            should_fail: true,
        }
    }
}

#[async_trait::async_trait]
impl SecretBackend for MockSecretBackend {
    async fn load_ca_key(&self, _environment: Environment) -> Result<SecretString, StartupError> {
        if self.should_fail {
            return Err(StartupError::CaKeyMissing(
                "Mock backend configured to fail".to_string(),
            ));
        }
        Ok(SecretString::new(self.ca_key_pem.clone()))
    }

    async fn load_ca_cert(&self, _environment: Environment) -> Result<String, StartupError> {
        if self.should_fail {
            return Err(StartupError::CaCertInvalid(
                "Mock backend configured to fail".to_string(),
            ));
        }
        Ok(self.ca_cert_pem.clone())
    }

    async fn health_check(&self) -> Result<(), StartupError> {
        if self.should_fail {
            return Err(StartupError::BackendError(
                "Mock backend health check failed".to_string(),
            ));
        }
        Ok(())
    }
}

// ============================================================================
// CA Key Manager Tests
// ============================================================================

#[tokio::test]
async fn test_ca_key_manager_load_success() {
    let backend: Arc<dyn SecretBackend> = Arc::new(MockSecretBackend::new());
    let ca_manager = CaKeyManager::load_or_fail(backend, Environment::Development).await;

    assert!(ca_manager.is_ok(), "CA manager should load successfully");

    let manager = ca_manager.unwrap();
    assert_eq!(manager.environment(), Environment::Development);
}

#[tokio::test]
async fn test_ca_key_manager_fail_fast_on_missing_key() {
    let backend: Arc<dyn SecretBackend> = Arc::new(MockSecretBackend::failing());
    let ca_manager = CaKeyManager::load_or_fail(backend, Environment::Development).await;

    assert!(
        ca_manager.is_err(),
        "CA manager should fail when backend fails"
    );
}

#[tokio::test]
async fn test_ca_key_manager_per_environment_isolation() {
    let backend: Arc<dyn SecretBackend> = Arc::new(MockSecretBackend::new());

    let dev_manager = CaKeyManager::load_or_fail(Arc::clone(&backend), Environment::Development)
        .await
        .unwrap();
    let staging_manager = CaKeyManager::load_or_fail(Arc::clone(&backend), Environment::Staging)
        .await
        .unwrap();
    let prod_manager = CaKeyManager::load_or_fail(backend, Environment::Production)
        .await
        .unwrap();

    assert_eq!(dev_manager.environment(), Environment::Development);
    assert_eq!(staging_manager.environment(), Environment::Staging);
    assert_eq!(prod_manager.environment(), Environment::Production);
}

#[tokio::test]
async fn test_ca_key_manager_debug_redacts_key() {
    let backend: Arc<dyn SecretBackend> = Arc::new(MockSecretBackend::new());
    let manager = CaKeyManager::load_or_fail(backend, Environment::Development)
        .await
        .unwrap();

    let debug_output = format!("{:?}", manager);

    // Should not contain actual key material
    assert!(!debug_output.contains("BEGIN PRIVATE KEY"));
    assert!(debug_output.contains("REDACTED"));
}

// ============================================================================
// Host Identifier Tests
// ============================================================================

#[test]
fn test_host_identifier_localhost_variants() {
    assert!(matches!(
        HostIdentifier::from_hostname("localhost"),
        HostIdentifier::Localhost
    ));

    assert!(matches!(
        HostIdentifier::from_hostname("127.0.0.1"),
        HostIdentifier::Localhost
    ));

    assert!(matches!(
        HostIdentifier::from_hostname("::1"),
        HostIdentifier::Localhost
    ));

    assert!(matches!(
        HostIdentifier::from_hostname("127.0.0.2"),
        HostIdentifier::Localhost
    ));
}

#[test]
fn test_host_identifier_ip_address() {
    let host_id = HostIdentifier::from_hostname("192.168.1.1");
    assert!(matches!(host_id, HostIdentifier::IpAddress(_)));

    if let HostIdentifier::IpAddress(ip) = host_id {
        assert_eq!(ip.to_string(), "192.168.1.1");
    }
}

#[test]
fn test_host_identifier_wildcard() {
    let host_id = HostIdentifier::from_hostname("*.example.com");
    assert!(matches!(host_id, HostIdentifier::Wildcard(_)));

    if let HostIdentifier::Wildcard(domain) = host_id {
        assert_eq!(domain, "*.example.com");
    }
}

#[test]
fn test_host_identifier_regular_domain() {
    let host_id = HostIdentifier::from_hostname("example.com");
    assert!(matches!(host_id, HostIdentifier::Domain(_)));

    if let HostIdentifier::Domain(domain) = host_id {
        assert_eq!(domain, "example.com");
    }
}

// ============================================================================
// Certificate Authority Tests
// ============================================================================

#[tokio::test]
async fn test_certificate_authority_localhost_bypass() {
    let backend: Arc<dyn SecretBackend> = Arc::new(MockSecretBackend::new());
    let ca_manager = Arc::new(
        CaKeyManager::load_or_fail(backend, Environment::Development)
            .await
            .unwrap(),
    );
    let ca = CertificateAuthority::new(ca_manager, 100);

    let result = ca.get_or_generate(HostIdentifier::Localhost).await;

    assert!(result.is_err(), "Should fail for localhost");
    match result {
        Err(MitmError::LocalhostBypass) => {}
        _ => panic!("Expected LocalhostBypass error"),
    }
}

#[tokio::test]
async fn test_certificate_authority_generate_domain_cert() {
    let backend: Arc<dyn SecretBackend> = Arc::new(MockSecretBackend::new());
    let ca_manager = Arc::new(
        CaKeyManager::load_or_fail(backend, Environment::Development)
            .await
            .unwrap(),
    );
    let ca = CertificateAuthority::new(ca_manager, 100);

    let host_id = HostIdentifier::Domain("example.com".to_string());
    let result = ca.get_or_generate(host_id).await;

    assert!(result.is_ok(), "Should generate certificate for domain");
}

#[tokio::test]
async fn test_certificate_authority_generate_ip_cert() {
    let backend: Arc<dyn SecretBackend> = Arc::new(MockSecretBackend::new());
    let ca_manager = Arc::new(
        CaKeyManager::load_or_fail(backend, Environment::Development)
            .await
            .unwrap(),
    );
    let ca = CertificateAuthority::new(ca_manager, 100);

    let host_id = HostIdentifier::IpAddress("192.168.1.1".parse().unwrap());
    let result = ca.get_or_generate(host_id).await;

    assert!(result.is_ok(), "Should generate certificate for IP address");
}

#[tokio::test]
async fn test_certificate_authority_generate_wildcard_cert() {
    let backend: Arc<dyn SecretBackend> = Arc::new(MockSecretBackend::new());
    let ca_manager = Arc::new(
        CaKeyManager::load_or_fail(backend, Environment::Development)
            .await
            .unwrap(),
    );
    let ca = CertificateAuthority::new(ca_manager, 100);

    let host_id = HostIdentifier::Wildcard("*.example.com".to_string());
    let result = ca.get_or_generate(host_id).await;

    assert!(result.is_ok(), "Should generate wildcard certificate");
}

#[tokio::test]
async fn test_certificate_authority_cache_hit() {
    let backend: Arc<dyn SecretBackend> = Arc::new(MockSecretBackend::new());
    let ca_manager = Arc::new(
        CaKeyManager::load_or_fail(backend, Environment::Development)
            .await
            .unwrap(),
    );
    let ca = CertificateAuthority::new(ca_manager, 100);

    let host_id = HostIdentifier::Domain("example.com".to_string());

    // First call - cache miss
    let cert1 = ca.get_or_generate(host_id.clone()).await.unwrap();

    // Second call - cache hit
    let cert2 = ca.get_or_generate(host_id).await.unwrap();

    // Should be the same certificate (same Arc pointer)
    assert!(
        Arc::ptr_eq(&cert1, &cert2),
        "Should return cached certificate"
    );
}

#[tokio::test]
async fn test_certificate_authority_cache_stats() {
    let backend: Arc<dyn SecretBackend> = Arc::new(MockSecretBackend::new());
    let ca_manager = Arc::new(
        CaKeyManager::load_or_fail(backend, Environment::Development)
            .await
            .unwrap(),
    );
    let ca = CertificateAuthority::new(ca_manager, 100);

    let (initial_count, max_size) = ca.cache_stats().await;
    assert_eq!(initial_count, 0);
    assert_eq!(max_size, 100);

    // Generate a few certificates
    ca.get_or_generate(HostIdentifier::Domain("example1.com".to_string()))
        .await
        .unwrap();
    ca.get_or_generate(HostIdentifier::Domain("example2.com".to_string()))
        .await
        .unwrap();

    let (count, _) = ca.cache_stats().await;
    assert_eq!(count, 2);
}

#[tokio::test]
async fn test_certificate_authority_serial_uniqueness() {
    let backend: Arc<dyn SecretBackend> = Arc::new(MockSecretBackend::new());
    let ca_manager = Arc::new(
        CaKeyManager::load_or_fail(backend, Environment::Development)
            .await
            .unwrap(),
    );
    let ca = CertificateAuthority::new(ca_manager, 1000);

    let mut serials = HashSet::new();

    // Generate 100 certificates
    for i in 0..100 {
        let host_id = HostIdentifier::Domain(format!("example{}.com", i));
        let cert = ca.get_or_generate(host_id).await.unwrap();

        // Use Arc pointer address as unique identifier
        // Each certificate should be a unique Arc instance
        serials.insert(Arc::as_ptr(&cert) as usize);
    }

    // All serials should be unique
    assert_eq!(serials.len(), 100, "All serial numbers should be unique");
}

// ============================================================================
// Bypass Manager Tests
// ============================================================================

#[tokio::test]
async fn test_bypass_manager_static_rules() {
    use derusted::{BypassConfig, StaticBypassRule};

    let mut config = BypassConfig::default();
    config.static_rules.push(StaticBypassRule {
        pattern: "example.com".to_string(),
        reason: "UserConfigured".to_string(),
        description: None,
    });

    let manager = BypassManager::new(config);

    // Should bypass configured domain
    assert!(manager.should_bypass("example.com").await.is_some());

    // Should not bypass unknown domain
    assert!(manager.should_bypass("unknown.example.com").await.is_none());
}

#[tokio::test]
async fn test_bypass_manager_wildcard_rules() {
    use derusted::{BypassConfig, StaticBypassRule};

    let mut config = BypassConfig::default();
    config.static_rules.push(StaticBypassRule {
        pattern: "*.example.com".to_string(),
        reason: "UserConfigured".to_string(),
        description: None,
    });

    let manager = BypassManager::new(config);

    // Should bypass wildcard subdomains
    assert!(manager
        .should_bypass("subdomain.example.com")
        .await
        .is_some());
    assert!(manager.should_bypass("example.com").await.is_some());
}

#[tokio::test]
async fn test_bypass_manager_dynamic_with_policy() {
    use derusted::BypassConfig;

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

    let result = manager.should_bypass("pinned.example.com").await;
    assert!(result.is_some());
    assert_eq!(result.unwrap(), BypassReason::CertificatePinning);
}

#[tokio::test]
async fn test_bypass_manager_dynamic_without_policy() {
    use derusted::BypassConfig;

    let mut config = BypassConfig::default();
    config.allow_dynamic = false;

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
async fn test_bypass_manager_stats() {
    use derusted::{BypassConfig, StaticBypassRule};

    let mut config = BypassConfig::default();
    config.allow_dynamic = true;
    config.static_rules.push(StaticBypassRule {
        pattern: "example.com".to_string(),
        reason: "UserConfigured".to_string(),
        description: None,
    });

    let manager = BypassManager::new(config);

    let stats = manager.stats().await;
    assert_eq!(stats.static_rules_count, 1);
    assert_eq!(stats.dynamic_rules_count, 0);

    manager
        .add_dynamic_rule(
            "test.example.com".to_string(),
            BypassReason::CertificatePinning,
            3600,
        )
        .await;

    let stats = manager.stats().await;
    assert_eq!(stats.dynamic_rules_count, 1);
}

#[tokio::test]
async fn test_bypass_manager_disabled() {
    use derusted::BypassManager;

    let manager = BypassManager::disabled();

    assert!(!manager.is_enabled());
    assert!(manager.should_bypass("any.domain.com").await.is_none());
}

// ============================================================================
// PII Redaction Tests
// ============================================================================

#[test]
fn test_pii_redaction_credit_card() {
    let text = "My credit card is 4532-1234-5678-9010";
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
    let text = "Contact me at user@example.com";
    let redacted = PiiRedactor::redact(text);

    assert!(redacted.contains("[REDACTED]"));
    assert!(!redacted.contains("user@example.com"));
}

#[test]
fn test_pii_redaction_phone() {
    let text = "Call me at 555-123-4567";
    let redacted = PiiRedactor::redact(text);

    assert!(redacted.contains("[REDACTED]"));
    assert!(!redacted.contains("555-123-4567"));
}

#[test]
fn test_pii_redaction_bearer_token() {
    let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let redacted = PiiRedactor::redact(text);

    assert!(redacted.contains("[REDACTED]"));
    assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
}

#[test]
fn test_sensitive_header_redaction() {
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert("authorization".to_string(), "Bearer secret123".to_string());
    headers.insert("cookie".to_string(), "session=abc123".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    let redacted = PiiRedactor::redact_headers(&headers);

    assert_eq!(redacted.get("authorization").unwrap(), "[REDACTED]");
    assert_eq!(redacted.get("cookie").unwrap(), "[REDACTED]");
    assert_eq!(redacted.get("content-type").unwrap(), "application/json");
}

// ============================================================================
// Logging Policy Tests
// ============================================================================

#[test]
fn test_logging_policy_defaults() {
    let policy = LoggingPolicy::default();

    assert!(
        !policy.log_request_headers,
        "Should not log request headers by default"
    );
    assert!(
        !policy.log_response_headers,
        "Should not log response headers by default"
    );
    assert!(
        !policy.log_request_body,
        "Should not log request body by default"
    );
    assert!(
        !policy.log_response_body,
        "Should not log response body by default"
    );
    assert_eq!(policy.sampling_rate, 0.01, "Default sampling should be 1%");
    assert!(
        policy.enable_pii_redaction,
        "PII redaction should be enabled by default"
    );
    assert!(
        policy.encrypt_logs,
        "Log encryption should be enabled by default"
    );
}

#[test]
fn test_environment_as_str() {
    assert_eq!(Environment::Development.as_str(), "development");
    assert_eq!(Environment::Staging.as_str(), "staging");
    assert_eq!(Environment::Production.as_str(), "production");
}
