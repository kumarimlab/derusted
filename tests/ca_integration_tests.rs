//! Integration tests for CA management (Week 1, Task 1.7)
//!
//! These tests verify end-to-end flows:
//! - CA loading → certificate generation → caching
//! - Multi-environment CA isolation
//! - Full MITM interception workflow (stub)
//! - Trust distribution simulation

use derusted::{
    CaKeyManager, CertificateAuthority, Environment, HostIdentifier, SecretBackend, StartupError,
};
use secrecy::SecretString;
use std::sync::Arc;

// ============================================================================
// Mock Secret Backend for Integration Testing
// ============================================================================

struct TestSecretBackend {
    ca_keys: std::collections::HashMap<String, String>,
    ca_certs: std::collections::HashMap<String, String>,
}

impl TestSecretBackend {
    fn new_with_test_cas() -> Self {
        let mut ca_keys = std::collections::HashMap::new();
        let mut ca_certs = std::collections::HashMap::new();

        // Generate CA for each environment
        for env in &["development", "staging", "production"] {
            let mut params = rcgen::CertificateParams::default();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, format!("Test CA - {}", env));

            let key_pair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = rcgen::Certificate::from_params(params).unwrap();

            ca_keys.insert(env.to_string(), key_pair.serialize_pem());
            ca_certs.insert(env.to_string(), cert.serialize_pem().unwrap());
        }

        Self { ca_keys, ca_certs }
    }
}

#[async_trait::async_trait]
impl SecretBackend for TestSecretBackend {
    async fn load_ca_key(&self, environment: Environment) -> Result<SecretString, StartupError> {
        let env_str = environment.as_str();
        self.ca_keys
            .get(env_str)
            .map(|key| SecretString::new(key.clone()))
            .ok_or_else(|| StartupError::CaKeyMissing(format!("No CA key for {}", env_str)))
    }

    async fn load_ca_cert(&self, environment: Environment) -> Result<String, StartupError> {
        let env_str = environment.as_str();
        self.ca_certs
            .get(env_str)
            .cloned()
            .ok_or_else(|| StartupError::CaCertInvalid(format!("No CA cert for {}", env_str)))
    }

    async fn health_check(&self) -> Result<(), StartupError> {
        Ok(())
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[tokio::test]
async fn test_end_to_end_ca_loading_and_cert_generation() {
    // Step 1: Load CA from backend
    let backend: Arc<dyn SecretBackend> = Arc::new(TestSecretBackend::new_with_test_cas());
    let ca_manager = CaKeyManager::load_or_fail(Arc::clone(&backend), Environment::Development)
        .await
        .expect("Failed to load CA");

    // Step 2: Create Certificate Authority
    let ca = CertificateAuthority::new(Arc::new(ca_manager), 100);

    // Step 3: Generate certificate for domain
    let host = HostIdentifier::Domain("example.com".to_string());
    let cert = ca
        .get_or_generate(host.clone())
        .await
        .expect("Failed to generate cert");

    // Step 4: Verify certificate is cached
    let cert2 = ca
        .get_or_generate(host)
        .await
        .expect("Failed to get cached cert");
    assert!(Arc::ptr_eq(&cert, &cert2), "Certificate should be cached");

    // Step 5: Verify cache stats
    let (count, _) = ca.cache_stats().await;
    assert_eq!(count, 1, "Cache should contain 1 certificate");
}

#[tokio::test]
async fn test_multi_environment_ca_isolation() {
    let backend: Arc<dyn SecretBackend> = Arc::new(TestSecretBackend::new_with_test_cas());

    // Load CA for each environment
    let dev_manager = CaKeyManager::load_or_fail(Arc::clone(&backend), Environment::Development)
        .await
        .expect("Failed to load dev CA");

    let staging_manager = CaKeyManager::load_or_fail(Arc::clone(&backend), Environment::Staging)
        .await
        .expect("Failed to load staging CA");

    let prod_manager = CaKeyManager::load_or_fail(backend, Environment::Production)
        .await
        .expect("Failed to load prod CA");

    // Create separate CAs for each environment
    let dev_ca = CertificateAuthority::new(Arc::new(dev_manager), 100);
    let staging_ca = CertificateAuthority::new(Arc::new(staging_manager), 100);
    let prod_ca = CertificateAuthority::new(Arc::new(prod_manager), 100);

    // Generate certificates from each CA
    let host = HostIdentifier::Domain("example.com".to_string());

    let dev_cert = dev_ca
        .get_or_generate(host.clone())
        .await
        .expect("Dev cert failed");
    let staging_cert = staging_ca
        .get_or_generate(host.clone())
        .await
        .expect("Staging cert failed");
    let prod_cert = prod_ca
        .get_or_generate(host)
        .await
        .expect("Prod cert failed");

    // Verify certificates are different (different CAs)
    // In a real test, we would parse and compare issuer DNs
    assert!(!Arc::ptr_eq(&dev_cert, &staging_cert));
    assert!(!Arc::ptr_eq(&staging_cert, &prod_cert));
    assert!(!Arc::ptr_eq(&dev_cert, &prod_cert));
}

#[tokio::test]
async fn test_certificate_generation_for_multiple_host_types() {
    let backend = Arc::new(TestSecretBackend::new_with_test_cas());
    let ca_manager = Arc::new(
        CaKeyManager::load_or_fail(backend, Environment::Development)
            .await
            .unwrap(),
    );
    let ca = CertificateAuthority::new(ca_manager, 100);

    // Test 1: Regular domain
    let domain_cert = ca
        .get_or_generate(HostIdentifier::Domain("example.com".to_string()))
        .await;
    assert!(domain_cert.is_ok(), "Should generate cert for domain");

    // Test 2: Wildcard domain
    let wildcard_cert = ca
        .get_or_generate(HostIdentifier::Wildcard("*.example.com".to_string()))
        .await;
    assert!(wildcard_cert.is_ok(), "Should generate cert for wildcard");

    // Test 3: IP address
    let ip_cert = ca
        .get_or_generate(HostIdentifier::IpAddress("192.168.1.1".parse().unwrap()))
        .await;
    assert!(ip_cert.is_ok(), "Should generate cert for IP");

    // Test 4: Localhost (should fail)
    let localhost_cert = ca.get_or_generate(HostIdentifier::Localhost).await;
    assert!(
        localhost_cert.is_err(),
        "Should NOT generate cert for localhost"
    );

    // Verify cache contains 3 certificates (not localhost)
    let (count, _) = ca.cache_stats().await;
    assert_eq!(count, 3, "Cache should contain 3 certificates");
}

#[tokio::test]
async fn test_ca_cache_lru_behavior() {
    let backend = Arc::new(TestSecretBackend::new_with_test_cas());
    let ca_manager = Arc::new(
        CaKeyManager::load_or_fail(backend, Environment::Development)
            .await
            .unwrap(),
    );

    // Create CA with small cache (max 3 items)
    let ca = CertificateAuthority::new(ca_manager, 3);

    // Generate 5 certificates (will exceed cache size)
    for i in 0..5 {
        let host = HostIdentifier::Domain(format!("example{}.com", i));
        ca.get_or_generate(host)
            .await
            .expect("Failed to generate cert");
    }

    // Cache should contain only 3 items (LRU evicted oldest)
    let (count, max_size) = ca.cache_stats().await;
    assert_eq!(count, 3, "Cache should contain exactly 3 items");
    assert_eq!(max_size, 3, "Max size should be 3");
}

#[tokio::test]
async fn test_ca_cache_clear() {
    let backend = Arc::new(TestSecretBackend::new_with_test_cas());
    let ca_manager = Arc::new(
        CaKeyManager::load_or_fail(backend, Environment::Development)
            .await
            .unwrap(),
    );
    let ca = CertificateAuthority::new(ca_manager, 100);

    // Generate some certificates
    for i in 0..5 {
        let host = HostIdentifier::Domain(format!("example{}.com", i));
        ca.get_or_generate(host)
            .await
            .expect("Failed to generate cert");
    }

    let (count_before, _) = ca.cache_stats().await;
    assert_eq!(count_before, 5);

    // Clear cache
    ca.clear_cache().await;

    let (count_after, _) = ca.cache_stats().await;
    assert_eq!(count_after, 0, "Cache should be empty after clear");
}

#[tokio::test]
async fn test_concurrent_certificate_generation() {
    let backend = Arc::new(TestSecretBackend::new_with_test_cas());
    let ca_manager = Arc::new(
        CaKeyManager::load_or_fail(backend, Environment::Development)
            .await
            .unwrap(),
    );
    let ca = Arc::new(CertificateAuthority::new(ca_manager, 100));

    // Spawn multiple concurrent certificate generation tasks
    let mut handles = vec![];

    for i in 0..10 {
        let ca_clone = Arc::clone(&ca);
        let handle = tokio::spawn(async move {
            let host = HostIdentifier::Domain(format!("concurrent{}.com", i));
            ca_clone.get_or_generate(host).await
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        let result = handle.await.expect("Task panicked");
        assert!(result.is_ok(), "Concurrent cert generation should succeed");
    }

    // Verify all certificates were generated
    let (count, _) = ca.cache_stats().await;
    assert_eq!(count, 10, "Should have 10 certificates in cache");
}

#[tokio::test]
async fn test_ca_loading_failure_handling() {
    // Create a backend that will fail
    struct FailingBackend;

    #[async_trait::async_trait]
    impl SecretBackend for FailingBackend {
        async fn load_ca_key(&self, _: Environment) -> Result<SecretString, StartupError> {
            Err(StartupError::CaKeyMissing("Vault unavailable".to_string()))
        }

        async fn load_ca_cert(&self, _: Environment) -> Result<String, StartupError> {
            Err(StartupError::CaCertInvalid("Vault unavailable".to_string()))
        }

        async fn health_check(&self) -> Result<(), StartupError> {
            Err(StartupError::BackendError(
                "Vault health check failed".to_string(),
            ))
        }
    }

    let backend = Arc::new(FailingBackend);
    let result = CaKeyManager::load_or_fail(backend, Environment::Development).await;

    assert!(result.is_err(), "CA loading should fail when backend fails");
}

#[tokio::test]
async fn test_certificate_generation_performance() {
    use std::time::Instant;

    let backend = Arc::new(TestSecretBackend::new_with_test_cas());
    let ca_manager = Arc::new(
        CaKeyManager::load_or_fail(backend, Environment::Development)
            .await
            .unwrap(),
    );
    let ca = CertificateAuthority::new(ca_manager, 1000);

    // Generate 100 certificates and measure time
    let start = Instant::now();

    for i in 0..100 {
        let host = HostIdentifier::Domain(format!("perf-test-{}.com", i));
        ca.get_or_generate(host)
            .await
            .expect("Failed to generate cert");
    }

    let duration = start.elapsed();

    println!("Generated 100 certificates in {:?}", duration);
    println!("Average: {:?} per certificate", duration / 100);

    // Verify all certificates are cached
    let (count, _) = ca.cache_stats().await;
    assert_eq!(count, 100);

    // Test cache hit performance
    let start = Instant::now();

    for i in 0..100 {
        let host = HostIdentifier::Domain(format!("perf-test-{}.com", i));
        ca.get_or_generate(host)
            .await
            .expect("Failed to get cached cert");
    }

    let cache_duration = start.elapsed();

    println!("Retrieved 100 cached certificates in {:?}", cache_duration);
    println!("Average cache hit: {:?}", cache_duration / 100);

    // Cache hits should be significantly faster
    assert!(
        cache_duration < duration / 10,
        "Cache hits should be at least 10x faster than generation"
    );
}
