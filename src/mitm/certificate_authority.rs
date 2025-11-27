//! Certificate Authority - Dynamic certificate generation for MITM
//!
//! This module handles generating fake certificates for intercepted domains.
//! It supports DNS SANs, IP SANs, wildcards, and localhost bypass.

use crate::mitm::ca_key_manager::CaKeyManager;
use anyhow::Result;
use base64::Engine;
use lru::LruCache;
use rcgen::{Certificate, CertificateParams, DnType, KeyPair, SanType};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Host identifier for certificate generation
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum HostIdentifier {
    /// Regular domain (e.g., example.com)
    Domain(String),

    /// Wildcard domain (e.g., *.example.com)
    Wildcard(String),

    /// IP address (e.g., 192.168.1.1)
    IpAddress(IpAddr),

    /// Localhost (127.0.0.1, ::1, localhost)
    Localhost,
}

impl HostIdentifier {
    /// Parse from hostname string
    pub fn from_hostname(hostname: &str) -> Self {
        // Check for localhost
        if hostname == "localhost"
            || hostname == "127.0.0.1"
            || hostname == "::1"
            || hostname.starts_with("127.")
        {
            return Self::Localhost;
        }

        // Check for IP address
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            if ip.is_loopback() {
                return Self::Localhost;
            }
            return Self::IpAddress(ip);
        }

        // Check for wildcard
        if hostname.starts_with("*.") {
            return Self::Wildcard(hostname.to_string());
        }

        // Regular domain
        Self::Domain(hostname.to_string())
    }
}

/// Cached certificate with TTL
#[derive(Clone)]
struct CachedCertificate {
    /// The certificate
    cert: Arc<Certificate>,

    /// When this certificate was created/cached
    created_at: Instant,
}

impl CachedCertificate {
    fn new(cert: Arc<Certificate>) -> Self {
        Self {
            cert,
            created_at: Instant::now(),
        }
    }

    /// Check if certificate has expired (TTL exceeded)
    fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }
}

/// MITM-specific errors
#[derive(Debug, Error)]
pub enum MitmError {
    #[error("Localhost bypass - MITM not allowed for localhost")]
    LocalhostBypass,

    #[error("Certificate generation failed: {0}")]
    CertGenerationFailed(String),

    #[error("Invalid hostname: {0}")]
    InvalidHostname(String),

    #[error("Cache error: {0}")]
    CacheError(String),
}

/// Certificate Authority - generates and caches certificates
pub struct CertificateAuthority {
    /// CA key manager
    ca_manager: Arc<CaKeyManager>,

    /// LRU cache for generated certificates (domain -> cert)
    cache: Arc<Mutex<LruCache<HostIdentifier, CachedCertificate>>>,

    /// Maximum cache size
    max_cache_size: usize,

    /// Certificate TTL (Time-To-Live)
    cert_ttl: Duration,
}

impl CertificateAuthority {
    /// Create new Certificate Authority with default TTL (24 hours)
    pub fn new(ca_manager: Arc<CaKeyManager>, max_cache_size: usize) -> Self {
        Self::with_ttl(ca_manager, max_cache_size, Duration::from_secs(86400))
    }

    /// Create new Certificate Authority with custom TTL
    pub fn with_ttl(
        ca_manager: Arc<CaKeyManager>,
        max_cache_size: usize,
        cert_ttl: Duration,
    ) -> Self {
        let cache_size =
            NonZeroUsize::new(max_cache_size).unwrap_or(NonZeroUsize::new(1000).unwrap());

        Self {
            ca_manager,
            cache: Arc::new(Mutex::new(LruCache::new(cache_size))),
            max_cache_size,
            cert_ttl,
        }
    }

    /// Get or generate certificate for host
    pub async fn get_or_generate(
        &self,
        host: HostIdentifier,
    ) -> Result<Arc<Certificate>, MitmError> {
        // Localhost bypass - MUST NOT MITM localhost
        if matches!(host, HostIdentifier::Localhost) {
            warn!("Attempted MITM on localhost - bypassing");
            return Err(MitmError::LocalhostBypass);
        }

        // Check cache first and validate TTL
        {
            let mut cache = self.cache.lock().await;
            if let Some(cached) = cache.get(&host) {
                // Check if certificate has expired
                if cached.is_expired(self.cert_ttl) {
                    debug!(host = ?host, "Certificate cache hit but expired, regenerating");
                    // Remove expired certificate from cache
                    cache.pop(&host);
                } else {
                    debug!(host = ?host, "Certificate cache hit (valid)");
                    return Ok(Arc::clone(&cached.cert));
                }
            }
        }

        // Generate new certificate
        debug!(host = ?host, "Generating new certificate");
        let cert = self.generate_certificate(&host).await?;
        let cert_arc = Arc::new(cert);

        // Store in cache with timestamp
        {
            let mut cache = self.cache.lock().await;
            cache.put(host.clone(), CachedCertificate::new(Arc::clone(&cert_arc)));
        }

        Ok(cert_arc)
    }

    /// Generate certificate for host
    async fn generate_certificate(&self, host: &HostIdentifier) -> Result<Certificate, MitmError> {
        let mut params = CertificateParams::default();

        // Set common name and SAN based on host type
        match host {
            HostIdentifier::Domain(domain) => {
                params
                    .distinguished_name
                    .push(DnType::CommonName, domain.clone());
                params.subject_alt_names = vec![SanType::DnsName(domain.clone())];
            }
            HostIdentifier::Wildcard(wildcard) => {
                params
                    .distinguished_name
                    .push(DnType::CommonName, wildcard.clone());
                params.subject_alt_names = vec![SanType::DnsName(wildcard.clone())];
            }
            HostIdentifier::IpAddress(ip) => {
                params
                    .distinguished_name
                    .push(DnType::CommonName, ip.to_string());
                params.subject_alt_names = vec![SanType::IpAddress(*ip)];
            }
            HostIdentifier::Localhost => {
                return Err(MitmError::LocalhostBypass);
            }
        }

        // Set validity period (90 days) - using time crate for rcgen compatibility
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(90);

        // Generate unique serial number (crypto RNG + timestamp)
        let serial_number = self.generate_serial_number();
        params.serial_number = Some(serial_number.into());

        // Generate key pair for the leaf certificate
        let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| MitmError::CertGenerationFailed(e.to_string()))?;

        // Create the certificate from params and key
        let temp_cert = Certificate::from_params(params)
            .map_err(|e| MitmError::CertGenerationFailed(e.to_string()))?;

        // Sign with CA (rcgen 0.12 API)
        let ca_cert = self.ca_manager.certificate();

        // Serialize with CA's signature (ca_cert is Arc<Certificate>, so just dereference once)
        let cert_der = temp_cert
            .serialize_der_with_signer(&*ca_cert)
            .map_err(|e| MitmError::CertGenerationFailed(e.to_string()))?;

        // Convert DER to PEM and reconstruct with the key pair
        let cert_pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            base64::engine::general_purpose::STANDARD.encode(&cert_der)
        );

        // Reconstruct Certificate from PEM and KeyPair
        let cert = Certificate::from_params(
            CertificateParams::from_ca_cert_pem(&cert_pem, key_pair)
                .map_err(|e| MitmError::CertGenerationFailed(e.to_string()))?,
        )
        .map_err(|e| MitmError::CertGenerationFailed(e.to_string()))?;

        Ok(cert)
    }

    /// Generate unique serial number using crypto RNG + timestamp
    fn generate_serial_number(&self) -> u64 {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let random_part: u32 = rng.gen();
        let timestamp_part = chrono::Utc::now().timestamp() as u32;

        // Combine for unique 64-bit serial
        ((timestamp_part as u64) << 32) | (random_part as u64)
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.lock().await;
        (cache.len(), self.max_cache_size)
    }

    /// Clear cache (for testing or rotation)
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.lock().await;
        cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_identifier_parsing() {
        // Localhost variants
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

        // IP address
        assert!(matches!(
            HostIdentifier::from_hostname("192.168.1.1"),
            HostIdentifier::IpAddress(_)
        ));

        // Wildcard
        assert!(matches!(
            HostIdentifier::from_hostname("*.example.com"),
            HostIdentifier::Wildcard(_)
        ));

        // Regular domain
        assert!(matches!(
            HostIdentifier::from_hostname("example.com"),
            HostIdentifier::Domain(_)
        ));
    }

    // TODO: Add tests for:
    // - Certificate generation with DNS SAN
    // - Certificate generation with IP SAN
    // - Wildcard certificate generation
    // - Localhost bypass enforcement
    // - Serial number uniqueness
    // - Cache hit/miss behavior
}
