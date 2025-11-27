//! Certificate Authority (CA) Management
//!
//! Phase 1, Week 1: CA Certificate Management
//!
//! This module handles:
//! - CA certificate generation
//! - CA private key storage and encryption
//! - Certificate persistence (filesystem or embedded)
//! - CA hot-reload support
//! - Dynamic certificate generation for intercepted domains

use super::error::{MitmError, Result};
use super::cert_cache::CertCache;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

/// Certificate Authority for MITM interception
///
/// Generates and manages SSL/TLS certificates for intercepting HTTPS traffic.
pub struct CertificateAuthority {
    /// CA certificate (root certificate installed in clients)
    ca_cert: Certificate,

    /// CA private key (used to sign generated certificates)
    ca_key: KeyPair,

    /// Certificate cache (LRU cache of generated certificates)
    cert_cache: Arc<RwLock<CertCache>>,

    /// Configuration
    config: CaConfig,
}

/// CA configuration
#[derive(Debug, Clone)]
pub struct CaConfig {
    /// Path to CA certificate file
    pub cert_path: String,

    /// Path to CA private key file
    pub key_path: String,

    /// Certificate cache size
    pub cache_size: usize,

    /// Certificate validity duration in days
    pub validity_days: u32,

    /// Organization name for generated certificates
    pub organization: String,

    /// Country code for generated certificates
    pub country: String,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            cert_path: "ca.crt".to_string(),
            key_path: "ca.key".to_string(),
            cache_size: 10_000,
            validity_days: 365,
            organization: "Pinaka Derusted Proxy".to_string(),
            country: "US".to_string(),
        }
    }
}

impl CertificateAuthority {
    /// Create a new Certificate Authority
    ///
    /// If CA files exist on disk, loads them. Otherwise, generates a new CA.
    pub async fn new(config: CaConfig) -> Result<Self> {
        info!("Initializing Certificate Authority");

        // Try to load existing CA from disk
        let (ca_cert, ca_key) = if Path::new(&config.cert_path).exists()
            && Path::new(&config.key_path).exists()
        {
            info!("Loading existing CA from disk");
            Self::load_ca(&config).await?
        } else {
            info!("Generating new CA certificate");
            let (cert, key) = Self::generate_ca(&config).await?;

            // Save to disk
            Self::save_ca(&config, &cert, &key).await?;

            (cert, key)
        };

        // Create certificate cache
        let cert_cache = Arc::new(RwLock::new(CertCache::new(config.cache_size)));

        info!("Certificate Authority initialized successfully");
        info!("Cache size: {} certificates", config.cache_size);
        info!("Certificate validity: {} days", config.validity_days);

        Ok(Self {
            ca_cert,
            ca_key,
            cert_cache,
            config,
        })
    }

    /// Generate a new CA certificate
    async fn generate_ca(config: &CaConfig) -> Result<(Certificate, KeyPair)> {
        info!("Generating CA certificate and private key");

        // Create CA certificate parameters
        let mut params = CertificateParams::default();

        // Set CA-specific extensions
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        // Set distinguished name
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::OrganizationName, &config.organization);
        distinguished_name.push(DnType::CommonName, "Pinaka Derusted Proxy CA");
        distinguished_name.push(DnType::CountryName, &config.country);
        params.distinguished_name = distinguished_name;

        // Set validity period (not_before and not_after)
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 1, 1); // 10 years

        // Set key usage
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];

        // Generate key pair
        let key_pair = KeyPair::generate()
            .map_err(|e| MitmError::ca_generation(format!("Failed to generate key pair: {}", e)))?;

        // Generate certificate
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| MitmError::ca_generation(format!("Failed to self-sign certificate: {}", e)))?;

        info!("CA certificate generated successfully");

        Ok((cert, key_pair))
    }

    /// Load CA certificate and private key from disk
    async fn load_ca(config: &CaConfig) -> Result<(Certificate, KeyPair)> {
        info!("Loading CA certificate from: {}", config.cert_path);
        info!("Loading CA private key from: {}", config.key_path);

        // Read certificate PEM
        let cert_pem = fs::read_to_string(&config.cert_path)
            .map_err(|e| MitmError::ca_load(format!("Failed to read cert file: {}", e)))?;

        // Read private key PEM
        let key_pem = fs::read_to_string(&config.key_path)
            .map_err(|e| MitmError::ca_load(format!("Failed to read key file: {}", e)))?;

        // Parse private key (rcgen 0.12 from_ca_cert_pem takes ownership, so parse twice)
        let key_pair_for_cert = KeyPair::from_pem(&key_pem)
            .map_err(|e| MitmError::ca_load(format!("Failed to parse private key: {}", e)))?;

        let key_pair = KeyPair::from_pem(&key_pem)
            .map_err(|e| MitmError::ca_load(format!("Failed to parse private key: {}", e)))?;

        // Parse certificate with key pair (rcgen 0.12 API)
        let params = CertificateParams::from_ca_cert_pem(&cert_pem, key_pair_for_cert)
            .map_err(|e| MitmError::ca_load(format!("Failed to parse certificate: {}", e)))?;

        let cert = Certificate::from_params(params)
            .map_err(|e| MitmError::ca_load(format!("Failed to reconstruct certificate: {}", e)))?;

        info!("CA certificate and key loaded successfully");

        Ok((cert, key_pair))
    }

    /// Save CA certificate and private key to disk
    async fn save_ca(config: &CaConfig, cert: &Certificate, key: &KeyPair) -> Result<()> {
        info!("Saving CA certificate to: {}", config.cert_path);
        info!("Saving CA private key to: {}", config.key_path);

        // Save certificate
        fs::write(&config.cert_path, cert.pem())
            .map_err(|e| MitmError::ca_generation(format!("Failed to save certificate: {}", e)))?;

        // Save private key
        fs::write(&config.key_path, key.serialize_pem())
            .map_err(|e| MitmError::ca_generation(format!("Failed to save private key: {}", e)))?;

        info!("CA certificate and key saved successfully");

        Ok(())
    }

    /// Generate a certificate for a specific domain
    ///
    /// Checks cache first. If not found, generates a new certificate signed by the CA.
    pub async fn generate_cert_for_domain(&self, domain: &str) -> Result<Certificate> {
        // Check cache first
        {
            let cache = self.cert_cache.read().await;
            if let Some(cert) = cache.get(domain) {
                info!("📦 Certificate cache hit for: {}", domain);
                return Ok(cert.clone());
            }
        }

        info!("🔧 Generating certificate for: {}", domain);

        // Create certificate parameters
        let mut params = CertificateParams::default();

        // Set subject alternative name (SAN)
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName(domain.to_string()),
            // Also support wildcard
            rcgen::SanType::DnsName(format!("*.{}", domain)),
        ];

        // Set distinguished name
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::OrganizationName, &self.config.organization);
        distinguished_name.push(DnType::CommonName, domain);
        distinguished_name.push(DnType::CountryName, &self.config.country);
        params.distinguished_name = distinguished_name;

        // Set validity period
        let now = chrono::Utc::now();
        let not_before = now - chrono::Duration::days(1); // 1 day in the past (clock skew)
        let not_after = now + chrono::Duration::days(self.config.validity_days as i64);

        params.not_before = rcgen::date_time_ymd(
            not_before.year(),
            not_before.month() as u8,
            not_before.day() as u8,
        );
        params.not_after = rcgen::date_time_ymd(
            not_after.year(),
            not_after.month() as u8,
            not_after.day() as u8,
        );

        // Set key usage
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];

        // Generate certificate signed by CA
        let cert = params
            .signed_by(&self.ca_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| {
                MitmError::cert_generation(
                    domain,
                    format!("Failed to sign certificate: {}", e),
                )
            })?;

        // Add to cache
        {
            let mut cache = self.cert_cache.write().await;
            cache.insert(domain.to_string(), cert.clone());
        }

        info!("✅ Certificate generated and cached for: {}", domain);

        Ok(cert)
    }

    /// Get or generate a certificate for a domain
    ///
    /// Convenience method that checks cache and generates if needed.
    pub async fn get_or_generate(&self, domain: &str) -> Result<Certificate> {
        self.generate_cert_for_domain(domain).await
    }

    /// Get the CA certificate PEM (for client installation)
    pub fn get_ca_cert_pem(&self) -> String {
        self.ca_cert.pem()
    }

    /// Get the CA private key PEM (for backup/restore)
    pub fn get_ca_key_pem(&self) -> String {
        self.ca_key.serialize_pem()
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> CacheStats {
        let cache = self.cert_cache.read().await;
        CacheStats {
            size: cache.len(),
            capacity: cache.capacity(),
            hit_rate: cache.hit_rate(),
        }
    }

    /// Reload CA certificate from disk (hot-reload)
    pub async fn reload(&mut self) -> Result<()> {
        info!("Hot-reloading CA certificate");

        let (ca_cert, ca_key) = Self::load_ca(&self.config).await?;

        self.ca_cert = ca_cert;
        self.ca_key = ca_key;

        // Clear certificate cache (all certs need to be regenerated with new CA)
        {
            let mut cache = self.cert_cache.write().await;
            cache.clear();
        }

        info!("CA certificate reloaded successfully");

        Ok(())
    }
}

/// Certificate cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub size: usize,
    pub capacity: usize,
    pub hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ca_generation() {
        let config = CaConfig {
            cert_path: "/tmp/test_ca.crt".to_string(),
            key_path: "/tmp/test_ca.key".to_string(),
            ..Default::default()
        };

        let ca = CertificateAuthority::new(config).await.unwrap();

        // CA certificate should be valid
        assert!(!ca.get_ca_cert_pem().is_empty());
        assert!(!ca.get_ca_key_pem().is_empty());
    }

    #[tokio::test]
    async fn test_domain_cert_generation() {
        let config = CaConfig {
            cert_path: "/tmp/test_ca2.crt".to_string(),
            key_path: "/tmp/test_ca2.key".to_string(),
            cache_size: 100,
            ..Default::default()
        };

        let ca = CertificateAuthority::new(config).await.unwrap();

        // Generate certificate for domain
        let cert = ca.generate_cert_for_domain("example.com").await.unwrap();
        assert!(!cert.pem().is_empty());

        // Second call should hit cache
        let cert2 = ca.generate_cert_for_domain("example.com").await.unwrap();
        assert_eq!(cert.pem(), cert2.pem());

        // Check cache stats
        let stats = ca.get_cache_stats().await;
        assert_eq!(stats.size, 1);
    }

    #[tokio::test]
    async fn test_ca_reload() {
        let config = CaConfig {
            cert_path: "/tmp/test_ca3.crt".to_string(),
            key_path: "/tmp/test_ca3.key".to_string(),
            ..Default::default()
        };

        let mut ca = CertificateAuthority::new(config).await.unwrap();

        // Get original CA PEM
        let original_pem = ca.get_ca_cert_pem();

        // Reload (should load from disk)
        ca.reload().await.unwrap();

        // PEM should be the same (loaded from same file)
        assert_eq!(original_pem, ca.get_ca_cert_pem());
    }
}
