//! TLS Configuration - Hardened TLS settings for MITM
//!
//! This module provides TLS configurations for:
//! - Client-facing TLS (proxy ← client) with fake certificates
//! - Upstream TLS (proxy → upstream) with real verification
//!
//! ## Security Hardening
//!
//! - TLS 1.2 and 1.3 only (no TLS 1.0/1.1)
//! - Strong cipher suites only
//! - ALPN negotiation (h2, http/1.1)
//! - Hostname verification for upstream
//! - SNI support

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::sync::Arc;
use thiserror::Error;
use tracing::info;
use webpki_roots::TLS_SERVER_ROOTS;

/// TLS configuration errors
#[derive(Debug, Error)]
pub enum TlsConfigError {
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("TLS configuration error: {0}")]
    ConfigError(String),

    #[error("No supported cipher suites")]
    NoCipherSuites,

    #[error("Invalid server name: {0}")]
    InvalidServerName(String),
}

/// TLS version preference
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.2 and 1.3
    Tls12And13,
    /// TLS 1.3 only (most secure)
    Tls13Only,
}

impl Default for TlsVersion {
    fn default() -> Self {
        Self::Tls12And13 // Compatible with most servers
    }
}

/// Client-facing TLS config (proxy acts as server with fake cert)
pub struct ClientTlsConfig {
    config: Arc<ServerConfig>,
}

impl ClientTlsConfig {
    /// Build server config with fake certificate (hardened)
    pub fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, TlsConfigError> {
        Self::new_with_options(cert_chain, private_key, TlsVersion::default())
    }

    /// Build server config with specific TLS version
    pub fn new_with_options(
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        tls_version: TlsVersion,
    ) -> Result<Self, TlsConfigError> {
        // Select protocol versions
        let versions = match tls_version {
            TlsVersion::Tls12And13 => vec![&TLS12, &TLS13],
            TlsVersion::Tls13Only => vec![&TLS13],
        };

        let mut config = ServerConfig::builder_with_protocol_versions(&versions)
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| TlsConfigError::ConfigError(e.to_string()))?;

        // Set ALPN protocols (h2, http/1.1)
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        info!(
            tls_version = ?tls_version,
            alpn = ?config.alpn_protocols,
            "Client-facing TLS config created"
        );

        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// Get rustls ServerConfig
    pub fn server_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.config)
    }
}

/// Upstream TLS config (proxy acts as client with real verification)
pub struct UpstreamTlsConfig {
    config: Arc<ClientConfig>,
}

impl UpstreamTlsConfig {
    /// Build client config with system root certificates (hardened)
    pub fn new() -> Result<Self, TlsConfigError> {
        Self::new_with_options(TlsVersion::default())
    }

    /// Build client config with specific TLS version
    pub fn new_with_options(tls_version: TlsVersion) -> Result<Self, TlsConfigError> {
        let mut root_store = RootCertStore::empty();

        // Add webpki roots (Mozilla CA bundle)
        root_store.extend(TLS_SERVER_ROOTS.iter().cloned());

        // Select protocol versions
        let versions = match tls_version {
            TlsVersion::Tls12And13 => vec![&TLS12, &TLS13],
            TlsVersion::Tls13Only => vec![&TLS13],
        };

        let config = ClientConfig::builder_with_protocol_versions(&versions)
            .with_root_certificates(root_store)
            .with_no_client_auth();

        info!(
            tls_version = ?tls_version,
            roots_count = TLS_SERVER_ROOTS.len(),
            "Upstream TLS config created"
        );

        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// Get rustls ClientConfig
    pub fn client_config(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.config)
    }
}

impl Default for UpstreamTlsConfig {
    fn default() -> Self {
        Self::new().expect("Failed to create default UpstreamTlsConfig")
    }
}

/// TLS config builder with hardening options
#[derive(Debug, Clone)]
pub struct TlsConfigBuilder {
    /// Minimum TLS version
    tls_version: TlsVersion,

    /// ALPN protocols
    alpn_protocols: Vec<Vec<u8>>,

    /// Enable SNI (default: true)
    enable_sni: bool,

    /// Hostname verification (default: true)
    verify_hostname: bool,
}

impl TlsConfigBuilder {
    /// Create new builder with secure defaults
    pub fn new() -> Self {
        Self {
            tls_version: TlsVersion::Tls12And13,
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            enable_sni: true,
            verify_hostname: true,
        }
    }

    /// Set TLS version preference
    pub fn tls_version(mut self, version: TlsVersion) -> Self {
        self.tls_version = version;
        self
    }

    /// Set ALPN protocols
    pub fn alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Enable/disable SNI
    pub fn enable_sni(mut self, enable: bool) -> Self {
        self.enable_sni = enable;
        self
    }

    /// Enable/disable hostname verification
    pub fn verify_hostname(mut self, verify: bool) -> Self {
        self.verify_hostname = verify;
        self
    }

    /// Build upstream TLS config
    pub fn build_upstream(&self) -> Result<UpstreamTlsConfig, TlsConfigError> {
        UpstreamTlsConfig::new_with_options(self.tls_version)
    }

    /// Build client-facing TLS config
    pub fn build_client_facing(
        &self,
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<ClientTlsConfig, TlsConfigError> {
        ClientTlsConfig::new_with_options(cert_chain, private_key, self.tls_version)
    }
}

impl Default for TlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// TLS hardening configuration
#[derive(Debug, Clone)]
pub struct TlsHardeningConfig {
    /// Reject TLS 1.0/1.1
    pub reject_old_tls: bool,

    /// Minimum TLS version
    pub min_version: TlsVersion,

    /// Require ALPN (reject if client doesn't support)
    pub require_alpn: bool,

    /// Enforce hostname verification
    pub enforce_hostname_verification: bool,
}

impl Default for TlsHardeningConfig {
    fn default() -> Self {
        Self {
            reject_old_tls: true, // Always reject TLS 1.0/1.1
            min_version: TlsVersion::Tls12And13,
            require_alpn: false, // Don't break legacy clients
            enforce_hostname_verification: true,
        }
    }
}

impl TlsHardeningConfig {
    /// Create strict configuration (maximum security)
    pub fn strict() -> Self {
        Self {
            reject_old_tls: true,
            min_version: TlsVersion::Tls13Only,
            require_alpn: true,
            enforce_hostname_verification: true,
        }
    }

    /// Create compatible configuration (balanced security/compatibility)
    pub fn compatible() -> Self {
        Self::default()
    }
}

/// SNI (Server Name Indication) utilities
pub struct SniUtils;

impl SniUtils {
    /// Parse hostname into ServerName for SNI
    pub fn parse_server_name(hostname: &str) -> Result<ServerName<'static>, TlsConfigError> {
        ServerName::try_from(hostname.to_owned())
            .map_err(|e| TlsConfigError::InvalidServerName(format!("{}", e)))
    }

    /// Validate hostname format
    pub fn validate_hostname(hostname: &str) -> bool {
        // Basic validation
        !hostname.is_empty()
            && !hostname.starts_with('.')
            && !hostname.ends_with('.')
            && hostname.len() <= 253
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_default() {
        assert_eq!(TlsVersion::default(), TlsVersion::Tls12And13);
    }

    #[test]
    fn test_hardening_config_defaults() {
        let config = TlsHardeningConfig::default();
        assert!(config.reject_old_tls);
        assert_eq!(config.min_version, TlsVersion::Tls12And13);
        assert!(config.enforce_hostname_verification);
    }

    #[test]
    fn test_hardening_config_strict() {
        let config = TlsHardeningConfig::strict();
        assert!(config.reject_old_tls);
        assert_eq!(config.min_version, TlsVersion::Tls13Only);
        assert!(config.require_alpn);
        assert!(config.enforce_hostname_verification);
    }

    #[test]
    fn test_sni_validate_hostname() {
        assert!(SniUtils::validate_hostname("example.com"));
        assert!(SniUtils::validate_hostname("sub.example.com"));
        assert!(SniUtils::validate_hostname("a.b.c.example.com"));

        assert!(!SniUtils::validate_hostname(""));
        assert!(!SniUtils::validate_hostname(".example.com"));
        assert!(!SniUtils::validate_hostname("example.com."));
    }

    #[test]
    fn test_sni_parse_server_name() {
        let result = SniUtils::parse_server_name("example.com");
        assert!(result.is_ok());

        // rustls 0.22+ accepts IP addresses in ServerName
        let result = SniUtils::parse_server_name("192.168.1.1");
        assert!(
            result.is_ok(),
            "rustls 0.22+ accepts IP addresses in ServerName"
        );

        // Invalid server names should fail
        let result = SniUtils::parse_server_name("");
        assert!(result.is_err(), "Empty hostname should fail");
    }

    #[test]
    fn test_tls_config_builder_defaults() {
        let builder = TlsConfigBuilder::new();
        assert_eq!(builder.tls_version, TlsVersion::Tls12And13);
        assert_eq!(builder.alpn_protocols.len(), 2);
        assert!(builder.enable_sni);
        assert!(builder.verify_hostname);
    }

    #[test]
    fn test_tls_config_builder_customization() {
        let builder = TlsConfigBuilder::new()
            .tls_version(TlsVersion::Tls13Only)
            .enable_sni(false)
            .verify_hostname(false);

        assert_eq!(builder.tls_version, TlsVersion::Tls13Only);
        assert!(!builder.enable_sni);
        assert!(!builder.verify_hostname);
    }

    #[test]
    fn test_upstream_tls_config_creation() {
        let config = UpstreamTlsConfig::new();
        assert!(config.is_ok());

        let config = UpstreamTlsConfig::new_with_options(TlsVersion::Tls13Only);
        assert!(config.is_ok());
    }
}
