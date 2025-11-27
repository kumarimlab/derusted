//! MITM error types

use thiserror::Error;

/// Result type for MITM operations
pub type Result<T> = std::result::Result<T, MitmError>;

/// MITM-specific errors
#[derive(Error, Debug)]
pub enum MitmError {
    /// CA certificate generation failed
    #[error("Failed to generate CA certificate: {0}")]
    CaGenerationFailed(String),

    /// CA certificate loading failed
    #[error("Failed to load CA certificate: {0}")]
    CaLoadFailed(String),

    /// Certificate generation failed
    #[error("Failed to generate certificate for domain {domain}: {source}")]
    CertGenerationFailed {
        domain: String,
        source: String,
    },

    /// Certificate parsing failed
    #[error("Failed to parse certificate: {0}")]
    CertParseFailed(String),

    /// TLS handshake failed
    #[error("TLS handshake failed for {host}: {source}")]
    TlsHandshakeFailed {
        host: String,
        source: String,
    },

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Certificate cache error
    #[error("Certificate cache error: {0}")]
    CacheError(String),

    /// Invalid domain name
    #[error("Invalid domain name: {0}")]
    InvalidDomain(String),

    /// Unsupported operation
    #[error("Unsupported operation: {0}")]
    Unsupported(String),

    /// Invalid CONNECT request
    #[error("Invalid CONNECT request: {0}")]
    InvalidConnectRequest(String),

    /// TLS configuration failed
    #[error("TLS configuration failed: {0}")]
    TlsConfigFailed(String),

    /// Invalid host
    #[error("Invalid host: {0}")]
    InvalidHost(String),

    /// Upstream connection failed
    #[error("Upstream connection failed for {host}: {source}")]
    UpstreamConnectionFailed {
        host: String,
        source: String,
    },

    /// Tunnel error
    #[error("Tunnel error: {0}")]
    TunnelError(String),

    /// Request parsing failed
    #[error("Request parsing failed: {0}")]
    RequestParseFailed(String),

    /// Response parsing failed
    #[error("Response parsing failed: {0}")]
    ResponseParseFailed(String),
}

impl MitmError {
    /// Create a CA generation error
    pub fn ca_generation(msg: impl Into<String>) -> Self {
        Self::CaGenerationFailed(msg.into())
    }

    /// Create a CA load error
    pub fn ca_load(msg: impl Into<String>) -> Self {
        Self::CaLoadFailed(msg.into())
    }

    /// Create a certificate generation error
    pub fn cert_generation(domain: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::CertGenerationFailed {
            domain: domain.into(),
            source: msg.into(),
        }
    }

    /// Create a TLS handshake error
    pub fn tls_handshake(host: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::TlsHandshakeFailed {
            host: host.into(),
            source: msg.into(),
        }
    }

    /// Create a cache error
    pub fn cache(msg: impl Into<String>) -> Self {
        Self::CacheError(msg.into())
    }
}
