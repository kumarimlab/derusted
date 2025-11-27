//! Derusted - Production-Ready Rust Forward Proxy
//!
//! Derusted is a high-performance forward proxy with MITM (Man-In-The-Middle) capabilities,
//! built in Rust for safety, speed, and reliability.
//!
//! ## Features
//!
//! - **HTTP/1.1 & HTTP/2**: Full support for both protocols with ALPN negotiation
//! - **MITM/SSL Interception**: Dynamic certificate generation for HTTPS content inspection
//! - **JWT Authentication**: HS256/384/512 token-based authentication
//! - **Rate Limiting**: Token bucket algorithm with configurable limits
//! - **Smart Bypass**: Intelligent bypass for certificate-pinned domains
//! - **SSRF Protection**: DNS-based SSRF prevention
//! - **Metrics**: Prometheus-compatible metrics
//!
//! ## Usage
//!
//! ```rust,no_run
//! use derusted::{CertificateAuthority, MitmConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create MITM Certificate Authority
//!     let mitm_config = MitmConfig::default();
//!     let ca = CertificateAuthority::new(mitm_config.into()).await?;
//!
//!     // Generate certificate for domain
//!     let cert = ca.get_or_generate("example.com").await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! Derusted is designed as a library that can be embedded in larger applications:
//!
//! - `mitm` - MITM/SSL interception core
//! - `auth` - JWT authentication
//! - `rate_limiter` - Rate limiting
//! - `destination_filter` - URL/domain filtering
//! - `http_client` - Upstream HTTP client
//! - `server` - Core proxy server logic
//!
//! ## Open Source
//!
//! Derusted is open source under Apache-2.0 license and welcomes contributions.
//! Visit: https://github.com/your-org/derusted

// Core proxy modules
pub mod config;
pub mod http_client;
pub mod logger;
pub mod server;

// Security & filtering
pub mod auth;
pub mod body_limiter;
pub mod destination_filter;
pub mod ip_tracker;
pub mod rate_limiter;

// MITM (Phase 1: Weeks 1-4)
pub mod mitm;

// Mixed content policy (v0.2.0)
pub mod mixed_content;

// Metrics
pub mod http_metrics;

// TLS utilities
pub mod reload;
pub mod tls;

// Connection pooling for performance
pub mod connection_pool;

// Re-export commonly used types

/// Configuration types
pub use config::Config;

/// Authentication
pub use auth::{JwtClaims, JwtValidator};

/// Rate limiting
pub use rate_limiter::{RateLimiter, RateLimiterConfig};

/// Destination filtering
pub use destination_filter::{DestinationError, DestinationFilter};

/// IP tracking and SSRF protection
pub use ip_tracker::{IpTracker, IpTrackerError};

/// Body size limiting
pub use body_limiter::{read_body_with_limit, BodyLimitError};

/// MITM types and functionality
pub use mitm::{
    AlertConfig,
    BypassConfig,
    BypassConfigError,
    // Bypass system
    BypassManager,
    BypassReason,
    BypassRule,
    BypassStats,
    // CA management
    CaKeyManager,
    // Certificate generation
    CertificateAuthority,
    ClientTlsConfig,
    DynamicBypassConfig,
    Environment,
    ExampleBypassRules,
    HostIdentifier,
    InterceptionError,

    InterceptionResult,
    // Logging
    LoggingPolicy,
    MitmError,

    // Interception
    MitmInterceptor,
    PiiRedactor,

    RequestMetadata,
    SecretBackend,
    StartupError,

    StaticBypassRule,
    // TLS configuration
    TlsConfigBuilder,
    UpstreamTlsConfig,

    VaultBackend,
};

/// HTTP metrics
pub use http_metrics::HttpMetrics;

/// Mixed content policy (v0.2.0)
pub use mixed_content::{
    build_block_response, build_upgrade_failure_response, detect_mixed_content, parse_https_origin,
    UpgradeError,
};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
        assert_eq!(NAME, "derusted");
    }
}
