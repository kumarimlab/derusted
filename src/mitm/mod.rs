//! MITM (Man-in-the-Middle) interception module
//!
//! This module provides TLS MITM capabilities for enterprise proxy use cases.
//! It includes:
//! - Certificate Authority (CA) management with Vault/KMS backend
//! - Dynamic certificate generation for intercepted domains
//! - TLS handshake handling (client and upstream)
//! - Smart bypass system for pinned/sensitive domains
//! - PII-safe logging with configurable policies

pub mod bypass;
pub mod bypass_config;
pub mod ca_key_manager;
pub mod certificate_authority;
pub mod hsts;
pub mod http2_mitm;
pub mod http2_parser;
pub mod http_parser;
pub mod interceptor;
pub mod log_storage;
pub mod logging;
pub mod pinning;
pub mod tls_config;

// Re-export main types
pub use bypass::{
    AlertConfig, BypassConfig, BypassManager, BypassReason, BypassRule, BypassStats,
    ConfigError as BypassConfigError, DynamicBypassConfig, ExampleBypassRules, StaticBypassRule,
};
pub use ca_key_manager::{CaKeyManager, Environment, SecretBackend, StartupError, VaultBackend};
pub use certificate_authority::{CertificateAuthority, HostIdentifier, MitmError};
pub use hsts::{HstsManager, HstsPolicy};
pub use http2_mitm::{handle_http2_mitm, H2Error, Http2Config};
pub use http2_parser::{
    extract_http2_request, extract_http2_response, has_end_headers, has_end_stream,
    is_client_stream, is_response_frame, parse_frame_header, parse_http2_frame, FrameType,
    Http2Frame, Http2Request, Http2Response, ParseError as Http2ParseError,
};
pub use http_parser::{
    parse_http1_request, parse_http1_response, HttpRequest, HttpResponse,
    ParseError as HttpParseError,
};
pub use interceptor::{InterceptionError, InterceptionResult, MitmInterceptor};
pub use log_storage::{LogStorage, StorageError};
pub use logging::{LoggingPolicy, PiiRedactor, RequestMetadata};
pub use pinning::{
    PinningDetection, PinningDetector, PinningPatterns, PinningPolicy, PinningStats,
};
pub use tls_config::{
    ClientTlsConfig, SniUtils, TlsConfigBuilder, TlsConfigError, TlsHardeningConfig, TlsVersion,
    UpstreamTlsConfig,
};
