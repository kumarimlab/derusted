//! Custom Config Extension Example
//!
//! This example demonstrates how to extend derusted's `Config` struct with
//! application-specific fields using the Deref pattern.
//!
//! # The Problem
//!
//! When integrating derusted into a larger application, you often need to add
//! custom configuration fields (custom validators, loggers, feature flags, etc.).
//! Wrapping `Config` in a nested struct leads to awkward access patterns:
//!
//! ```ignore
//! // Awkward: need to access through `.base`
//! config.base.destination_filter.check_and_resolve(host)
//! ```
//!
//! # The Solution: Deref Pattern
//!
//! By implementing `Deref` for your custom config, you get transparent access
//! to all derusted fields while adding your own:
//!
//! ```ignore
//! // Clean: direct access to derusted fields
//! config.destination_filter.check_and_resolve(host)
//! // Plus your custom fields
//! config.custom_logger.log(...)
//! ```
//!
//! # Running this example
//!
//! ```bash
//! cargo run --example custom_config
//! ```

use std::ops::Deref;
use std::sync::Arc;

// Note: In a real application, you would import derusted::Config
// For this example, we'll create a simplified mock

/// Simplified mock of derusted::Config for demonstration
/// (In real code, use `derusted::Config`)
#[derive(Debug)]
pub struct DerustedConfig {
    pub host: String,
    pub port: u16,
    pub rate_limit_requests_per_minute: usize,
    pub max_request_body_size: usize,
}

impl DerustedConfig {
    pub fn new() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 443,
            rate_limit_requests_per_minute: 10000,
            max_request_body_size: 100 * 1024 * 1024, // 100MB
        }
    }
}

// ============================================================================
// Your Application-Specific Extensions
// ============================================================================

/// Custom analytics logger
#[derive(Debug, Clone)]
pub struct AnalyticsLogger {
    endpoint: String,
    batch_size: usize,
}

impl AnalyticsLogger {
    pub fn new(endpoint: &str, batch_size: usize) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            batch_size,
        }
    }

    pub fn log_request(&self, path: &str, latency_ms: u64) {
        println!(
            "[Analytics] {} - {}ms (batch: {}, endpoint: {})",
            path, latency_ms, self.batch_size, self.endpoint
        );
    }
}

/// Custom feature flags
#[derive(Debug, Clone)]
pub struct FeatureFlags {
    pub enable_caching: bool,
    pub enable_compression: bool,
    pub enable_beta_features: bool,
    pub max_cache_size_mb: usize,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            enable_caching: true,
            enable_compression: true,
            enable_beta_features: false,
            max_cache_size_mb: 512,
        }
    }
}

/// Custom request validator
pub trait RequestValidator: Send + Sync + std::fmt::Debug {
    fn validate_path(&self, path: &str) -> bool;
    fn validate_headers(&self, headers: &[(&str, &str)]) -> bool;
}

/// Simple path-based validator
#[derive(Debug)]
pub struct PathValidator {
    blocked_paths: Vec<String>,
}

impl PathValidator {
    pub fn new(blocked_paths: Vec<String>) -> Self {
        Self { blocked_paths }
    }
}

impl RequestValidator for PathValidator {
    fn validate_path(&self, path: &str) -> bool {
        !self.blocked_paths.iter().any(|blocked| path.starts_with(blocked))
    }

    fn validate_headers(&self, _headers: &[(&str, &str)]) -> bool {
        true // Accept all headers
    }
}

// ============================================================================
// Extended Config with Deref Pattern
// ============================================================================

/// Extended configuration that wraps derusted::Config
///
/// Uses the Deref pattern for transparent access to base config fields
/// while adding application-specific extensions.
#[derive(Debug)]
pub struct MyAppConfig {
    /// Base derusted configuration
    base: DerustedConfig,

    /// Custom analytics logger
    pub analytics: Arc<AnalyticsLogger>,

    /// Feature flags for this deployment
    pub features: FeatureFlags,

    /// Custom request validator
    pub validator: Arc<dyn RequestValidator>,

    /// Application-specific settings
    pub app_name: String,
    pub app_version: String,
    pub environment: String,
}

/// Implement Deref to allow transparent access to base config
impl Deref for MyAppConfig {
    type Target = DerustedConfig;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl MyAppConfig {
    /// Create a new extended config
    pub fn new(
        base: DerustedConfig,
        app_name: &str,
        environment: &str,
    ) -> Self {
        Self {
            base,
            analytics: Arc::new(AnalyticsLogger::new(
                "https://analytics.example.com/v1/events",
                100,
            )),
            features: FeatureFlags::default(),
            validator: Arc::new(PathValidator::new(vec![
                "/admin".to_string(),
                "/internal".to_string(),
            ])),
            app_name: app_name.to_string(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: environment.to_string(),
        }
    }

    /// Builder method to customize analytics
    pub fn with_analytics(mut self, endpoint: &str, batch_size: usize) -> Self {
        self.analytics = Arc::new(AnalyticsLogger::new(endpoint, batch_size));
        self
    }

    /// Builder method to customize features
    pub fn with_features(mut self, features: FeatureFlags) -> Self {
        self.features = features;
        self
    }

    /// Builder method to customize validator
    pub fn with_validator(mut self, validator: Arc<dyn RequestValidator>) -> Self {
        self.validator = validator;
        self
    }
}

// ============================================================================
// Example Usage
// ============================================================================

fn main() {
    println!("=== Custom Config Extension Demo ===\n");

    // Create base derusted config
    let base_config = DerustedConfig::new();

    // Create extended config with app-specific settings
    let config = MyAppConfig::new(base_config, "my-proxy-app", "production")
        .with_features(FeatureFlags {
            enable_caching: true,
            enable_compression: true,
            enable_beta_features: false,
            max_cache_size_mb: 1024,
        })
        .with_analytics("https://my-analytics.example.com", 50);

    // === Transparent access to derusted fields via Deref ===
    println!("--- Accessing derusted fields (via Deref) ---");
    println!("Host: {}", config.host);  // No .base needed!
    println!("Port: {}", config.port);
    println!("Rate limit: {} req/min", config.rate_limit_requests_per_minute);
    println!("Max body size: {} bytes", config.max_request_body_size);

    // === Access to custom fields ===
    println!("\n--- Accessing custom fields ---");
    println!("App name: {}", config.app_name);
    println!("App version: {}", config.app_version);
    println!("Environment: {}", config.environment);

    // === Using custom analytics ===
    println!("\n--- Using custom analytics ---");
    config.analytics.log_request("/api/users", 42);
    config.analytics.log_request("/api/orders", 156);

    // === Using feature flags ===
    println!("\n--- Feature flags ---");
    println!("Caching enabled: {}", config.features.enable_caching);
    println!("Compression enabled: {}", config.features.enable_compression);
    println!("Beta features: {}", config.features.enable_beta_features);
    println!("Max cache size: {} MB", config.features.max_cache_size_mb);

    // === Using custom validator ===
    println!("\n--- Custom request validation ---");
    let test_paths = ["/api/users", "/admin/settings", "/public/docs", "/internal/health"];

    for path in test_paths {
        let allowed = config.validator.validate_path(path);
        println!("Path '{}': {}", path, if allowed { "ALLOWED" } else { "BLOCKED" });
    }

    // === Demonstrate passing to functions expecting base config ===
    println!("\n--- Function that expects base config ---");
    process_with_base_config(&config);
}

/// Example function that only needs derusted::Config
/// Thanks to Deref, we can pass MyAppConfig directly
fn process_with_base_config(config: &DerustedConfig) {
    println!(
        "Processing with base config: {}:{} (rate limit: {})",
        config.host, config.port, config.rate_limit_requests_per_minute
    );
}
