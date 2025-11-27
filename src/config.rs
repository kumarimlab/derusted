use anyhow::{Context, Result};
use std::env;
use std::sync::Arc;

use crate::auth::{JwtValidator, SharedJwtValidator};
use crate::destination_filter::DestinationFilter;
use crate::ip_tracker::IpTracker;
use crate::logger::{RequestLogger, SharedRequestLogger};
use crate::rate_limiter::{RateLimiter, RateLimiterConfig, SharedRateLimiter};

#[derive(Debug)]
pub struct Config {
    // Server configuration
    pub host: String,
    pub port: u16,

    // TLS certificate paths
    pub cert_path: String,
    pub key_path: String,

    // JWT configuration
    pub jwt_secret: String,
    pub jwt_algorithm: String,

    // Rate limiting
    pub rate_limit_requests_per_minute: usize,
    pub rate_limit_burst_size: usize,
    pub rate_limit_bucket_ttl_seconds: u64,
    pub rate_limit_max_buckets: usize,

    // Backend API configuration
    pub backend_url: String,
    pub probe_node_name: String,
    pub probe_node_region: String,

    // Logging
    pub log_batch_size: usize,
    pub log_batch_interval_secs: u64,

    // Phase 2: Authentication and rate limiting components
    pub jwt_validator: SharedJwtValidator,
    pub rate_limiter: SharedRateLimiter,
    pub request_logger: SharedRequestLogger,

    // HTTP Forwarding configuration
    pub http_proxy_enabled: bool,
    pub max_request_body_size: usize,
    pub max_response_body_size: usize,
    pub connect_timeout_seconds: u64,
    pub read_timeout_seconds: u64,
    pub write_timeout_seconds: u64,

    // DNS configuration
    pub dns_cache_size: usize,
    pub dns_cache_ttl_seconds: u64,
    pub dns_resolver_timeout_seconds: u64,

    // IP tracking configuration
    pub max_ips_per_token: usize,
    pub ip_tracker_cache_size: usize,
    pub ip_tracker_ttl_seconds: u64,

    // SSRF protection and IP tracking components
    pub destination_filter: Arc<DestinationFilter>,
    pub ip_tracker: Arc<IpTracker>,

    // Mixed content policy configuration
    pub mixed_content_policy: String,
    pub upgrade_failure_action: String,
    pub upgrade_probe_timeout_ms: u64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenv::dotenv().ok(); // Load .env file if present

        // Load configuration values
        let host = env::var("PROXY_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("PROXY_PORT")
            .unwrap_or_else(|_| "443".to_string())
            .parse()
            .context("Invalid PROXY_PORT")?;

        let cert_path = env::var("TLS_CERT_PATH").unwrap_or_else(|_| {
            "/etc/letsencrypt/live/staging.probeops.com/fullchain.pem".to_string()
        });
        let key_path = env::var("TLS_KEY_PATH").unwrap_or_else(|_| {
            "/etc/letsencrypt/live/staging.probeops.com/privkey.pem".to_string()
        });

        let jwt_secret = env::var("JWT_SECRET")
            .context("JWT_SECRET environment variable is required for authentication")?;

        // Validate JWT_SECRET is not empty or too short
        if jwt_secret.trim().is_empty() {
            return Err(anyhow::anyhow!("JWT_SECRET cannot be empty"));
        }
        if jwt_secret.len() < 32 {
            return Err(anyhow::anyhow!(
                "JWT_SECRET is too short ({} chars). Minimum 32 characters recommended for security.",
                jwt_secret.len()
            ));
        }

        let jwt_algorithm = env::var("JWT_ALGORITHM").unwrap_or_else(|_| "HS256".to_string());

        // Optional issuer and audience validation
        let jwt_issuer = env::var("JWT_ISSUER").ok();
        let jwt_audience = env::var("JWT_AUDIENCE").ok();

        let rate_limit_requests_per_minute = env::var("RATE_LIMIT_REQUESTS_PER_MINUTE")
            .unwrap_or_else(|_| "10000".to_string())
            .parse()
            .context("Invalid RATE_LIMIT_REQUESTS_PER_MINUTE")?;
        let rate_limit_burst_size = env::var("RATE_LIMIT_BURST_SIZE")
            .unwrap_or_else(|_| "500".to_string())
            .parse()
            .context("Invalid RATE_LIMIT_BURST_SIZE")?;
        let rate_limit_bucket_ttl_seconds = env::var("RATE_LIMIT_BUCKET_TTL_SECONDS")
            .unwrap_or_else(|_| "300".to_string())
            .parse()
            .context("Invalid RATE_LIMIT_BUCKET_TTL_SECONDS")?;
        let rate_limit_max_buckets = env::var("RATE_LIMIT_MAX_BUCKETS")
            .unwrap_or_else(|_| "10000".to_string())
            .parse()
            .context("Invalid RATE_LIMIT_MAX_BUCKETS")?;

        let backend_url =
            env::var("BACKEND_URL").unwrap_or_else(|_| "https://staging.probeops.com".to_string());
        let probe_node_name =
            env::var("PROBE_NODE_NAME").unwrap_or_else(|_| "probe-node-rust".to_string());
        let probe_node_region =
            env::var("PROBE_NODE_REGION").unwrap_or_else(|_| "us-east".to_string());

        let log_batch_size = env::var("LOG_BATCH_SIZE")
            .unwrap_or_else(|_| "100".to_string())
            .parse()
            .context("Invalid LOG_BATCH_SIZE")?;
        let log_batch_interval_secs = env::var("LOG_BATCH_INTERVAL_SECS")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .context("Invalid LOG_BATCH_INTERVAL_SECS")?;

        // HTTP Forwarding configuration
        let http_proxy_enabled = env::var("HTTP_PROXY_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .context("Invalid HTTP_PROXY_ENABLED")?;
        let max_request_body_size = env::var("MAX_REQUEST_BODY_SIZE")
            .unwrap_or_else(|_| "104857600".to_string()) // 100MB default
            .parse()
            .context("Invalid MAX_REQUEST_BODY_SIZE")?;
        let max_response_body_size = env::var("MAX_RESPONSE_BODY_SIZE")
            .unwrap_or_else(|_| "104857600".to_string()) // 100MB default
            .parse()
            .context("Invalid MAX_RESPONSE_BODY_SIZE")?;
        let connect_timeout_seconds = env::var("CONNECT_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .context("Invalid CONNECT_TIMEOUT_SECONDS")?;
        let read_timeout_seconds = env::var("READ_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .context("Invalid READ_TIMEOUT_SECONDS")?;
        let write_timeout_seconds = env::var("WRITE_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .context("Invalid WRITE_TIMEOUT_SECONDS")?;

        // DNS configuration
        let dns_cache_size = env::var("DNS_CACHE_SIZE")
            .unwrap_or_else(|_| "5000".to_string())
            .parse()
            .context("Invalid DNS_CACHE_SIZE")?;
        let dns_cache_ttl_seconds = env::var("DNS_CACHE_TTL_SECONDS")
            .unwrap_or_else(|_| "60".to_string())
            .parse()
            .context("Invalid DNS_CACHE_TTL_SECONDS")?;
        let dns_resolver_timeout_seconds = env::var("DNS_RESOLVER_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .context("Invalid DNS_RESOLVER_TIMEOUT_SECONDS")?;

        // IP tracking configuration
        let max_ips_per_token = env::var("MAX_IPS_PER_TOKEN")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .context("Invalid MAX_IPS_PER_TOKEN")?;
        let ip_tracker_cache_size = env::var("IP_TRACKER_CACHE_SIZE")
            .unwrap_or_else(|_| "10000".to_string())
            .parse()
            .context("Invalid IP_TRACKER_CACHE_SIZE")?;
        let ip_tracker_ttl_seconds = env::var("IP_TRACKER_TTL_SECONDS")
            .unwrap_or_else(|_| "3600".to_string())
            .parse()
            .context("Invalid IP_TRACKER_TTL_SECONDS")?;

        // Phase 2: Initialize JWT validator
        let jwt_validator = JwtValidator::new(
            jwt_secret.clone(),
            jwt_algorithm.clone(),
            probe_node_region.clone(),
            jwt_issuer.clone(),
            jwt_audience.clone(),
        )
        .context("Failed to initialize JWT validator")?;

        // Security warning: Log if issuer/audience validation is disabled
        if jwt_issuer.is_none() || jwt_audience.is_none() {
            tracing::warn!(
                issuer_set = jwt_issuer.is_some(),
                audience_set = jwt_audience.is_some(),
                "⚠️  JWT issuer/audience validation is DISABLED. Any token signed with the correct secret will be accepted. \
                 Set JWT_ISSUER and JWT_AUDIENCE environment variables for production deployments. \
                 See docs/JWT_VALIDATION_DEPLOYMENT_GUIDE.md for details."
            );
        } else {
            tracing::info!(
                issuer = jwt_issuer.as_deref().unwrap(),
                audience = jwt_audience.as_deref().unwrap(),
                "✓ JWT validation configured with issuer and audience enforcement"
            );
        }

        // Phase 2: Initialize rate limiter
        let rate_limiter_config = RateLimiterConfig {
            requests_per_minute: rate_limit_requests_per_minute,
            burst_size: rate_limit_burst_size,
            bucket_ttl_seconds: rate_limit_bucket_ttl_seconds,
            max_buckets: rate_limit_max_buckets,
        };
        let rate_limiter = RateLimiter::new(rate_limiter_config);

        // Initialize request logger
        let request_logger = RequestLogger::new(
            backend_url.clone(),
            probe_node_name.clone(),
            probe_node_region.clone(),
            log_batch_size,
            log_batch_interval_secs,
        );

        // Initialize destination filter (SSRF protection)
        let destination_filter = DestinationFilter::new(
            dns_cache_size,
            dns_cache_ttl_seconds,
            dns_resolver_timeout_seconds,
        )
        .context("Failed to initialize destination filter")?;

        // Initialize IP tracker
        let ip_tracker = IpTracker::new(
            max_ips_per_token,
            ip_tracker_cache_size,
            ip_tracker_ttl_seconds,
        );

        // Mixed content policy configuration
        let mixed_content_policy =
            env::var("MIXED_CONTENT_POLICY").unwrap_or_else(|_| "allow".to_string());

        // Validate mixed_content_policy value
        if !["allow", "upgrade", "block"].contains(&mixed_content_policy.as_str()) {
            return Err(anyhow::anyhow!(
                "Invalid MIXED_CONTENT_POLICY '{}'. Must be 'allow', 'upgrade', or 'block'",
                mixed_content_policy
            ));
        }

        let upgrade_failure_action =
            env::var("UPGRADE_FAILURE_ACTION").unwrap_or_else(|_| "warn".to_string());

        // Validate upgrade_failure_action value
        if !["block", "fallback", "warn"].contains(&upgrade_failure_action.as_str()) {
            return Err(anyhow::anyhow!(
                "Invalid UPGRADE_FAILURE_ACTION '{}'. Must be 'block', 'fallback', or 'warn'",
                upgrade_failure_action
            ));
        }

        let upgrade_probe_timeout_ms = env::var("UPGRADE_PROBE_TIMEOUT")
            .unwrap_or_else(|_| "1000".to_string())
            .parse()
            .context("Invalid UPGRADE_PROBE_TIMEOUT")?;

        // Log mixed content policy configuration
        if mixed_content_policy != "allow" {
            tracing::info!(
                policy = %mixed_content_policy,
                failure_action = %upgrade_failure_action,
                probe_timeout_ms = upgrade_probe_timeout_ms,
                "✓ Mixed content policy enabled"
            );
        }

        Ok(Config {
            host,
            port,
            cert_path,
            key_path,
            jwt_secret,
            jwt_algorithm,
            rate_limit_requests_per_minute,
            rate_limit_burst_size,
            rate_limit_bucket_ttl_seconds,
            rate_limit_max_buckets,
            backend_url,
            probe_node_name,
            probe_node_region,
            log_batch_size,
            log_batch_interval_secs,
            jwt_validator: Arc::new(jwt_validator),
            rate_limiter: Arc::new(rate_limiter),
            request_logger: Arc::new(request_logger),
            http_proxy_enabled,
            max_request_body_size,
            max_response_body_size,
            connect_timeout_seconds,
            read_timeout_seconds,
            write_timeout_seconds,
            dns_cache_size,
            dns_cache_ttl_seconds,
            dns_resolver_timeout_seconds,
            max_ips_per_token,
            ip_tracker_cache_size,
            ip_tracker_ttl_seconds,
            destination_filter: Arc::new(destination_filter),
            ip_tracker: Arc::new(ip_tracker),
            mixed_content_policy,
            upgrade_failure_action,
            upgrade_probe_timeout_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // Global mutex to serialize config tests (env vars are process-global)
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    // Helper to setup minimal valid test environment
    fn setup_test_env() {
        env::set_var("JWT_SECRET", "valid_test_secret_32_chars_min!!");
        env::set_var("PROBE_NODE_REGION", "test-region");
        env::set_var("BACKEND_URL", "http://localhost:8000");
        env::set_var("PROBE_NODE_NAME", "test-node");
    }

    // Helper to clear test environment
    fn clear_test_env() {
        env::remove_var("JWT_SECRET");
        env::remove_var("JWT_ISSUER");
        env::remove_var("JWT_AUDIENCE");
        env::remove_var("PROBE_NODE_REGION");
    }

    #[test]
    fn test_config_from_env_rejects_empty_jwt_secret() {
        // Phase 2.2 Integration Test: Config::from_env() should reject empty JWT_SECRET
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_test_env();
        env::set_var("JWT_SECRET", "");
        env::set_var("PROBE_NODE_REGION", "test-region");

        let result = Config::from_env();
        assert!(result.is_err(), "Empty JWT_SECRET should be rejected");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("JWT_SECRET cannot be empty"),
            "Error message should mention empty secret: {}",
            err_msg
        );

        clear_test_env();
    }

    #[test]
    fn test_config_from_env_rejects_whitespace_jwt_secret() {
        // Phase 2.2 Integration Test: Config::from_env() should reject whitespace-only JWT_SECRET
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_test_env();
        env::set_var("JWT_SECRET", "   ");
        env::set_var("PROBE_NODE_REGION", "test-region");

        let result = Config::from_env();
        assert!(
            result.is_err(),
            "Whitespace-only JWT_SECRET should be rejected"
        );

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("JWT_SECRET cannot be empty"),
            "Error message should mention empty secret: {}",
            err_msg
        );

        clear_test_env();
    }

    #[test]
    fn test_config_from_env_rejects_short_jwt_secret() {
        // Phase 2.2 Integration Test: Config::from_env() should reject JWT_SECRET < 32 chars
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_test_env();
        env::set_var("JWT_SECRET", "short_secret_19chars"); // 19 chars
        env::set_var("PROBE_NODE_REGION", "test-region");

        let result = Config::from_env();
        assert!(
            result.is_err(),
            "JWT_SECRET shorter than 32 chars should be rejected"
        );

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("too short") && err_msg.contains("32 characters"),
            "Error message should mention minimum length: {}",
            err_msg
        );

        clear_test_env();
    }

    #[test]
    fn test_config_from_env_accepts_minimum_length_jwt_secret() {
        // Phase 2.2 Integration Test: Config::from_env() should accept JWT_SECRET with exactly 32 chars
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_test_env();
        env::set_var("JWT_SECRET", "exactly_32_characters_long_yes!!"); // Exactly 32 chars
        env::set_var("PROBE_NODE_REGION", "test-region");

        let result = Config::from_env();
        assert!(
            result.is_ok(),
            "JWT_SECRET with exactly 32 chars should be accepted: {:?}",
            result.err()
        );

        let config = result.unwrap();
        assert_eq!(config.jwt_secret, "exactly_32_characters_long_yes!!");

        clear_test_env();
    }

    #[test]
    fn test_config_from_env_accepts_long_jwt_secret() {
        // Phase 2.2 Integration Test: Config::from_env() should accept JWT_SECRET > 32 chars
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_test_env();
        let long_secret =
            "this_is_a_very_long_jwt_secret_with_more_than_32_characters_for_security";
        env::set_var("JWT_SECRET", long_secret);
        env::set_var("PROBE_NODE_REGION", "test-region");

        let result = Config::from_env();
        assert!(
            result.is_ok(),
            "JWT_SECRET longer than 32 chars should be accepted: {:?}",
            result.err()
        );

        let config = result.unwrap();
        assert_eq!(config.jwt_secret, long_secret);

        clear_test_env();
    }

    #[test]
    fn test_config_from_env_issuer_audience_optional() {
        // Phase 2.2 Integration Test: JWT_ISSUER and JWT_AUDIENCE should be optional
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_test_env();
        setup_test_env();

        // Without JWT_ISSUER/JWT_AUDIENCE set
        let result = Config::from_env();
        assert!(
            result.is_ok(),
            "Config should succeed without JWT_ISSUER/JWT_AUDIENCE"
        );

        let config = result.unwrap();
        assert!(
            config.jwt_validator.expected_issuer().is_none(),
            "expected_issuer should be None when JWT_ISSUER not set"
        );
        assert!(
            config.jwt_validator.expected_audience().is_none(),
            "expected_audience should be None when JWT_AUDIENCE not set"
        );

        clear_test_env();
    }

    #[test]
    fn test_config_from_env_issuer_audience_configured() {
        // Phase 2.2 Integration Test: JWT_ISSUER and JWT_AUDIENCE should be configurable
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_test_env();
        setup_test_env();
        env::set_var("JWT_ISSUER", "test-issuer");
        env::set_var("JWT_AUDIENCE", "test-audience");

        let result = Config::from_env();
        assert!(
            result.is_ok(),
            "Config should succeed with JWT_ISSUER/JWT_AUDIENCE"
        );

        let config = result.unwrap();
        assert_eq!(
            config.jwt_validator.expected_issuer(),
            Some("test-issuer"),
            "expected_issuer should match JWT_ISSUER env var"
        );
        assert_eq!(
            config.jwt_validator.expected_audience(),
            Some("test-audience"),
            "expected_audience should match JWT_AUDIENCE env var"
        );

        clear_test_env();
    }
}
