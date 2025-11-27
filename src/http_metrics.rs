// HTTP Forwarding Metrics Module
// Phase 4: Prometheus metrics for monitoring HTTP proxy performance

use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge, HistogramVec,
    IntCounterVec, IntGauge,
};

lazy_static::lazy_static! {
    // Request counters
    pub static ref HTTP_REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "http_proxy_requests_total",
        "Total number of HTTP proxy requests",
        &["method", "status"]
    ).unwrap();

    pub static ref HTTP_REQUEST_ERRORS: IntCounterVec = register_int_counter_vec!(
        "http_proxy_request_errors_total",
        "Total number of HTTP proxy request errors",
        &["error_type"]
    ).unwrap();

    // IP retry metrics
    pub static ref IP_RETRY_ATTEMPTS: IntCounterVec = register_int_counter_vec!(
        "http_proxy_ip_retry_attempts_total",
        "Total number of IP retry attempts",
        &["success"]
    ).unwrap();

    pub static ref IP_RETRY_FAILURES: IntCounterVec = register_int_counter_vec!(
        "http_proxy_ip_retry_failures_total",
        "Total number of failed IP retry attempts by failure reason",
        &["failure_reason"]
    ).unwrap();

    // DNS cache metrics
    pub static ref DNS_CACHE_HITS: IntCounterVec = register_int_counter_vec!(
        "http_proxy_dns_cache_hits_total",
        "Total number of DNS cache hits",
        &["cache_status"]
    ).unwrap();

    pub static ref DNS_RESOLUTIONS: IntCounterVec = register_int_counter_vec!(
        "http_proxy_dns_resolutions_total",
        "Total number of DNS resolutions",
        &["result"]
    ).unwrap();

    // Body size metrics
    pub static ref REQUEST_BODY_SIZE: HistogramVec = register_histogram_vec!(
        "http_proxy_request_body_bytes",
        "Request body size distribution in bytes",
        &["method"],
        vec![100.0, 1_000.0, 10_000.0, 100_000.0, 1_000_000.0, 10_000_000.0, 100_000_000.0]
    ).unwrap();

    pub static ref RESPONSE_BODY_SIZE: HistogramVec = register_histogram_vec!(
        "http_proxy_response_body_bytes",
        "Response body size distribution in bytes",
        &["status"],
        vec![100.0, 1_000.0, 10_000.0, 100_000.0, 1_000_000.0, 10_000_000.0, 100_000_000.0]
    ).unwrap();

    // TLS handshake metrics
    pub static ref TLS_HANDSHAKE_DURATION: HistogramVec = register_histogram_vec!(
        "http_proxy_tls_handshake_duration_seconds",
        "TLS handshake duration in seconds",
        &["result"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
    ).unwrap();

    pub static ref TLS_HANDSHAKE_ERRORS: IntCounterVec = register_int_counter_vec!(
        "http_proxy_tls_handshake_errors_total",
        "Total number of TLS handshake errors",
        &["error_type"]
    ).unwrap();

    // Connection timing metrics
    pub static ref CONNECTION_DURATION: HistogramVec = register_histogram_vec!(
        "http_proxy_connection_duration_seconds",
        "Connection establishment duration in seconds",
        &["result"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
    ).unwrap();

    pub static ref REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "http_proxy_request_duration_seconds",
        "Total request duration from start to finish",
        &["method", "status"],
        vec![0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
    ).unwrap();

    // SSRF protection metrics
    pub static ref SSRF_BLOCKS: IntCounterVec = register_int_counter_vec!(
        "http_proxy_ssrf_blocks_total",
        "Total number of requests blocked by SSRF protection",
        &["block_reason"]
    ).unwrap();

    // Rate limiting metrics
    pub static ref RATE_LIMIT_HITS: IntCounterVec = register_int_counter_vec!(
        "http_proxy_rate_limit_hits_total",
        "Total number of rate limit hits",
        &["token_id"]
    ).unwrap();

    // IP tracking metrics
    pub static ref IP_LIMIT_VIOLATIONS: IntCounterVec = register_int_counter_vec!(
        "http_proxy_ip_limit_violations_total",
        "Total number of IP limit violations",
        &["token_id"]
    ).unwrap();

    pub static ref UNIQUE_IPS_PER_TOKEN: IntGauge = register_int_gauge!(
        "http_proxy_unique_ips_per_token",
        "Current number of unique IPs tracked per token"
    ).unwrap();

    // Chunked encoding metrics
    pub static ref CHUNKED_RESPONSES: IntCounterVec = register_int_counter_vec!(
        "http_proxy_chunked_responses_total",
        "Total number of chunked transfer encoding responses",
        &["dechunked"]
    ).unwrap();

    // Content-Length metrics
    pub static ref CONTENT_LENGTH_MISMATCHES: IntCounterVec = register_int_counter_vec!(
        "http_proxy_content_length_mismatches_total",
        "Total number of Content-Length mismatches (premature EOF)",
        &["expected_vs_actual"]
    ).unwrap();

    // Mixed content policy metrics
    pub static ref MIXED_CONTENT_DETECTED: IntCounterVec = register_int_counter_vec!(
        "http_proxy_mixed_content_detected_total",
        "Total HTTP requests with HTTPS Referer/Origin",
        &["policy_action"]
    ).unwrap();

    pub static ref MIXED_CONTENT_ALLOWED: IntCounterVec = register_int_counter_vec!(
        "http_proxy_mixed_content_allowed_total",
        "Mixed content requests allowed through",
        &["reason"]
    ).unwrap();

    pub static ref MIXED_CONTENT_BLOCKED: IntCounterVec = register_int_counter_vec!(
        "http_proxy_mixed_content_blocked_total",
        "Mixed content requests blocked (403)",
        &["reason"]
    ).unwrap();

    pub static ref MIXED_CONTENT_UPGRADED: IntCounterVec = register_int_counter_vec!(
        "http_proxy_mixed_content_upgraded_total",
        "Successful HTTP→HTTPS upgrades",
        &["result"]
    ).unwrap();

    pub static ref MIXED_CONTENT_UPGRADE_FAILED: IntCounterVec = register_int_counter_vec!(
        "http_proxy_mixed_content_upgrade_failed_total",
        "Failed HTTP→HTTPS upgrade attempts",
        &["failure_reason"]
    ).unwrap();

    pub static ref UPGRADE_PROBE_DURATION: HistogramVec = register_histogram_vec!(
        "http_proxy_upgrade_probe_duration_seconds",
        "HTTPS probe duration in seconds",
        &["result"],
        vec![0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]
    ).unwrap();
}

/// Helper struct for recording HTTP metrics
pub struct HttpMetrics;

impl HttpMetrics {
    /// Record a completed HTTP request
    pub fn record_request(method: &str, status: u16, duration_secs: f64) {
        HTTP_REQUESTS_TOTAL
            .with_label_values(&[method, &status.to_string()])
            .inc();

        REQUEST_DURATION
            .with_label_values(&[method, &status.to_string()])
            .observe(duration_secs);
    }

    /// Record an HTTP request error
    pub fn record_error(error_type: &str) {
        HTTP_REQUEST_ERRORS.with_label_values(&[error_type]).inc();
    }

    /// Record IP retry attempt
    pub fn record_ip_retry(success: bool, failure_reason: Option<&str>) {
        IP_RETRY_ATTEMPTS
            .with_label_values(&[if success { "true" } else { "false" }])
            .inc();

        if let Some(reason) = failure_reason {
            IP_RETRY_FAILURES.with_label_values(&[reason]).inc();
        }
    }

    /// Record DNS cache hit/miss
    pub fn record_dns_cache(is_hit: bool) {
        DNS_CACHE_HITS
            .with_label_values(&[if is_hit { "hit" } else { "miss" }])
            .inc();
    }

    /// Record DNS resolution result
    pub fn record_dns_resolution(success: bool) {
        DNS_RESOLUTIONS
            .with_label_values(&[if success { "success" } else { "failure" }])
            .inc();
    }

    /// Record request body size
    pub fn record_request_body_size(method: &str, size: usize) {
        REQUEST_BODY_SIZE
            .with_label_values(&[method])
            .observe(size as f64);
    }

    /// Record response body size
    pub fn record_response_body_size(status: u16, size: usize) {
        RESPONSE_BODY_SIZE
            .with_label_values(&[&status.to_string()])
            .observe(size as f64);
    }

    /// Record TLS handshake duration
    pub fn record_tls_handshake(duration_secs: f64, success: bool) {
        TLS_HANDSHAKE_DURATION
            .with_label_values(&[if success { "success" } else { "failure" }])
            .observe(duration_secs);
    }

    /// Record TLS handshake error
    pub fn record_tls_error(error_type: &str) {
        TLS_HANDSHAKE_ERRORS.with_label_values(&[error_type]).inc();
    }

    /// Record connection duration
    pub fn record_connection(duration_secs: f64, success: bool) {
        CONNECTION_DURATION
            .with_label_values(&[if success { "success" } else { "failure" }])
            .observe(duration_secs);
    }

    /// Record SSRF block
    pub fn record_ssrf_block(reason: &str) {
        SSRF_BLOCKS.with_label_values(&[reason]).inc();
    }

    /// Record rate limit hit
    pub fn record_rate_limit_hit(token_id: &str) {
        RATE_LIMIT_HITS.with_label_values(&[token_id]).inc();
    }

    /// Record IP limit violation
    pub fn record_ip_limit_violation(token_id: &str) {
        IP_LIMIT_VIOLATIONS.with_label_values(&[token_id]).inc();
    }

    /// Record chunked response
    pub fn record_chunked_response(was_dechunked: bool) {
        CHUNKED_RESPONSES
            .with_label_values(&[if was_dechunked { "yes" } else { "no" }])
            .inc();
    }

    /// Record Content-Length mismatch
    pub fn record_content_length_mismatch(expected: usize, actual: usize) {
        CONTENT_LENGTH_MISMATCHES
            .with_label_values(&[&format!("expected_{}_got_{}", expected, actual)])
            .inc();
    }

    /// Record mixed content detection
    pub fn record_mixed_content_detected(policy_action: &str) {
        MIXED_CONTENT_DETECTED
            .with_label_values(&[policy_action])
            .inc();
    }

    /// Record mixed content allowed
    pub fn record_mixed_content_allowed(reason: &str) {
        MIXED_CONTENT_ALLOWED.with_label_values(&[reason]).inc();
    }

    /// Record mixed content blocked
    pub fn record_mixed_content_blocked(reason: &str) {
        MIXED_CONTENT_BLOCKED.with_label_values(&[reason]).inc();
    }

    /// Record successful HTTP→HTTPS upgrade
    pub fn record_mixed_content_upgraded(result: &str) {
        MIXED_CONTENT_UPGRADED.with_label_values(&[result]).inc();
    }

    /// Record failed HTTP→HTTPS upgrade
    pub fn record_mixed_content_upgrade_failed(failure_reason: &str) {
        MIXED_CONTENT_UPGRADE_FAILED
            .with_label_values(&[failure_reason])
            .inc();
    }

    /// Record HTTPS probe duration
    pub fn record_upgrade_probe_duration(duration_secs: f64, success: bool) {
        UPGRADE_PROBE_DURATION
            .with_label_values(&[if success { "success" } else { "failure" }])
            .observe(duration_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_request() {
        HttpMetrics::record_request("GET", 200, 0.5);
        // Metrics should increment without panicking
    }

    #[test]
    fn test_record_error() {
        HttpMetrics::record_error("connection_timeout");
    }

    #[test]
    fn test_record_body_sizes() {
        HttpMetrics::record_request_body_size("POST", 1024);
        HttpMetrics::record_response_body_size(200, 50652);
    }
}
