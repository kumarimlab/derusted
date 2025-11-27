// Mixed Content Policy Module
// Implements HTTP→HTTPS upgrade policy based on Referer/Origin headers

use anyhow::Result;
use http::{HeaderMap, Response, StatusCode, Uri};
use http_body_util::Full;
use hyper::body::Bytes;
use std::time::Duration;
use tracing::{debug, info, warn};
use url::Url;

use crate::config::Config;
use crate::http_metrics::HttpMetrics;

/// Error types for HTTPS upgrade attempts
#[derive(Debug)]
pub enum UpgradeError {
    InvalidUri(String),
    Timeout,
    HttpError(StatusCode),
    ConnectionFailed(String),
}

impl std::fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpgradeError::InvalidUri(msg) => write!(f, "Invalid URI: {}", msg),
            UpgradeError::Timeout => write!(f, "HTTPS probe timeout"),
            UpgradeError::HttpError(status) => write!(f, "HTTP error: {}", status),
            UpgradeError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
        }
    }
}

/// Parse and validate HTTPS origin from Referer or Origin headers
/// Returns the HTTPS origin if found, otherwise None
pub fn parse_https_origin(headers: &HeaderMap) -> Option<String> {
    // Check both Referer and Origin headers
    let referer = headers.get("referer").and_then(|v| v.to_str().ok());
    let origin = headers.get("origin").and_then(|v| v.to_str().ok());

    // Prioritize Origin (more reliable), fall back to Referer
    let source = origin.or(referer)?;

    // Parse with proper URL parser
    match Url::parse(source) {
        Ok(url) if url.scheme() == "https" => Some(url.origin().ascii_serialization()),
        Ok(_) => None, // HTTP or other protocol
        Err(e) => {
            warn!("Invalid Referer/Origin header: {} ({})", source, e);
            None
        }
    }
}

/// Probe HTTPS availability before upgrade
/// Returns the HTTPS URI if successful, otherwise an error
pub async fn try_upgrade_to_https(
    http_uri: &str,
    probe_timeout_ms: u64,
) -> Result<String, UpgradeError> {
    let https_uri = http_uri.replace("http://", "https://");

    // Parse to validate URI
    let _url = Url::parse(&https_uri).map_err(|e| UpgradeError::InvalidUri(e.to_string()))?;

    // Probe HTTPS availability with HEAD request
    debug!("Probing HTTPS availability: {}", https_uri);

    let start = std::time::Instant::now();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(probe_timeout_ms))
        .danger_accept_invalid_certs(true) // We're just checking availability
        .build()
        .map_err(|e| UpgradeError::ConnectionFailed(e.to_string()))?;

    match client.head(&https_uri).send().await {
        Ok(response) => {
            let duration = start.elapsed().as_secs_f64();

            if response.status().is_success() || response.status().is_redirection() {
                info!(
                    "HTTPS upgrade successful: {} → {} ({}ms)",
                    http_uri,
                    https_uri,
                    duration * 1000.0
                );
                HttpMetrics::record_upgrade_probe_duration(duration, true);
                Ok(https_uri)
            } else {
                let status_code = response.status().as_u16();
                warn!(
                    "HTTPS endpoint exists but returned {}: {}",
                    status_code, https_uri
                );
                HttpMetrics::record_upgrade_probe_duration(duration, false);
                // Convert reqwest::StatusCode to http::StatusCode
                let http_status =
                    StatusCode::from_u16(status_code).unwrap_or(StatusCode::BAD_GATEWAY);
                Err(UpgradeError::HttpError(http_status))
            }
        }
        Err(e) if e.is_timeout() => {
            let duration = start.elapsed().as_secs_f64();
            warn!("HTTPS probe timeout: {}", https_uri);
            HttpMetrics::record_upgrade_probe_duration(duration, false);
            Err(UpgradeError::Timeout)
        }
        Err(e) => {
            let duration = start.elapsed().as_secs_f64();
            warn!("HTTPS probe failed: {} ({})", https_uri, e);
            HttpMetrics::record_upgrade_probe_duration(duration, false);
            Err(UpgradeError::ConnectionFailed(e.to_string()))
        }
    }
}

/// Check if request is mixed content (HTTP with HTTPS Referer/Origin)
/// Returns (is_mixed_content, https_origin)
pub fn detect_mixed_content(uri: &Uri, headers: &HeaderMap) -> (bool, Option<String>) {
    let is_http = uri.scheme_str() == Some("http");
    let https_origin = parse_https_origin(headers);
    let is_mixed_content = is_http && https_origin.is_some();

    (is_mixed_content, https_origin)
}

/// Build error response for mixed content policy violation
pub fn build_block_response(message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("Content-Type", "text/plain")
        .header("Connection", "close")
        .body(Full::new(Bytes::from(format!(
            "Mixed Content Blocked: {}\n\nThis proxy policy requires all resources to use HTTPS when loaded from HTTPS pages.",
            message
        ))))
        .unwrap()
}

/// Build error response for upgrade failure
pub fn build_upgrade_failure_response(
    http_uri: &str,
    error: &UpgradeError,
) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("Content-Type", "text/plain")
        .header("Connection", "close")
        .body(Full::new(Bytes::from(format!(
            "HTTP→HTTPS Upgrade Failed\n\nCould not upgrade {} to HTTPS.\nError: {}\n\nThe HTTPS endpoint is not available.",
            http_uri, error
        ))))
        .unwrap()
}

/// Handle mixed content request according to policy
/// Returns Some(Response) if request should be blocked/modified
/// Returns None if request should proceed normally
pub async fn handle_mixed_content_request(
    uri: &mut Uri,
    headers: &HeaderMap,
    config: &Config,
) -> Result<Option<Response<Full<Bytes>>>, anyhow::Error> {
    // Check if this is mixed content
    let (is_mixed_content, https_origin) = detect_mixed_content(uri, headers);

    if !is_mixed_content {
        return Ok(None); // Not mixed content, proceed normally
    }

    let http_uri = uri.to_string();
    let origin = https_origin.as_deref().unwrap_or("unknown");

    info!(
        "[Mixed Content] Detected HTTP request from HTTPS origin: {} from {}",
        http_uri, origin
    );

    // Record mixed content detection
    HttpMetrics::record_mixed_content_detected(&config.mixed_content_policy);

    match config.mixed_content_policy.as_str() {
        "block" => {
            // Policy: Block all mixed content
            HttpMetrics::record_mixed_content_blocked("policy_block");
            warn!("[Mixed Content] Blocked: {}", http_uri);

            Ok(Some(build_block_response(&format!(
                "Cannot load HTTP resource {} from HTTPS page",
                http_uri
            ))))
        }

        "upgrade" => {
            // Policy: Try to upgrade HTTP→HTTPS
            match try_upgrade_to_https(&http_uri, config.upgrade_probe_timeout_ms).await {
                Ok(https_uri) => {
                    // Upgrade successful
                    HttpMetrics::record_mixed_content_upgraded("success");
                    info!("[Mixed Content] Upgraded: {} → {}", http_uri, https_uri);

                    // Parse and update URI
                    *uri = https_uri
                        .parse()
                        .map_err(|e| anyhow::anyhow!("Failed to parse upgraded URI: {}", e))?;

                    Ok(None) // Continue with upgraded request
                }
                Err(e) => {
                    // Upgrade failed - apply failure action
                    let failure_reason = match &e {
                        UpgradeError::Timeout => "timeout",
                        UpgradeError::HttpError(status) => {
                            if status.as_u16() == 404 {
                                "404_not_found"
                            } else {
                                "http_error"
                            }
                        }
                        UpgradeError::ConnectionFailed(_) => "connection_failed",
                        UpgradeError::InvalidUri(_) => "invalid_uri",
                    };

                    HttpMetrics::record_mixed_content_upgrade_failed(failure_reason);
                    warn!("[Mixed Content] Upgrade failed for {}: {}", http_uri, e);

                    match config.upgrade_failure_action.as_str() {
                        "block" => {
                            // Block request on upgrade failure
                            HttpMetrics::record_mixed_content_blocked("upgrade_failed");
                            Ok(Some(build_upgrade_failure_response(&http_uri, &e)))
                        }
                        "fallback" => {
                            // Allow HTTP request (fallback)
                            HttpMetrics::record_mixed_content_allowed("upgrade_fallback");
                            warn!(
                                "[Mixed Content] Falling back to HTTP after upgrade failure: {}",
                                http_uri
                            );
                            Ok(None) // Continue with original HTTP request
                        }
                        "warn" => {
                            // Allow HTTP with warning (lenient)
                            HttpMetrics::record_mixed_content_allowed("upgrade_warn");
                            warn!(
                                "[Mixed Content] Allowing HTTP after upgrade failure (warn mode): {}",
                                http_uri
                            );
                            Ok(None) // Continue with HTTP, just log warning
                        }
                        _ => Ok(None), // Default: allow
                    }
                }
            }
        }

        "allow" | _ => {
            // Policy: Allow mixed content
            HttpMetrics::record_mixed_content_allowed("policy_allow");
            debug!("[Mixed Content] Allowed: {}", http_uri);
            Ok(None) // Continue normally
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn test_parse_https_origin_with_referer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "referer",
            HeaderValue::from_static("https://www.example.com/page"),
        );

        let result = parse_https_origin(&headers);
        assert!(result.is_some());
        assert!(result.unwrap().starts_with("https://"));
    }

    #[test]
    fn test_parse_https_origin_with_http_referer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "referer",
            HeaderValue::from_static("http://www.example.com/page"),
        );

        let result = parse_https_origin(&headers);
        assert!(result.is_none()); // HTTP referer should return None
    }

    #[test]
    fn test_parse_https_origin_prioritizes_origin_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "origin",
            HeaderValue::from_static("https://origin.example.com"),
        );
        headers.insert(
            "referer",
            HeaderValue::from_static("https://referer.example.com"),
        );

        let result = parse_https_origin(&headers);
        assert!(result.is_some());
        assert!(result.unwrap().contains("origin.example.com"));
    }

    #[test]
    fn test_detect_mixed_content_http_with_https_referer() {
        let uri: Uri = "http://example.com/image.jpg".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "referer",
            HeaderValue::from_static("https://www.yahoo.com/"),
        );

        let (is_mixed, origin) = detect_mixed_content(&uri, &headers);
        assert!(is_mixed);
        assert!(origin.is_some());
    }

    #[test]
    fn test_detect_mixed_content_https_with_https_referer() {
        let uri: Uri = "https://example.com/image.jpg".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "referer",
            HeaderValue::from_static("https://www.yahoo.com/"),
        );

        let (is_mixed, _) = detect_mixed_content(&uri, &headers);
        assert!(!is_mixed); // HTTPS request is not mixed content
    }

    #[test]
    fn test_detect_mixed_content_http_with_http_referer() {
        let uri: Uri = "http://example.com/image.jpg".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "referer",
            HeaderValue::from_static("http://www.oldsite.com/"),
        );

        let (is_mixed, _) = detect_mixed_content(&uri, &headers);
        assert!(!is_mixed); // HTTP→HTTP is not mixed content
    }
}
