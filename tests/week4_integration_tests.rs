//! Week 4 Integration Tests: HTTP Parsing & Logging
//!
//! End-to-end tests for MITM with HTTP parsing and SQLite logging

use derusted::mitm::{
    http_parser::{parse_http1_request, parse_http1_response},
    log_storage::LogStorage,
    logging::PiiRedactor,
};
use tempfile::TempDir;

/// Test 1: HTTP Parser Integration with Request Parsing
#[tokio::test]
async fn test_http_parser_request_integration() {
    // Test simple GET request
    let request_data =
        b"GET /api/users?id=123 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test\r\n\r\n";
    let request = parse_http1_request(request_data).unwrap();

    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/api/users?id=123");
    assert_eq!(request.version, "HTTP/1.1");
    assert_eq!(request.headers.get("host").unwrap(), "example.com");
    assert_eq!(request.headers.get("user-agent").unwrap(), "Test");
    assert_eq!(request.content_length, None);
    assert!(request.body_preview.is_empty());
}

/// Test 2: HTTP Parser Integration with POST Request
#[tokio::test]
async fn test_http_parser_post_with_body() {
    let request_data = b"POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"user\":\"test\",\"pass\":\"secret\"}";
    let request = parse_http1_request(request_data).unwrap();

    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/login");
    assert_eq!(request.content_length, Some(27));
    assert!(request.body_preview.contains("\"user\":\"test\""));
}

/// Test 3: HTTP Parser Integration with Response Parsing
#[tokio::test]
async fn test_http_parser_response_integration() {
    let response_data = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"status\":\"ok\"}";
    let response = parse_http1_response(response_data).unwrap();

    assert_eq!(response.version, "HTTP/1.1");
    assert_eq!(response.status_code, 200);
    assert_eq!(response.reason, "OK");
    assert_eq!(
        response.headers.get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(response.content_length, Some(16));
    assert!(response.is_success());
    assert!(!response.is_error());
}

/// Test 4: Binary Response Handling
#[tokio::test]
async fn test_binary_response_handling() {
    // Create PNG response (magic bytes)
    let mut response_data =
        b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 100\r\n\r\n".to_vec();
    response_data.extend_from_slice(&[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]); // PNG header
    response_data.extend_from_slice(&vec![0; 92]); // Pad to 100 bytes

    let response = parse_http1_response(&response_data).unwrap();

    assert_eq!(response.status_code, 200);
    assert_eq!(response.content_type().unwrap(), "image/png");
    assert!(response.body_preview.contains("[Binary data:"));
}

/// Test 5: PII Redaction in Logging
#[tokio::test]
async fn test_pii_redaction_in_logging() {
    // Test credit card redaction
    let path_with_cc = "/payment?card=4532-1234-5678-9010&cvv=123";
    let redacted = PiiRedactor::redact(path_with_cc);
    assert!(redacted.contains("[REDACTED]"));
    assert!(!redacted.contains("4532-1234-5678-9010"));

    // Test email redaction
    let path_with_email = "/user?email=john.doe@example.com&action=verify";
    let redacted = PiiRedactor::redact(path_with_email);
    assert!(redacted.contains("[REDACTED]"));
    assert!(!redacted.contains("john.doe@example.com"));

    // Test SSN redaction
    let path_with_ssn = "/profile?ssn=123-45-6789&name=test";
    let redacted = PiiRedactor::redact(path_with_ssn);
    assert!(redacted.contains("[REDACTED]"));
    assert!(!redacted.contains("123-45-6789"));
}

/// Test 6: SQLite Logging Integration
#[tokio::test]
async fn test_sqlite_logging_integration() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_requests.db");

    // Create storage
    let storage = LogStorage::new(db_path.to_str().unwrap()).await.unwrap();

    // Create test metadata
    let metadata = derusted::mitm::logging::RequestMetadata {
        timestamp: chrono::Utc::now().timestamp(),
        method: "GET".to_string(),
        host: "example.com".to_string(),
        port: 443,
        path: "/api/test".to_string(),
        http_version: "HTTP/1.1".to_string(),
        status_code: Some(200),
        request_size: 512,
        response_size: 1024,
        duration_ms: 150,
        tls_version: Some("TLS 1.3".to_string()),
        mitm_applied: true,
        bypass_reason: None,
    };

    // Log request
    let log_id = storage.log_request(&metadata).await.unwrap();
    assert!(log_id > 0);

    // Query logs
    let start_ts = chrono::Utc::now().timestamp() - 3600;
    let end_ts = chrono::Utc::now().timestamp() + 3600;
    let logs = storage.query_logs(start_ts, end_ts, 10).await.unwrap();

    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].method, "GET");
    assert_eq!(logs[0].host, "example.com");
    assert_eq!(logs[0].path, "/api/test");
    assert_eq!(logs[0].status_code, Some(200));

    // Test query by host
    let host_logs = storage.query_logs_by_host("example.com", 10).await.unwrap();
    assert_eq!(host_logs.len(), 1);

    // Test count
    let count = storage.count_logs().await.unwrap();
    assert_eq!(count, 1);
}

/// Test 7: Logging Policy Sampling
#[tokio::test]
async fn test_logging_policy_sampling() {
    // Test 0% sampling (disabled)
    let mut sampled_count = 0;
    for _ in 0..100 {
        if PiiRedactor::should_sample(0.0) {
            sampled_count += 1;
        }
    }
    assert_eq!(sampled_count, 0);

    // Test 100% sampling (all)
    let mut sampled_count = 0;
    for _ in 0..100 {
        if PiiRedactor::should_sample(1.0) {
            sampled_count += 1;
        }
    }
    assert_eq!(sampled_count, 100);

    // Test ~10% sampling (statistical)
    let mut sampled_count = 0;
    for _ in 0..1000 {
        if PiiRedactor::should_sample(0.1) {
            sampled_count += 1;
        }
    }
    // Allow some variance (5%-15%)
    assert!(sampled_count >= 50);
    assert!(sampled_count <= 150);
}

/// Test 8: Multiple Request Logging
#[tokio::test]
async fn test_multiple_request_logging() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("multi_requests.db");

    let storage = LogStorage::new(db_path.to_str().unwrap()).await.unwrap();

    // Log multiple requests
    for i in 0..10 {
        let metadata = derusted::mitm::logging::RequestMetadata {
            timestamp: chrono::Utc::now().timestamp(),
            method: "GET".to_string(),
            host: format!("host{}.example.com", i),
            port: 443,
            path: format!("/api/endpoint{}", i),
            http_version: "HTTP/1.1".to_string(),
            status_code: Some(200 + i as u16),
            request_size: 100 + i * 10,
            response_size: 500 + i * 50,
            duration_ms: 100 + (i * 10) as u64,
            tls_version: Some("TLS 1.3".to_string()),
            mitm_applied: true,
            bypass_reason: None,
        };

        storage.log_request(&metadata).await.unwrap();
    }

    // Verify all logged
    let count = storage.count_logs().await.unwrap();
    assert_eq!(count, 10);

    // Query with limit
    let start_ts = chrono::Utc::now().timestamp() - 3600;
    let end_ts = chrono::Utc::now().timestamp() + 3600;
    let logs = storage.query_logs(start_ts, end_ts, 5).await.unwrap();
    assert_eq!(logs.len(), 5); // Limited to 5

    // Query specific host
    let host_logs = storage
        .query_logs_by_host("host5.example.com", 10)
        .await
        .unwrap();
    assert_eq!(host_logs.len(), 1);
    assert_eq!(host_logs[0].path, "/api/endpoint5");
}

/// Test 9: PII Redaction with Multiple Patterns
#[tokio::test]
async fn test_pii_redaction_multiple_patterns() {
    let path =
        "/checkout?card=4532-1234-5678-9010&email=user@test.com&phone=555-123-4567&ssn=123-45-6789";
    let redacted = PiiRedactor::redact(path);

    // Verify all PII is redacted
    assert!(redacted.contains("[REDACTED]"));
    assert!(!redacted.contains("4532-1234-5678-9010"));
    assert!(!redacted.contains("user@test.com"));
    assert!(!redacted.contains("555-123-4567"));
    assert!(!redacted.contains("123-45-6789"));

    // Verify safe parts remain
    assert!(redacted.contains("/checkout"));
    assert!(redacted.contains("card="));
    assert!(redacted.contains("email="));
}

/// Test 10: Database Cleanup
#[tokio::test]
async fn test_database_cleanup() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("cleanup_test.db");

    let storage = LogStorage::new(db_path.to_str().unwrap()).await.unwrap();

    // Create old log (365 days ago)
    let old_metadata = derusted::mitm::logging::RequestMetadata {
        timestamp: chrono::Utc::now().timestamp() - (365 * 86400),
        method: "GET".to_string(),
        host: "old.example.com".to_string(),
        port: 443,
        path: "/old".to_string(),
        http_version: "HTTP/1.1".to_string(),
        status_code: Some(200),
        request_size: 100,
        response_size: 500,
        duration_ms: 100,
        tls_version: Some("TLS 1.2".to_string()),
        mitm_applied: true,
        bypass_reason: None,
    };

    // Create recent log
    let recent_metadata = derusted::mitm::logging::RequestMetadata {
        timestamp: chrono::Utc::now().timestamp(),
        method: "GET".to_string(),
        host: "new.example.com".to_string(),
        port: 443,
        path: "/new".to_string(),
        http_version: "HTTP/1.1".to_string(),
        status_code: Some(200),
        request_size: 100,
        response_size: 500,
        duration_ms: 100,
        tls_version: Some("TLS 1.3".to_string()),
        mitm_applied: true,
        bypass_reason: None,
    };

    storage.log_request(&old_metadata).await.unwrap();
    storage.log_request(&recent_metadata).await.unwrap();

    // Verify both logged
    let count = storage.count_logs().await.unwrap();
    assert_eq!(count, 2);

    // Cleanup logs older than 30 days
    let deleted = storage.cleanup_old_logs(30).await.unwrap();
    assert_eq!(deleted, 1);

    // Verify only recent log remains
    let count = storage.count_logs().await.unwrap();
    assert_eq!(count, 1);

    // Vacuum database
    storage.vacuum().await.unwrap();
}

/// Test 11: Error Response Logging
#[tokio::test]
async fn test_error_response_logging() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("error_responses.db");

    let storage = LogStorage::new(db_path.to_str().unwrap()).await.unwrap();

    // Log 404 error
    let metadata_404 = derusted::mitm::logging::RequestMetadata {
        timestamp: chrono::Utc::now().timestamp(),
        method: "GET".to_string(),
        host: "example.com".to_string(),
        port: 443,
        path: "/not-found".to_string(),
        http_version: "HTTP/1.1".to_string(),
        status_code: Some(404),
        request_size: 100,
        response_size: 200,
        duration_ms: 50,
        tls_version: Some("TLS 1.3".to_string()),
        mitm_applied: true,
        bypass_reason: None,
    };

    // Log 500 error
    let metadata_500 = derusted::mitm::logging::RequestMetadata {
        timestamp: chrono::Utc::now().timestamp(),
        method: "POST".to_string(),
        host: "api.example.com".to_string(),
        port: 443,
        path: "/api/action".to_string(),
        http_version: "HTTP/1.1".to_string(),
        status_code: Some(500),
        request_size: 500,
        response_size: 300,
        duration_ms: 200,
        tls_version: Some("TLS 1.3".to_string()),
        mitm_applied: true,
        bypass_reason: None,
    };

    storage.log_request(&metadata_404).await.unwrap();
    storage.log_request(&metadata_500).await.unwrap();

    // Verify both logged
    let count = storage.count_logs().await.unwrap();
    assert_eq!(count, 2);

    // Query logs
    let start_ts = chrono::Utc::now().timestamp() - 3600;
    let end_ts = chrono::Utc::now().timestamp() + 3600;
    let logs = storage.query_logs(start_ts, end_ts, 10).await.unwrap();

    assert_eq!(logs.len(), 2);

    // Verify error codes
    let status_codes: Vec<u16> = logs.iter().filter_map(|l| l.status_code).collect();
    assert!(status_codes.contains(&404));
    assert!(status_codes.contains(&500));
}
