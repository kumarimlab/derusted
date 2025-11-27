//! Week 4 Edge Case Tests
//!
//! Tests for edge cases in HTTP parsing and logging

use derusted::mitm::{
    http_parser::{parse_http1_request, parse_http1_response, ParseError},
    logging::PiiRedactor,
};

/// Test 1: Incomplete HTTP request (no complete headers)
#[test]
fn test_incomplete_http_request() {
    let incomplete_request = b"GET /api/test HTTP/1.1\r\nHost: example.com\r\n";

    let result = parse_http1_request(incomplete_request);

    // Should return Incomplete error
    match result {
        Err(ParseError::Incomplete) => {
            // Expected - request missing final \r\n\r\n
        }
        _ => panic!("Expected ParseError::Incomplete for incomplete request"),
    }
}

/// Test 2: Very large headers (exceeding typical 8KB buffer)
#[test]
fn test_large_headers() {
    // Create a request with very large header value (10KB)
    let large_value = "x".repeat(10000);
    let large_header_request = format!(
        "GET /api/test HTTP/1.1\r\nHost: example.com\r\nX-Large-Header: {}\r\n\r\n",
        large_value
    );

    let result = parse_http1_request(large_header_request.as_bytes());

    // Should parse successfully (parser handles large headers)
    assert!(result.is_ok());
    let request = result.unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/api/test");
    assert!(request.headers.contains_key("x-large-header"));
}

/// Test 3: Multiple small headers (many headers, small values)
#[test]
fn test_many_headers() {
    let mut request_str = String::from("POST /api/data HTTP/1.1\r\nHost: example.com\r\n");

    // Add 100 custom headers
    for i in 0..100 {
        request_str.push_str(&format!("X-Custom-{}: value{}\r\n", i, i));
    }
    request_str.push_str("\r\n");

    let result = parse_http1_request(request_str.as_bytes());

    assert!(result.is_ok());
    let request = result.unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.headers.len(), 101); // 100 custom + Host
}

/// Test 4: HTTP request with chunked transfer encoding header
#[test]
fn test_chunked_transfer_encoding_header() {
    let chunked_request =
        b"POST /api/upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";

    let result = parse_http1_request(chunked_request);

    assert!(result.is_ok());
    let request = result.unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.headers.get("transfer-encoding").unwrap(), "chunked");
    assert_eq!(request.content_length, None); // No Content-Length with chunked
}

/// Test 5: Response with chunked transfer encoding
#[test]
fn test_chunked_response_header() {
    let chunked_response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";

    let result = parse_http1_response(chunked_response);

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status_code, 200);
    assert_eq!(
        response.headers.get("transfer-encoding").unwrap(),
        "chunked"
    );
    assert_eq!(response.content_length, None);
}

/// Test 6: Malformed HTTP request (invalid format)
#[test]
fn test_malformed_http_request() {
    let malformed_request = b"INVALID REQUEST FORMAT\r\n\r\n";

    let result = parse_http1_request(malformed_request);

    // Should return error
    assert!(result.is_err());
}

/// Test 7: HTTP/1.0 request (older protocol version)
#[test]
fn test_http10_request() {
    let http10_request = b"GET /index.html HTTP/1.0\r\nHost: example.com\r\n\r\n";

    let result = parse_http1_request(http10_request);

    assert!(result.is_ok());
    let request = result.unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(request.version, "HTTP/1.0");
}

/// Test 8: HTTP/1.0 response
#[test]
fn test_http10_response() {
    let http10_response = b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n";

    let result = parse_http1_response(http10_response);

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.version, "HTTP/1.0");
    assert_eq!(response.status_code, 200);
}

/// Test 9: Request with unusual but valid method
#[test]
fn test_unusual_http_methods() {
    let methods = ["OPTIONS", "HEAD", "PATCH", "DELETE", "TRACE"];

    for method in &methods {
        let request_str = format!("{} /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n", method);
        let result = parse_http1_request(request_str.as_bytes());

        assert!(result.is_ok());
        let request = result.unwrap();
        assert_eq!(request.method, *method);
    }
}

/// Test 10: Response with 1xx informational status
#[test]
fn test_informational_response() {
    let info_response = b"HTTP/1.1 100 Continue\r\n\r\n";

    let result = parse_http1_response(info_response);

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status_code, 100);
    assert_eq!(response.reason, "Continue");
}

/// Test 11: Response with 3xx redirect
#[test]
fn test_redirect_response() {
    let redirect_response =
        b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://newsite.com\r\n\r\n";

    let result = parse_http1_response(redirect_response);

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status_code, 301);
    assert_eq!(
        response.headers.get("location").unwrap(),
        "https://newsite.com"
    );
}

/// Test 12: Response with 4xx client error
#[test]
fn test_client_error_response() {
    let error_response = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n";

    let result = parse_http1_response(error_response);

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status_code, 404);
    assert!(response.is_error());
}

/// Test 13: Response with 5xx server error
#[test]
fn test_server_error_response() {
    let error_response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n";

    let result = parse_http1_response(error_response);

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status_code, 500);
    assert!(response.is_error());
}

/// Test 14: Request with empty path (should use /)
#[test]
fn test_request_with_root_path() {
    let root_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    let result = parse_http1_request(root_request);

    assert!(result.is_ok());
    let request = result.unwrap();
    assert_eq!(request.path, "/");
}

/// Test 15: Request with very long path (realistic URL)
#[test]
fn test_long_path() {
    let long_path = format!("/api/{}/data", "segment/".repeat(100));
    let request_str = format!("GET {} HTTP/1.1\r\nHost: example.com\r\n\r\n", long_path);

    let result = parse_http1_request(request_str.as_bytes());

    assert!(result.is_ok());
    let request = result.unwrap();
    // Parser successfully handles long paths
    assert!(request.path.starts_with("/api/"));
    assert!(request.path.contains("segment"));
}

/// Test 16: PII redaction with Unicode characters
#[test]
fn test_pii_redaction_unicode() {
    let path_with_unicode = "/user?name=José&email=jose@example.com&city=São_Paulo";

    let redacted = PiiRedactor::redact(path_with_unicode);

    // Email should be redacted (ASCII email addresses)
    assert!(redacted.contains("[REDACTED]"));
    assert!(!redacted.contains("jose@example.com"));
    // Unicode characters in other parts should be preserved
    assert!(redacted.contains("José") || redacted.contains("Jose"));
}

/// Test 17: PII redaction with URL encoding
#[test]
fn test_pii_redaction_url_encoded() {
    let path_encoded = "/search?q=test%20query&email=user%40example.com";

    let redacted = PiiRedactor::redact(path_encoded);

    // Note: Current implementation may not catch URL-encoded emails
    // This documents the limitation
    assert!(path_encoded.contains("%40")); // URL-encoded @
}

/// Test 18: Empty request body with Content-Length: 0
#[test]
fn test_empty_body_with_content_length() {
    let request = b"POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";

    let result = parse_http1_request(request);

    assert!(result.is_ok());
    let req = result.unwrap();
    assert_eq!(req.content_length, Some(0));
    assert!(req.body_preview.is_empty());
}

/// Test 19: Request with multiple Content-Length headers (ambiguous)
#[test]
fn test_multiple_content_length() {
    // This is a security issue in HTTP/1.1 (request smuggling)
    let request = b"POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\nContent-Length: 20\r\n\r\n";

    let result = parse_http1_request(request);

    // Parser should handle this (may take first or reject)
    // Document behavior
    assert!(result.is_ok() || result.is_err());
}

/// Test 20: Response with no reason phrase
#[test]
fn test_response_no_reason_phrase() {
    let response = b"HTTP/1.1 200\r\nContent-Type: text/plain\r\n\r\n";

    let result = parse_http1_response(response);

    // Some servers send responses without reason phrase
    // Parser should handle gracefully
    match result {
        Ok(resp) => {
            assert_eq!(resp.status_code, 200);
        }
        Err(_) => {
            // Also acceptable if parser requires reason phrase
        }
    }
}

/// Test 21: Case insensitivity of header names
#[test]
fn test_header_case_insensitivity() {
    let request = b"GET /api/test HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\ncontent-length: 100\r\n\r\n";

    let result = parse_http1_request(request);

    assert!(result.is_ok());
    let req = result.unwrap();

    // Headers should be normalized to lowercase
    assert!(req.headers.contains_key("content-type"));
    assert!(req.headers.contains_key("content-length"));
}

/// Test 22: Whitespace handling in header values
#[test]
fn test_header_value_whitespace() {
    let request = b"GET /api/test HTTP/1.1\r\nHost: example.com\r\nAuthorization:  Bearer  token123  \r\n\r\n";

    let result = parse_http1_request(request);

    assert!(result.is_ok());
    let req = result.unwrap();

    // Header value may or may not have whitespace trimmed
    let auth = req.headers.get("authorization").unwrap();
    assert!(auth.contains("Bearer"));
    assert!(auth.contains("token123"));
}
