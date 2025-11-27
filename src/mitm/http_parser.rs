//! HTTP Parser for MITM Inspection
//!
//! Lightweight HTTP/1.1 parser for extracting request/response metadata
//! Used for logging, filtering, and policy enforcement

use std::collections::HashMap;
use thiserror::Error;

/// HTTP parsing errors
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Invalid HTTP format")]
    InvalidFormat,

    #[error("Incomplete HTTP message")]
    Incomplete,

    #[error("Invalid method: {0}")]
    InvalidMethod(String),

    #[error("Invalid status code: {0}")]
    InvalidStatusCode(String),

    #[error("Header parse error: {0}")]
    InvalidHeader(String),

    #[error("UTF-8 decode error")]
    Utf8Error,
}

/// Parsed HTTP request
#[derive(Debug, Clone, PartialEq)]
pub struct HttpRequest {
    /// HTTP method (GET, POST, etc.)
    pub method: String,

    /// Request path (/path?query)
    pub path: String,

    /// HTTP version (HTTP/1.1, HTTP/2.0)
    pub version: String,

    /// Request headers
    pub headers: HashMap<String, String>,

    /// Body preview (first 1KB for logging, empty if no body)
    pub body_preview: String,

    /// Content-Length from header (if present)
    pub content_length: Option<usize>,
}

/// Parsed HTTP response
#[derive(Debug, Clone, PartialEq)]
pub struct HttpResponse {
    /// HTTP version (HTTP/1.1)
    pub version: String,

    /// Status code (200, 404, etc.)
    pub status_code: u16,

    /// Reason phrase (OK, Not Found, etc.)
    pub reason: String,

    /// Response headers
    pub headers: HashMap<String, String>,

    /// Body preview (first 1KB for logging, empty if no body)
    pub body_preview: String,

    /// Content-Length from header (if present)
    pub content_length: Option<usize>,
}

/// Parse HTTP/1.1 request from bytes
///
/// Expects format:
/// ```text
/// METHOD /path HTTP/1.1\r\n
/// Header: Value\r\n
/// \r\n
/// [body]
/// ```
pub fn parse_http1_request(data: &[u8]) -> Result<HttpRequest, ParseError> {
    // Find the end of headers (double CRLF)
    let header_end = find_header_end(data).ok_or(ParseError::Incomplete)?;

    // Parse headers only (always ASCII/UTF-8)
    let header_data = &data[..header_end];
    let text = std::str::from_utf8(header_data).map_err(|_| ParseError::Utf8Error)?;

    // Split into lines
    let lines: Vec<&str> = text.split("\r\n").collect();
    if lines.is_empty() {
        return Err(ParseError::InvalidFormat);
    }

    // Parse request line: METHOD /path HTTP/1.1
    let request_line = lines[0];
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(ParseError::InvalidFormat);
    }

    let method = parts[0].to_string();
    let path = parts[1].to_string();
    let version = parts[2].to_string();

    // Validate method
    if !is_valid_method(&method) {
        return Err(ParseError::InvalidMethod(method));
    }

    // Parse headers
    let (headers, _body_start_idx) = parse_headers(&lines[1..])?;

    // Extract Content-Length
    let content_length = headers.get("content-length").and_then(|v| v.parse().ok());

    // Extract body preview (first 1KB) from raw bytes after headers
    let body_start = header_end + 4; // +4 for \r\n\r\n
    let body_preview = extract_body_preview_bytes(data, body_start)?;

    Ok(HttpRequest {
        method,
        path,
        version,
        headers,
        body_preview,
        content_length,
    })
}

/// Parse HTTP/1.1 response from bytes
///
/// Expects format:
/// ```text
/// HTTP/1.1 200 OK\r\n
/// Header: Value\r\n
/// \r\n
/// [body]
/// ```
pub fn parse_http1_response(data: &[u8]) -> Result<HttpResponse, ParseError> {
    // Find the end of headers (double CRLF)
    let header_end = find_header_end(data).ok_or(ParseError::Incomplete)?;

    // Parse headers only (always ASCII/UTF-8)
    let header_data = &data[..header_end];
    let text = std::str::from_utf8(header_data).map_err(|_| ParseError::Utf8Error)?;

    // Split into lines
    let lines: Vec<&str> = text.split("\r\n").collect();
    if lines.is_empty() {
        return Err(ParseError::InvalidFormat);
    }

    // Parse status line: HTTP/1.1 200 OK
    let status_line = lines[0];
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(ParseError::InvalidFormat);
    }

    let version = parts[0].to_string();
    let status_code = parts[1]
        .parse::<u16>()
        .map_err(|_| ParseError::InvalidStatusCode(parts[1].to_string()))?;
    let reason = if parts.len() > 2 {
        parts[2].to_string()
    } else {
        String::new()
    };

    // Parse headers
    let (headers, _body_start_idx) = parse_headers(&lines[1..])?;

    // Extract Content-Length
    let content_length = headers.get("content-length").and_then(|v| v.parse().ok());

    // Extract body preview from raw bytes after headers
    let body_start = header_end + 4; // +4 for \r\n\r\n
    let body_preview = extract_body_preview_bytes(data, body_start)?;

    Ok(HttpResponse {
        version,
        status_code,
        reason,
        headers,
        body_preview,
        content_length,
    })
}

/// Parse headers from lines
///
/// Returns (headers map, body_start_line_index)
fn parse_headers(lines: &[&str]) -> Result<(HashMap<String, String>, usize), ParseError> {
    let mut headers = HashMap::new();
    let mut idx = 0;

    for (i, line) in lines.iter().enumerate() {
        // Empty line marks end of headers
        if line.is_empty() {
            idx = i + 1;
            break;
        }

        // Parse header: Name: Value
        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].trim().to_lowercase();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.insert(name, value);
        } else if !line.is_empty() {
            return Err(ParseError::InvalidHeader(line.to_string()));
        }
    }

    Ok((headers, idx))
}

/// Find the end of HTTP headers (position before \r\n\r\n)
fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

/// Extract body preview from raw bytes (handles binary data)
fn extract_body_preview_bytes(data: &[u8], body_start: usize) -> Result<String, ParseError> {
    // Check if there's a body
    if body_start >= data.len() {
        return Ok(String::new());
    }

    // Extract up to 1KB of body
    let body_data = &data[body_start..];
    let preview_len = body_data.len().min(1024);
    let preview_bytes = &body_data[..preview_len];

    // Try to convert to UTF-8 (for text content)
    match std::str::from_utf8(preview_bytes) {
        Ok(text) => Ok(text.to_string()),
        Err(_) => {
            // Binary content - return hex preview
            Ok(format!("[Binary data: {} bytes]", body_data.len()))
        }
    }
}

/// Check if method is valid
fn is_valid_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT" | "TRACE"
    )
}

impl HttpRequest {
    /// Get Content-Type header
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type").map(|s| s.as_str())
    }

    /// Check if request has body
    pub fn has_body(&self) -> bool {
        self.content_length.map(|len| len > 0).unwrap_or(false)
            || self.headers.contains_key("transfer-encoding")
    }

    /// Get host from headers
    pub fn host(&self) -> Option<&str> {
        self.headers.get("host").map(|s| s.as_str())
    }
}

impl HttpResponse {
    /// Get Content-Type header
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type").map(|s| s.as_str())
    }

    /// Check if response has body
    pub fn has_body(&self) -> bool {
        // 1xx, 204, 304 responses have no body
        if (100..200).contains(&self.status_code)
            || self.status_code == 204
            || self.status_code == 304
        {
            return false;
        }

        self.content_length.map(|len| len > 0).unwrap_or(false)
            || self.headers.contains_key("transfer-encoding")
    }

    /// Check if status is success (2xx)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    /// Check if status is error (4xx or 5xx)
    pub fn is_error(&self) -> bool {
        self.status_code >= 400
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_get_request() {
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let request = parse_http1_request(data).unwrap();

        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/path");
        assert_eq!(request.version, "HTTP/1.1");
        assert_eq!(
            request.headers.get("host"),
            Some(&"example.com".to_string())
        );
        assert_eq!(request.content_length, None);
    }

    #[test]
    fn test_parse_post_request_with_body() {
        let data =
            b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\nHello, World!";
        let request = parse_http1_request(data).unwrap();

        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/api");
        assert_eq!(request.content_length, Some(13));
        assert_eq!(request.body_preview, "Hello, World!");
    }

    #[test]
    fn test_parse_response_200() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nHello";
        let response = parse_http1_response(data).unwrap();

        assert_eq!(response.version, "HTTP/1.1");
        assert_eq!(response.status_code, 200);
        assert_eq!(response.reason, "OK");
        assert_eq!(
            response.headers.get("content-type"),
            Some(&"text/html".to_string())
        );
        assert_eq!(response.content_length, Some(5));
        assert_eq!(response.body_preview, "Hello");
    }

    #[test]
    fn test_parse_response_404() {
        let data = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let response = parse_http1_response(data).unwrap();

        assert_eq!(response.status_code, 404);
        assert_eq!(response.reason, "Not Found");
        assert!(response.is_error());
    }

    #[test]
    fn test_invalid_method() {
        let data = b"INVALID /path HTTP/1.1\r\n\r\n";
        let result = parse_http1_request(data);
        assert!(matches!(result, Err(ParseError::InvalidMethod(_))));
    }

    #[test]
    fn test_invalid_status_code() {
        let data = b"HTTP/1.1 ABC OK\r\n\r\n";
        let result = parse_http1_response(data);
        assert!(matches!(result, Err(ParseError::InvalidStatusCode(_))));
    }

    #[test]
    fn test_multiple_headers() {
        let data =
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test\r\nAccept: */*\r\n\r\n";
        let request = parse_http1_request(data).unwrap();

        assert_eq!(request.headers.len(), 3);
        assert_eq!(
            request.headers.get("host"),
            Some(&"example.com".to_string())
        );
        assert_eq!(request.headers.get("user-agent"), Some(&"Test".to_string()));
        assert_eq!(request.headers.get("accept"), Some(&"*/*".to_string()));
    }

    #[test]
    fn test_body_preview_truncation() {
        // Create a large body (2KB)
        let large_body = "X".repeat(2048);
        let data = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            large_body.len(),
            large_body
        );
        let request = parse_http1_request(data.as_bytes()).unwrap();

        // Preview should be truncated to 1KB
        assert_eq!(request.body_preview.len(), 1024);
    }

    #[test]
    fn test_request_helper_methods() {
        let data = b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{\"test\":1}";
        let request = parse_http1_request(data).unwrap();

        assert_eq!(request.content_type(), Some("application/json"));
        assert!(request.has_body());
        assert_eq!(request.host(), Some("example.com"));
    }

    #[test]
    fn test_response_helper_methods() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHello";
        let response = parse_http1_response(data).unwrap();

        assert_eq!(response.content_type(), Some("text/plain"));
        assert!(response.has_body());
        assert!(response.is_success());
        assert!(!response.is_error());
    }

    #[test]
    fn test_response_no_body_status_codes() {
        // 204 No Content
        let data = b"HTTP/1.1 204 No Content\r\n\r\n";
        let response = parse_http1_response(data).unwrap();
        assert!(!response.has_body());

        // 304 Not Modified
        let data = b"HTTP/1.1 304 Not Modified\r\n\r\n";
        let response = parse_http1_response(data).unwrap();
        assert!(!response.has_body());
    }

    #[test]
    fn test_binary_body_handling() {
        // Binary request (gzip data)
        let mut request_data = b"POST /upload HTTP/1.1\r\nContent-Type: application/gzip\r\nContent-Length: 10\r\n\r\n".to_vec();
        request_data.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]); // gzip magic bytes + binary

        let request = parse_http1_request(&request_data).unwrap();
        assert_eq!(request.method, "POST");
        assert!(request.body_preview.contains("[Binary data:"));

        // Binary response (image data)
        let mut response_data =
            b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 8\r\n\r\n".to_vec();
        response_data.extend_from_slice(&[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]); // PNG magic bytes

        let response = parse_http1_response(&response_data).unwrap();
        assert_eq!(response.status_code, 200);
        assert!(response.body_preview.contains("[Binary data:"));
    }
}
