//! HTTP Parser for Decrypted Traffic
//!
//! Parses HTTP requests and responses from decrypted TLS streams.
//! Supports both HTTP/1.1 and HTTP/2.

use crate::mitm::{MitmError, Result};
use hyper::{Body, Method, Request, Response, StatusCode, Uri, Version};
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tracing::{debug, warn};

/// HTTP Request Parser
///
/// Parses HTTP requests from decrypted TLS streams
pub struct HttpRequestParser;

impl HttpRequestParser {
    /// Parse HTTP request from stream
    pub async fn parse<R: AsyncRead + Unpin>(
        reader: R,
    ) -> Result<ParsedRequest> {
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        // Read request line (e.g., "GET /path HTTP/1.1")
        buf_reader
            .read_line(&mut line)
            .await
            .map_err(|e| MitmError::RequestParseFailed(e.to_string()))?;

        let request_line = line.trim();
        debug!("Request line: {}", request_line);

        // Parse request line
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(MitmError::RequestParseFailed(format!(
                "Invalid request line: {}",
                request_line
            )));
        }

        let method = parts[0]
            .parse::<Method>()
            .map_err(|e| MitmError::RequestParseFailed(format!("Invalid method: {}", e)))?;

        let uri = parts[1]
            .parse::<Uri>()
            .map_err(|e| MitmError::RequestParseFailed(format!("Invalid URI: {}", e)))?;

        let version = Self::parse_version(parts[2])?;

        // Read headers
        let headers = Self::parse_headers(&mut buf_reader).await?;

        // Extract content length
        let content_length = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);

        Ok(ParsedRequest {
            method,
            uri,
            version,
            headers,
            content_length,
        })
    }

    /// Parse HTTP version
    fn parse_version(version_str: &str) -> Result<Version> {
        match version_str {
            "HTTP/0.9" => Ok(Version::HTTP_09),
            "HTTP/1.0" => Ok(Version::HTTP_10),
            "HTTP/1.1" => Ok(Version::HTTP_11),
            "HTTP/2.0" => Ok(Version::HTTP_2),
            "HTTP/3.0" => Ok(Version::HTTP_3),
            _ => Err(MitmError::RequestParseFailed(format!(
                "Unsupported HTTP version: {}",
                version_str
            ))),
        }
    }

    /// Parse HTTP headers
    async fn parse_headers<R: AsyncRead + Unpin>(
        reader: &mut BufReader<R>,
    ) -> Result<HashMap<String, String>> {
        let mut headers = HashMap::new();
        let mut line = String::new();

        loop {
            line.clear();
            let bytes_read = reader
                .read_line(&mut line)
                .await
                .map_err(|e| MitmError::RequestParseFailed(e.to_string()))?;

            if bytes_read == 0 {
                break; // EOF
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                break; // End of headers
            }

            // Parse header (e.g., "Content-Type: application/json")
            if let Some(colon_pos) = trimmed.find(':') {
                let name = trimmed[..colon_pos].trim().to_lowercase();
                let value = trimmed[colon_pos + 1..].trim().to_string();
                headers.insert(name, value);
            } else {
                warn!("Invalid header line: {}", trimmed);
            }
        }

        debug!("Parsed {} headers", headers.len());
        Ok(headers)
    }
}

/// HTTP Response Parser
///
/// Parses HTTP responses from decrypted upstream connections
pub struct HttpResponseParser;

impl HttpResponseParser {
    /// Parse HTTP response from stream
    pub async fn parse<R: AsyncRead + Unpin>(
        reader: R,
    ) -> Result<ParsedResponse> {
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        // Read status line (e.g., "HTTP/1.1 200 OK")
        buf_reader
            .read_line(&mut line)
            .await
            .map_err(|e| MitmError::ResponseParseFailed(e.to_string()))?;

        let status_line = line.trim();
        debug!("Status line: {}", status_line);

        // Parse status line
        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(MitmError::ResponseParseFailed(format!(
                "Invalid status line: {}",
                status_line
            )));
        }

        let version = HttpRequestParser::parse_version(parts[0])?;

        let status_code = parts[1]
            .parse::<u16>()
            .map_err(|e| MitmError::ResponseParseFailed(format!("Invalid status code: {}", e)))?;

        let status = StatusCode::from_u16(status_code)
            .map_err(|e| MitmError::ResponseParseFailed(format!("Invalid status code: {}", e)))?;

        let reason = parts.get(2).unwrap_or(&"").to_string();

        // Read headers
        let headers = HttpRequestParser::parse_headers(&mut buf_reader).await?;

        // Extract content length
        let content_length = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);

        Ok(ParsedResponse {
            version,
            status,
            reason,
            headers,
            content_length,
        })
    }
}

/// Parsed HTTP Request
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: HashMap<String, String>,
    pub content_length: usize,
}

impl ParsedRequest {
    /// Get header value by name (case-insensitive)
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_lowercase())
    }

    /// Get host from headers
    pub fn host(&self) -> Option<&String> {
        self.get_header("host")
    }

    /// Get user agent from headers
    pub fn user_agent(&self) -> Option<&String> {
        self.get_header("user-agent")
    }

    /// Get content type from headers
    pub fn content_type(&self) -> Option<&String> {
        self.get_header("content-type")
    }

    /// Check if request expects JSON response
    pub fn accepts_json(&self) -> bool {
        self.get_header("accept")
            .map(|v| v.contains("application/json"))
            .unwrap_or(false)
    }

    /// Convert to hyper Request (without body)
    pub fn to_hyper_request(&self) -> Request<Body> {
        let mut builder = Request::builder()
            .method(self.method.clone())
            .uri(self.uri.clone())
            .version(self.version);

        for (name, value) in &self.headers {
            builder = builder.header(name, value);
        }

        builder.body(Body::empty()).expect("Failed to build request")
    }
}

/// Parsed HTTP Response
#[derive(Debug, Clone)]
pub struct ParsedResponse {
    pub version: Version,
    pub status: StatusCode,
    pub reason: String,
    pub headers: HashMap<String, String>,
    pub content_length: usize,
}

impl ParsedResponse {
    /// Get header value by name (case-insensitive)
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_lowercase())
    }

    /// Get content type from headers
    pub fn content_type(&self) -> Option<&String> {
        self.get_header("content-type")
    }

    /// Check if response is JSON
    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|v| v.contains("application/json"))
            .unwrap_or(false)
    }

    /// Check if response is HTML
    pub fn is_html(&self) -> bool {
        self.content_type()
            .map(|v| v.contains("text/html"))
            .unwrap_or(false)
    }

    /// Convert to hyper Response (without body)
    pub fn to_hyper_response(&self) -> Response<Body> {
        let mut builder = Response::builder()
            .status(self.status)
            .version(self.version);

        for (name, value) in &self.headers {
            builder = builder.header(name, value);
        }

        builder.body(Body::empty()).expect("Failed to build response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_parse_get_request() {
        let request_data = b"GET /path HTTP/1.1\r\n\
            Host: example.com\r\n\
            User-Agent: test-client\r\n\
            Accept: application/json\r\n\
            \r\n";

        let cursor = Cursor::new(request_data);
        let parsed = HttpRequestParser::parse(cursor).await.unwrap();

        assert_eq!(parsed.method, Method::GET);
        assert_eq!(parsed.uri, "/path");
        assert_eq!(parsed.version, Version::HTTP_11);
        assert_eq!(parsed.host(), Some(&"example.com".to_string()));
        assert_eq!(parsed.user_agent(), Some(&"test-client".to_string()));
        assert!(parsed.accepts_json());
    }

    #[tokio::test]
    async fn test_parse_post_request() {
        let request_data = b"POST /api/data HTTP/1.1\r\n\
            Host: api.example.com\r\n\
            Content-Type: application/json\r\n\
            Content-Length: 42\r\n\
            \r\n";

        let cursor = Cursor::new(request_data);
        let parsed = HttpRequestParser::parse(cursor).await.unwrap();

        assert_eq!(parsed.method, Method::POST);
        assert_eq!(parsed.uri, "/api/data");
        assert_eq!(parsed.content_type(), Some(&"application/json".to_string()));
        assert_eq!(parsed.content_length, 42);
    }

    #[tokio::test]
    async fn test_parse_response_200() {
        let response_data = b"HTTP/1.1 200 OK\r\n\
            Content-Type: text/html\r\n\
            Content-Length: 1234\r\n\
            Server: nginx\r\n\
            \r\n";

        let cursor = Cursor::new(response_data);
        let parsed = HttpResponseParser::parse(cursor).await.unwrap();

        assert_eq!(parsed.status, StatusCode::OK);
        assert_eq!(parsed.version, Version::HTTP_11);
        assert_eq!(parsed.content_type(), Some(&"text/html".to_string()));
        assert_eq!(parsed.content_length, 1234);
        assert!(parsed.is_html());
        assert!(!parsed.is_json());
    }

    #[tokio::test]
    async fn test_parse_response_404() {
        let response_data = b"HTTP/1.1 404 Not Found\r\n\
            Content-Type: application/json\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let cursor = Cursor::new(response_data);
        let parsed = HttpResponseParser::parse(cursor).await.unwrap();

        assert_eq!(parsed.status, StatusCode::NOT_FOUND);
        assert_eq!(parsed.reason, "Not Found");
        assert!(parsed.is_json());
    }

    #[tokio::test]
    async fn test_case_insensitive_headers() {
        let request_data = b"GET / HTTP/1.1\r\n\
            Content-Type: text/plain\r\n\
            \r\n";

        let cursor = Cursor::new(request_data);
        let parsed = HttpRequestParser::parse(cursor).await.unwrap();

        assert_eq!(parsed.get_header("content-type"), Some(&"text/plain".to_string()));
        assert_eq!(parsed.get_header("Content-Type"), Some(&"text/plain".to_string()));
        assert_eq!(parsed.get_header("CONTENT-TYPE"), Some(&"text/plain".to_string()));
    }

    #[tokio::test]
    async fn test_invalid_request_line() {
        let request_data = b"INVALID\r\n\r\n";
        let cursor = Cursor::new(request_data);
        let result = HttpRequestParser::parse(cursor).await;
        assert!(result.is_err());
    }
}
