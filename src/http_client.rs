use anyhow::Result;
use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use httparse;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{rustls, TlsConnector};
use tracing::{debug, error, warn};

use crate::config::Config;

const MAX_HEADER_SIZE: usize = 16384; // 16KB max headers
const READ_BUFFER_SIZE: usize = 8192;

#[derive(Debug, thiserror::Error)]
pub enum HttpClientError {
    #[error("All upstream IPs failed")]
    AllIpsFailed,

    #[error("Connection timeout")]
    ConnectionTimeout,

    #[error("Read timeout")]
    ReadTimeout,

    #[error("Write timeout")]
    WriteTimeout,

    #[error("Response body too large: {size} bytes (limit: {limit})")]
    ResponseTooLarge { size: usize, limit: usize },

    #[error("Headers too large (> 16KB)")]
    HeadersTooLarge,

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
}

/// Forward HTTP request to upstream with retry across all vetted IPs
pub async fn forward_request(
    vetted_ips: Vec<IpAddr>,
    port: u16,
    scheme: &str,
    method: &str,
    path: &str,
    host: &str,
    headers: &HeaderMap,
    body: Option<Bytes>,
    config: &Config,
) -> Result<(StatusCode, HeaderMap, Bytes), HttpClientError> {
    if vetted_ips.is_empty() {
        return Err(HttpClientError::AllIpsFailed);
    }

    // Shuffle IPs for load distribution
    let mut ips = vetted_ips.clone();
    ips.shuffle(&mut thread_rng());

    let mut last_error = None;

    // Try each IP until one succeeds
    for (idx, ip) in ips.iter().enumerate() {
        debug!("[HTTP Client] Trying IP {}/{}: {}", idx + 1, ips.len(), ip);

        match try_single_ip(
            *ip,
            port,
            scheme,
            method,
            path,
            host,
            headers,
            body.as_ref(),
            config,
        )
        .await
        {
            Ok(response) => {
                debug!("[HTTP Client] Success with IP {}", ip);
                return Ok(response);
            }
            Err(e) => {
                warn!("[HTTP Client] IP {} failed: {}", ip, e);
                last_error = Some(e);
                continue;
            }
        }
    }

    // All IPs failed
    error!("[HTTP Client] All {} IPs failed", ips.len());
    Err(last_error.unwrap_or(HttpClientError::AllIpsFailed))
}

/// Try a single IP address
async fn try_single_ip(
    ip: IpAddr,
    port: u16,
    scheme: &str,
    method: &str,
    path: &str,
    host: &str,
    headers: &HeaderMap,
    body: Option<&Bytes>,
    config: &Config,
) -> Result<(StatusCode, HeaderMap, Bytes), HttpClientError> {
    // 1. Connect with timeout
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(
        Duration::from_secs(config.connect_timeout_seconds),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| HttpClientError::ConnectionTimeout)?
    .map_err(HttpClientError::IoError)?;

    // 2. TLS handshake if HTTPS
    if scheme == "https" {
        let tls_config = build_tls_config()?;
        let connector = TlsConnector::from(Arc::new(tls_config));

        let server_name = rustls::pki_types::ServerName::try_from(host)
            .map_err(|e| HttpClientError::TlsError(format!("Invalid server name: {}", e)))?;

        let mut tls_stream = connector
            .connect(server_name.to_owned(), stream)
            .await
            .map_err(|e| HttpClientError::TlsError(e.to_string()))?;

        send_and_receive(&mut tls_stream, method, path, host, headers, body, config).await
    } else {
        // Plain HTTP
        send_and_receive(&mut stream, method, path, host, headers, body, config).await
    }
}

/// Send request and receive response (generic over TLS and plain TCP)
async fn send_and_receive<S>(
    stream: &mut S,
    method: &str,
    path: &str,
    host: &str,
    headers: &HeaderMap,
    body: Option<&Bytes>,
    config: &Config,
) -> Result<(StatusCode, HeaderMap, Bytes), HttpClientError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // 1. Format and send request
    let request_bytes = format_http_request(method, path, host, headers, body)?;

    timeout(
        Duration::from_secs(config.write_timeout_seconds),
        stream.write_all(&request_bytes),
    )
    .await
    .map_err(|_| HttpClientError::WriteTimeout)?
    .map_err(HttpClientError::IoError)?;

    // 2. Read and parse response
    read_http_response(stream, config).await
}

/// Format HTTP/1.1 request with proper header sanitization
fn format_http_request(
    method: &str,
    path: &str,
    host: &str,
    headers: &HeaderMap,
    body: Option<&Bytes>,
) -> Result<Bytes, HttpClientError> {
    let mut buf = BytesMut::new();

    // Request line (origin-form)
    buf.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method, path).as_bytes());

    // Host header (required)
    buf.extend_from_slice(format!("Host: {}\r\n", host).as_bytes());

    // Filter and add headers
    let filtered = filter_request_headers(headers);
    for (name, value) in &filtered {
        if let Ok(val_str) = value.to_str() {
            buf.extend_from_slice(format!("{}: {}\r\n", name, val_str).as_bytes());
        }
    }

    // Content-Length if body present
    if let Some(body) = body {
        buf.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }

    // Connection: close (we don't support keep-alive for now)
    buf.extend_from_slice(b"Connection: close\r\n");

    buf.extend_from_slice(b"\r\n");

    // Body
    if let Some(body) = body {
        buf.extend_from_slice(body);
    }

    Ok(buf.freeze())
}

/// Filter request headers - strip hop-by-hop, normalize, enforce single Host/Content-Length
fn filter_request_headers(headers: &HeaderMap) -> HeaderMap {
    let mut filtered = HeaderMap::new();
    let mut seen_host = false;
    let mut seen_content_length = false;

    for (name, value) in headers {
        let name_lower = name.as_str().to_lowercase();

        // Skip hop-by-hop headers
        if is_hop_by_hop(&name_lower) {
            continue;
        }

        // Skip headers we'll add ourselves
        if name_lower == "host" {
            if seen_host {
                warn!("[HTTP Client] Duplicate Host header, skipping");
                continue;
            }
            seen_host = true;
            continue; // We add Host ourselves
        }

        if name_lower == "content-length" {
            if seen_content_length {
                warn!("[HTTP Client] Duplicate Content-Length header, skipping");
                continue;
            }
            seen_content_length = true;
            continue; // We add Content-Length ourselves
        }

        if name_lower == "connection" {
            continue; // We set Connection: close ourselves
        }

        // Copy header
        filtered.insert(name.clone(), value.clone());
    }

    filtered
}

/// Check if header is hop-by-hop (RFC 7230 § 6.1)
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-connection"
    )
}

/// Filter response headers - strip hop-by-hop headers
fn filter_response_headers(headers: &HeaderMap) -> HeaderMap {
    let mut filtered = HeaderMap::new();

    for (name, value) in headers {
        let name_lower = name.as_str().to_lowercase();

        // Skip hop-by-hop headers
        if is_hop_by_hop(&name_lower) {
            continue;
        }

        // Copy header
        filtered.insert(name.clone(), value.clone());
    }

    filtered
}

/// Read HTTP response with proper header loop and chunked dechunking
async fn read_http_response<S>(
    stream: &mut S,
    config: &Config,
) -> Result<(StatusCode, HeaderMap, Bytes), HttpClientError>
where
    S: AsyncReadExt + Unpin,
{
    // 1. Read headers with max size limit
    let (status, response_headers, headers_end) = read_response_headers(stream, config).await?;

    // 2. Check if response is chunked
    let is_chunked = response_headers
        .get("transfer-encoding")
        .and_then(|te| te.to_str().ok())
        .map(|te| te.to_lowercase().contains("chunked"))
        .unwrap_or(false);

    // 3. Read body based on Content-Length or chunked encoding
    let body = read_response_body(
        stream,
        &response_headers,
        headers_end,
        config.max_response_body_size,
        config.read_timeout_seconds,
    )
    .await?;

    // 4. Filter response headers and fix Content-Length if dechunked
    let mut filtered_headers = filter_response_headers(&response_headers);

    if is_chunked {
        // We dechunked the body, so set Content-Length
        filtered_headers.insert(
            "content-length",
            HeaderValue::from_str(&body.len().to_string()).unwrap(),
        );
    }

    Ok((status, filtered_headers, body))
}

/// Read response headers with looped read until \r\n\r\n
async fn read_response_headers<S>(
    stream: &mut S,
    config: &Config,
) -> Result<(StatusCode, HeaderMap, BytesMut), HttpClientError>
where
    S: AsyncReadExt + Unpin,
{
    let mut header_buf = BytesMut::with_capacity(READ_BUFFER_SIZE);
    let mut headers_complete = false;

    // Loop until we have complete headers
    while !headers_complete && header_buf.len() < MAX_HEADER_SIZE {
        let mut buf = vec![0u8; READ_BUFFER_SIZE];

        let n = timeout(
            Duration::from_secs(config.read_timeout_seconds),
            stream.read(&mut buf),
        )
        .await
        .map_err(|_| HttpClientError::ReadTimeout)?
        .map_err(HttpClientError::IoError)?;

        if n == 0 {
            return Err(HttpClientError::InvalidResponse(
                "Connection closed".to_string(),
            ));
        }

        header_buf.extend_from_slice(&buf[..n]);

        // Check for end of headers (\r\n\r\n)
        if find_header_end(&header_buf).is_some() {
            headers_complete = true;
        }
    }

    if !headers_complete {
        return Err(HttpClientError::HeadersTooLarge);
    }

    // Parse headers with httparse
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);

    let headers_len = match response.parse(&header_buf)? {
        httparse::Status::Complete(len) => len,
        httparse::Status::Partial => {
            return Err(HttpClientError::InvalidResponse(
                "Incomplete headers".to_string(),
            ));
        }
    };

    let status = StatusCode::from_u16(response.code.unwrap_or(500))
        .map_err(|e| HttpClientError::InvalidResponse(format!("Invalid status code: {}", e)))?;

    // Convert headers
    let mut header_map = HeaderMap::new();
    for h in response.headers {
        if let Ok(name) = HeaderName::from_bytes(h.name.as_bytes()) {
            if let Ok(value) = HeaderValue::from_bytes(h.value) {
                header_map.insert(name, value);
            }
        }
    }

    // Return status, headers, and any body bytes that came with headers
    let remaining = header_buf.split_off(headers_len);
    Ok((status, header_map, remaining))
}

/// Find \r\n\r\n in buffer
fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

/// Read response body (handle Content-Length and chunked encoding)
async fn read_response_body<S>(
    stream: &mut S,
    headers: &HeaderMap,
    initial_bytes: BytesMut,
    max_size: usize,
    read_timeout_secs: u64,
) -> Result<Bytes, HttpClientError>
where
    S: AsyncReadExt + Unpin,
{
    // Check for Transfer-Encoding: chunked
    if let Some(te) = headers.get("transfer-encoding") {
        if te.to_str().unwrap_or("").to_lowercase().contains("chunked") {
            return read_chunked_body(stream, initial_bytes, max_size, read_timeout_secs).await;
        }
    }

    // Check for Content-Length
    if let Some(cl) = headers.get("content-length") {
        if let Ok(cl_str) = cl.to_str() {
            if let Ok(content_length) = cl_str.parse::<usize>() {
                if content_length > max_size {
                    return Err(HttpClientError::ResponseTooLarge {
                        size: content_length,
                        limit: max_size,
                    });
                }

                return read_content_length_body(
                    stream,
                    initial_bytes,
                    content_length,
                    max_size,
                    read_timeout_secs,
                )
                .await;
            }
        }
    }

    // No Content-Length or Transfer-Encoding - read until EOF
    read_until_eof(stream, initial_bytes, max_size, read_timeout_secs).await
}

/// Read body with known Content-Length
async fn read_content_length_body<S>(
    stream: &mut S,
    mut body: BytesMut,
    content_length: usize,
    max_size: usize,
    read_timeout_secs: u64,
) -> Result<Bytes, HttpClientError>
where
    S: AsyncReadExt + Unpin,
{
    while body.len() < content_length {
        let mut buf = vec![0u8; READ_BUFFER_SIZE];

        let n = timeout(
            Duration::from_secs(read_timeout_secs),
            stream.read(&mut buf),
        )
        .await
        .map_err(|_| HttpClientError::ReadTimeout)?
        .map_err(HttpClientError::IoError)?;

        if n == 0 {
            // EOF before reading full body - this is an error
            return Err(HttpClientError::InvalidResponse(format!(
                "Premature EOF: expected {} bytes, got {} bytes",
                content_length,
                body.len()
            )));
        }

        body.extend_from_slice(&buf[..n]);

        if body.len() > max_size {
            return Err(HttpClientError::ResponseTooLarge {
                size: body.len(),
                limit: max_size,
            });
        }
    }

    Ok(body.freeze())
}

/// Read chunked body and dechunk it (RFC 7230 compliant)
async fn read_chunked_body<S>(
    stream: &mut S,
    mut buf: BytesMut,
    max_size: usize,
    read_timeout_secs: u64,
) -> Result<Bytes, HttpClientError>
where
    S: AsyncReadExt + Unpin,
{
    let mut dechunked = BytesMut::new();

    loop {
        // Read chunk size line (must end with CRLF)
        while !contains_crlf(&buf) {
            let mut tmp = vec![0u8; READ_BUFFER_SIZE];
            let n = timeout(
                Duration::from_secs(read_timeout_secs),
                stream.read(&mut tmp),
            )
            .await
            .map_err(|_| HttpClientError::ReadTimeout)?
            .map_err(HttpClientError::IoError)?;

            if n == 0 {
                return Err(HttpClientError::InvalidResponse(
                    "Incomplete chunk size line".to_string(),
                ));
            }

            buf.extend_from_slice(&tmp[..n]);
        }

        // Find CRLF position
        let crlf_pos = find_crlf(&buf).unwrap();
        let size_line = &buf[..crlf_pos];

        // Parse chunk size (may have extensions like "A5;name=value")
        let size_str = std::str::from_utf8(size_line).map_err(|_| {
            HttpClientError::InvalidResponse("Invalid chunk size encoding".to_string())
        })?;

        // Strip chunk extensions (everything after semicolon)
        let size_only = size_str.split(';').next().unwrap_or(size_str).trim();

        let chunk_size = usize::from_str_radix(size_only, 16).map_err(|_| {
            HttpClientError::InvalidResponse(format!("Invalid chunk size hex: {}", size_only))
        })?;

        buf.advance(crlf_pos + 2); // Skip size line + CRLF

        if chunk_size == 0 {
            // Last chunk - consume trailers if any
            consume_trailers(&mut buf, stream, read_timeout_secs).await?;
            break;
        }

        // Read chunk data + trailing CRLF
        let total_needed = chunk_size + 2; // +2 for trailing CRLF
        while buf.len() < total_needed {
            let mut tmp = vec![0u8; READ_BUFFER_SIZE];
            let n = timeout(
                Duration::from_secs(read_timeout_secs),
                stream.read(&mut tmp),
            )
            .await
            .map_err(|_| HttpClientError::ReadTimeout)?
            .map_err(HttpClientError::IoError)?;

            if n == 0 {
                return Err(HttpClientError::InvalidResponse(format!(
                    "Incomplete chunk data: expected {} bytes",
                    chunk_size
                )));
            }

            buf.extend_from_slice(&tmp[..n]);
        }

        // Verify trailing CRLF
        if &buf[chunk_size..chunk_size + 2] != b"\r\n" {
            return Err(HttpClientError::InvalidResponse(
                "Missing CRLF after chunk data".to_string(),
            ));
        }

        // Extract chunk data
        dechunked.extend_from_slice(&buf[..chunk_size]);
        buf.advance(chunk_size + 2); // Skip data + CRLF

        if dechunked.len() > max_size {
            return Err(HttpClientError::ResponseTooLarge {
                size: dechunked.len(),
                limit: max_size,
            });
        }
    }

    Ok(dechunked.freeze())
}

/// Check if buffer contains CRLF
fn contains_crlf(buf: &[u8]) -> bool {
    find_crlf(buf).is_some()
}

/// Find CRLF position in buffer
fn find_crlf(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(1) {
        if &buf[i..i + 2] == b"\r\n" {
            return Some(i);
        }
    }
    None
}

/// Consume chunk trailers (headers after last chunk)
async fn consume_trailers<S>(
    buf: &mut BytesMut,
    stream: &mut S,
    read_timeout_secs: u64,
) -> Result<(), HttpClientError>
where
    S: AsyncReadExt + Unpin,
{
    // Read until we find the final CRLF (empty line)
    while !buf.starts_with(b"\r\n") {
        // Check if we have a complete trailer line
        if contains_crlf(buf) {
            let crlf_pos = find_crlf(buf).unwrap();
            buf.advance(crlf_pos + 2); // Consume trailer line
        } else {
            // Need more data
            let mut tmp = vec![0u8; READ_BUFFER_SIZE];
            let n = timeout(
                Duration::from_secs(read_timeout_secs),
                stream.read(&mut tmp),
            )
            .await
            .map_err(|_| HttpClientError::ReadTimeout)?
            .map_err(HttpClientError::IoError)?;

            if n == 0 {
                return Err(HttpClientError::InvalidResponse(
                    "Incomplete trailers".to_string(),
                ));
            }

            buf.extend_from_slice(&tmp[..n]);
        }
    }

    // Consume final CRLF
    buf.advance(2);
    Ok(())
}

/// Read until EOF (no Content-Length)
async fn read_until_eof<S>(
    stream: &mut S,
    mut body: BytesMut,
    max_size: usize,
    read_timeout_secs: u64,
) -> Result<Bytes, HttpClientError>
where
    S: AsyncReadExt + Unpin,
{
    loop {
        let mut buf = vec![0u8; READ_BUFFER_SIZE];

        let n = timeout(
            Duration::from_secs(read_timeout_secs),
            stream.read(&mut buf),
        )
        .await
        .map_err(|_| HttpClientError::ReadTimeout)?
        .map_err(HttpClientError::IoError)?;

        if n == 0 {
            break; // EOF
        }

        body.extend_from_slice(&buf[..n]);

        if body.len() > max_size {
            return Err(HttpClientError::ResponseTooLarge {
                size: body.len(),
                limit: max_size,
            });
        }
    }

    Ok(body.freeze())
}

/// Build TLS client config
fn build_tls_config() -> Result<rustls::ClientConfig, HttpClientError> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Enforce HTTP/1.1 only (no HTTP/2)
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    // DISABLE_TLS_VERIFY_NONPROD for testing/development only
    // Requires explicit _NONPROD suffix to prevent accidental production use
    if std::env::var("DISABLE_TLS_VERIFY_NONPROD").is_ok() {
        // Check for production environment - refuse to start if detected
        let environment = std::env::var("ENVIRONMENT")
            .or_else(|_| std::env::var("ENV"))
            .unwrap_or_else(|_| "unknown".to_string())
            .to_lowercase();

        if environment.contains("prod") || environment == "production" {
            panic!(
                "🚨 FATAL: DISABLE_TLS_VERIFY_NONPROD is set but ENVIRONMENT={} 🚨\n\
                 TLS verification CANNOT be disabled in production.\n\
                 Remove DISABLE_TLS_VERIFY_NONPROD or change ENVIRONMENT to proceed.",
                environment
            );
        }

        error!("🚨 TLS CERTIFICATE VERIFICATION DISABLED 🚨");
        error!("This is EXTREMELY DANGEROUS and should ONLY be used in development/testing");
        error!("NEVER use DISABLE_TLS_VERIFY_NONPROD in production!");
        error!("All TLS connections are vulnerable to MITM attacks");
        error!("Current ENVIRONMENT: {}", environment);

        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertVerifier));
    }

    Ok(config)
}

/// No-op certificate verifier (ONLY FOR TESTING)
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

impl From<httparse::Error> for HttpClientError {
    fn from(e: httparse::Error) -> Self {
        HttpClientError::InvalidResponse(e.to_string())
    }
}
