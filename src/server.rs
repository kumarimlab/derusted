use anyhow::Result;
use bytes::BytesMut;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::{debug, error, info, warn};

use crate::auth::AuthError;
use crate::config::Config;
use crate::rate_limiter::RateLimitError;

/// Parse and validate CONNECT authority (host:port)
/// Returns (host, port) or error message
fn parse_authority(authority: &str) -> Result<(String, u16), String> {
    // Split by last colon to handle IPv6 addresses like [::1]:443
    let parts: Vec<&str> = authority.rsplitn(2, ':').collect();

    if parts.len() != 2 {
        return Err("Authority must be in host:port format".to_string());
    }

    let port_str = parts[0];
    let host = parts[1];

    // Validate host is not empty
    if host.is_empty() {
        return Err("Host cannot be empty".to_string());
    }

    // Parse and validate port
    let port: u16 = port_str.parse().map_err(|_| {
        format!(
            "Invalid port '{}': must be a number between 1 and 65535",
            port_str
        )
    })?;

    // Validate port is in valid range (1-65535)
    if port == 0 {
        return Err("Invalid port: must be between 1 and 65535".to_string());
    }

    Ok((host.to_string(), port))
}

/// Serve HTTP/2 connections using direct h2 crate
/// Phase 4: Direct h2::server implementation for Extended CONNECT support
pub async fn serve_h2(tls_stream: TlsStream<TcpStream>, config: Arc<Config>) -> Result<()> {
    info!("HTTP/2 connection handler started");

    // Phase 4.1: Create h2 server connection with h2::server::Builder
    let mut h2_conn = h2::server::Builder::new()
        .initial_window_size(65535) // 64KB per stream
        .initial_connection_window_size(1024 * 1024) // 1MB connection window
        .max_concurrent_streams(100) // Limit concurrent streams
        .max_frame_size(16384) // 16KB frame size
        .handshake(tls_stream)
        .await
        .map_err(|e| anyhow::anyhow!("HTTP/2 handshake failed: {}", e))?;

    info!("HTTP/2 handshake complete, accepting streams");

    // Phase 4.2: Accept and process streams
    while let Some(result) = h2_conn.accept().await {
        match result {
            Ok((request, mut respond)) => {
                let config = Arc::clone(&config);

                // Spawn task to handle each stream independently
                tokio::spawn(async move {
                    let method = request.method().clone();
                    let uri = request.uri().clone();

                    let result = if method == Method::CONNECT {
                        handle_h2_connect(request, respond, config).await
                    } else if config.http_proxy_enabled {
                        // Forward HTTP requests (GET, POST, etc.) if HTTP proxy is enabled
                        handle_h2_http_request(request, respond, config).await
                    } else {
                        // For non-CONNECT methods when HTTP proxy is disabled, return 204 No Content (stub response)
                        info!("[H2] Non-CONNECT {} request for {} - HTTP forwarding disabled, returning 204", method, uri);
                        let response = Response::builder()
                            .status(StatusCode::NO_CONTENT)
                            .body(())
                            .unwrap();

                        match respond.send_response(response, true) {
                            Ok(_) => Ok(()),
                            Err(e) => {
                                error!("[H2] Failed to send stub response: {}", e);
                                Err(anyhow::anyhow!("Failed to send response: {}", e))
                            }
                        }
                    };

                    if let Err(e) = result {
                        error!("[H2] Stream handler error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("[H2] Error accepting stream: {}", e);
                break;
            }
        }
    }

    info!("HTTP/2 connection closed");
    Ok(())
}

/// Handle HTTP/2 regular HTTP requests (GET, POST, etc.) on a single stream
/// This handles plain HTTP traffic and Chrome's connectivity checks over HTTP/2
async fn handle_h2_http_request(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    config: Arc<Config>,
) -> Result<()> {
    let start_time = std::time::Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();

    // Phase 1: Validate method (block TRACE for security)
    if method == Method::TRACE {
        warn!("[H2 HTTP] Blocked TRACE method (XST prevention)");
        send_h2_error(
            &mut respond,
            StatusCode::METHOD_NOT_ALLOWED,
            "TRACE method not allowed",
        )
        .await?;
        return Ok(());
    }

    // Phase 2: Parse absolute-form URI
    let target_url = uri.to_string();
    if uri.scheme().is_none() || uri.authority().is_none() {
        warn!(
            "[H2 HTTP] Invalid proxy request URI (missing scheme/authority): {}",
            target_url
        );
        send_h2_error(
            &mut respond,
            StatusCode::BAD_REQUEST,
            "Proxy requests must use absolute-form URI",
        )
        .await?;
        return Ok(());
    }

    let scheme = uri.scheme_str().unwrap_or("http");
    let authority = uri.authority().unwrap().as_str();

    info!(
        "[H2 HTTP] {} request for {} (scheme={}, authority={})",
        method, target_url, scheme, authority
    );

    // Phase 3: Authentication
    let claims = match config.jwt_validator.validate_request(&request) {
        Ok(claims) => claims,
        Err(e) => {
            return handle_h2_auth_error(e, &target_url, start_time, &mut respond).await;
        }
    };

    debug!(
        "[H2 HTTP] Authenticated {} - user_id={}, token_id={}",
        target_url, claims.user_id, claims.token_id
    );

    // Phase 4: Rate limiting
    match config.rate_limiter.check_limit(&claims.token_id).await {
        Ok(()) => {}
        Err(e) => {
            return handle_h2_rate_limit_error(
                e,
                &target_url,
                &claims.token_id,
                start_time,
                &mut respond,
            )
            .await;
        }
    };

    // Phase 5: Extract headers BEFORE consuming request body
    let request_headers = request.headers().clone();

    // Phase 6: Extract request body
    let mut recv_stream = request.into_body();
    let mut body_bytes = BytesMut::new();

    while let Some(chunk) = recv_stream.data().await {
        match chunk {
            Ok(data) => {
                recv_stream.flow_control().release_capacity(data.len()).ok();
                body_bytes.extend_from_slice(&data);
            }
            Err(e) => {
                error!("[H2 HTTP] Error reading request body: {}", e);
                send_h2_error(
                    &mut respond,
                    StatusCode::BAD_REQUEST,
                    "Failed to read request body",
                )
                .await?;
                return Ok(());
            }
        }
    }

    // Phase 6: Build upstream HTTP client
    // Disable automatic redirect following to avoid redirect loops when sites redirect HTTP→HTTPS
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!("[H2 HTTP] Failed to create HTTP client: {}", e);
            send_h2_error(
                &mut respond,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
            )
            .await?;
            return Ok(());
        }
    };

    // Phase 7: Build upstream request (convert method to avoid type mismatch)
    let method_str = method.as_str();
    let upstream_method = reqwest::Method::from_bytes(method_str.as_bytes())
        .map_err(|e| anyhow::anyhow!("Invalid HTTP method: {}", e))?;
    let mut upstream_req = client.request(upstream_method, &target_url);

    // Add request body if present
    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes.to_vec());
    }

    // Phase 8: Copy headers (filter hop-by-hop headers)
    // Hop-by-hop headers that should NOT be forwarded (per RFC 7540 Section 8.1.2.2)
    let hop_by_hop_headers = [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authorization", // Already validated, don't forward
        "transfer-encoding",
        "upgrade",
        "te", // Except "trailers"
    ];

    debug!("[H2 HTTP] Request headers received: {:?}", request_headers);

    for (name, value) in request_headers.iter() {
        let name_str = name.as_str();

        // Skip hop-by-hop headers
        if hop_by_hop_headers.contains(&name_str) {
            continue;
        }

        // Skip HTTP/2 pseudo-headers (start with ':')
        if name_str.starts_with(':') {
            continue;
        }

        // Forward all other headers
        if let Ok(header_value) = value.to_str() {
            debug!(
                "[H2 HTTP] Forwarding header: {}: {}",
                name_str, header_value
            );
            upstream_req = upstream_req.header(name_str, header_value);
        }
    }

    // Ensure Host header is set (required by HTTP/1.1)
    // Always set from authority since HTTP/2 uses :authority pseudo-header
    upstream_req = upstream_req.header("host", authority);
    debug!("[H2 HTTP] Set Host header to: {}", authority);

    // Phase 9: Send request to upstream
    let upstream_response = match upstream_req.send().await {
        Ok(resp) => resp,
        Err(e) => {
            error!(
                "[H2 HTTP] Failed to connect to upstream {}: {}",
                target_url, e
            );

            config
                .request_logger
                .log_request(
                    claims.token_id.clone(),
                    claims.user_id as i32,
                    method.as_str().to_string(),
                    target_url.clone(),
                    Some(502),
                    0,
                    Some(start_time.elapsed().as_millis() as i64),
                    false,
                    false,
                    Some(format!("Connection failed: {}", e)),
                )
                .await;

            send_h2_error(
                &mut respond,
                StatusCode::BAD_GATEWAY,
                "Failed to connect to upstream",
            )
            .await?;
            return Ok(());
        }
    };

    let status = upstream_response.status();
    let upstream_headers = upstream_response.headers().clone();

    // Phase 10: Read response body
    let response_bytes = match upstream_response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("[H2 HTTP] Failed to read response body: {}", e);
            send_h2_error(
                &mut respond,
                StatusCode::BAD_GATEWAY,
                "Failed to read response body",
            )
            .await?;
            return Ok(());
        }
    };

    let total_bytes = response_bytes.len();
    let duration = start_time.elapsed();

    // Phase 11: Build HTTP/2 response
    // Convert reqwest::StatusCode to http::StatusCode via u16
    let status_code =
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response_builder = Response::builder().status(status_code);

    // Copy response headers (filter hop-by-hop)
    for (name, value) in &upstream_headers {
        let name_str = name.as_str().to_lowercase();
        if matches!(
            name_str.as_str(),
            "connection" | "keep-alive" | "te" | "trailer" | "transfer-encoding" | "upgrade"
        ) {
            continue;
        }

        // Convert reqwest headers to http headers via string
        if let Ok(value_str) = value.to_str() {
            response_builder = response_builder.header(name.as_str(), value_str);
        }
    }

    let response = response_builder.body(()).unwrap();

    // Send response headers
    let mut send_stream = match respond.send_response(response, false) {
        Ok(stream) => stream,
        Err(e) => {
            error!("[H2 HTTP] Failed to send response headers: {}", e);
            return Err(anyhow::anyhow!("Failed to send response: {}", e));
        }
    };

    // Send response body
    if !response_bytes.is_empty() {
        if let Err(e) = send_stream.send_data(response_bytes.clone(), true) {
            error!("[H2 HTTP] Failed to send response body: {}", e);
            return Err(anyhow::anyhow!("Failed to send body: {}", e));
        }
    } else {
        // Send empty body with END_STREAM
        if let Err(e) = send_stream.send_data(Bytes::new(), true) {
            error!("[H2 HTTP] Failed to close stream: {}", e);
        }
    }

    // Phase 12: Log successful request
    config
        .request_logger
        .log_request(
            claims.token_id.clone(),
            claims.user_id as i32,
            method.as_str().to_string(),
            target_url.clone(),
            Some(status.as_u16() as i32),
            total_bytes as i64,
            Some(duration.as_millis() as i64),
            true,
            false,
            None,
        )
        .await;

    info!(
        "[H2 HTTP] Completed {} {} - user_id={}, token_id={}, status={}, duration={:?}, bytes={}",
        method,
        target_url,
        claims.user_id,
        claims.token_id,
        status.as_u16(),
        duration,
        total_bytes
    );

    Ok(())
}

/// Handle HTTP/2 CONNECT request on a single stream
/// Phase 4: Complete CONNECT handler with auth, rate limiting, and tunneling
async fn handle_h2_connect(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    config: Arc<Config>,
) -> Result<()> {
    let start_time = std::time::Instant::now();

    // Phase 4.4: Extract and validate authority
    let target_host = match request.uri().authority() {
        Some(auth) => auth.to_string(),
        None => {
            warn!("[H2] Missing authority in CONNECT request");
            send_h2_error(
                &mut respond,
                StatusCode::BAD_REQUEST,
                "Bad Request: CONNECT requires a valid host:port authority",
            )
            .await?;
            return Ok(());
        }
    };

    // Validate authority format (reuse parse_authority from HTTP/1.1)
    let (_host, _port) = match parse_authority(&target_host) {
        Ok((h, p)) => (h, p),
        Err(err_msg) => {
            warn!("[H2] Invalid authority {}: {}", target_host, err_msg);
            send_h2_error(
                &mut respond,
                StatusCode::BAD_REQUEST,
                &format!("Bad Request: {}", err_msg),
            )
            .await?;
            return Ok(());
        }
    };

    // Phase 4.5: JWT Authentication
    let claims = match config.jwt_validator.validate_request(&request) {
        Ok(claims) => claims,
        Err(e) => {
            return handle_h2_auth_error(e, &target_host, start_time, &mut respond).await;
        }
    };

    info!(
        "[H2 CONNECT] Authenticated {} - user_id={}, token_id={}, regions={:?}",
        target_host, claims.user_id, claims.token_id, claims.allowed_regions
    );

    // Phase 4.6: Rate Limiting
    match config.rate_limiter.check_limit(&claims.token_id).await {
        Ok(()) => {}
        Err(e) => {
            return handle_h2_rate_limit_error(
                e,
                &target_host,
                &claims.token_id,
                start_time,
                &mut respond,
            )
            .await;
        }
    };

    // Phase 4.7: Connect to upstream
    let upstream = match tokio::net::TcpStream::connect(&target_host).await {
        Ok(stream) => stream,
        Err(e) => {
            let duration = start_time.elapsed();
            error!(
                "[H2 CONNECT] Failed to connect to {} - user_id={}, token_id={}, error={}, duration={:?}",
                target_host, claims.user_id, claims.token_id, e, duration
            );
            send_h2_error(
                &mut respond,
                StatusCode::BAD_GATEWAY,
                "Failed to connect to upstream server",
            )
            .await?;
            return Ok(());
        }
    };

    info!(
        "[H2 CONNECT] Connected to {} - user_id={}, token_id={}",
        target_host, claims.user_id, claims.token_id
    );

    // Phase 4.8: Send 200 Connection Established and get SendStream
    let response = Response::builder().status(StatusCode::OK).body(()).unwrap();

    let send_stream = match respond.send_response(response, false) {
        Ok(stream) => stream,
        Err(e) => {
            error!("[H2 CONNECT] Failed to send response: {}", e);
            return Err(anyhow::anyhow!("Failed to send 200 response: {}", e));
        }
    };

    // Phase 4.9: Extract RecvStream from request body
    let recv_stream = request.into_body();

    info!(
        "[H2 CONNECT] Starting tunnel for {} - user_id={}, token_id={}",
        target_host, claims.user_id, claims.token_id
    );

    // Phase 4.10: Spawn tunnel task
    let config_for_tunnel = Arc::clone(&config);
    tokio::spawn(async move {
        match tunnel_h2_streams(
            recv_stream,
            send_stream,
            upstream,
            target_host.clone(),
            claims.user_id,
            claims.token_id.clone(),
            start_time,
        )
        .await
        {
            Ok((bytes_sent, bytes_received)) => {
                let duration = start_time.elapsed();
                let total_bytes = bytes_sent + bytes_received;
                info!(
                    "[H2 CONNECT] Completed {} - user_id={}, token_id={}, duration={:?}, \
                     client→upstream={} bytes, upstream→client={} bytes, total={} bytes",
                    target_host,
                    claims.user_id,
                    claims.token_id,
                    duration,
                    bytes_sent,
                    bytes_received,
                    total_bytes
                );

                // Log request to backend (best-effort, non-blocking)
                config_for_tunnel
                    .request_logger
                    .log_request(
                        claims.token_id.clone(),
                        claims.user_id,
                        "CONNECT".to_string(),
                        target_host.clone(),
                        Some(200), // HTTP/2 CONNECT returns 200 on success
                        total_bytes as i64,
                        Some(duration.as_millis() as i64),
                        true,  // success = true
                        false, // rate_limited = false (made it through tunnel)
                        None,  // no error
                    )
                    .await;
            }
            Err(e) => {
                error!(
                    "[H2 CONNECT] Tunnel error for {} - user_id={}, token_id={}, error={}",
                    target_host, claims.user_id, claims.token_id, e
                );
            }
        }
    });

    Ok(())
}

/// Send error response for HTTP/2 stream
/// Phase 4 Audit Fix: Add descriptive error bodies matching HTTP/1.1 behavior
async fn send_h2_error(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: StatusCode,
    message: &str,
) -> Result<()> {
    let response = Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(())
        .unwrap();

    let mut send_stream = respond
        .send_response(response, false)
        .map_err(|e| anyhow::anyhow!("Failed to send error response: {}", e))?;

    // Send error message as body
    let body = Bytes::from(message.to_string());
    send_stream
        .send_data(body, true)
        .map_err(|e| anyhow::anyhow!("Failed to send error body: {}", e))?;

    Ok(())
}

/// Handle HTTP/2 authentication errors
/// Phase 4 Audit Fix: Send descriptive error bodies
async fn handle_h2_auth_error(
    error: AuthError,
    target_host: &str,
    start_time: std::time::Instant,
    respond: &mut h2::server::SendResponse<Bytes>,
) -> Result<()> {
    let duration = start_time.elapsed();

    let (status, message) = match error {
        AuthError::MissingHeader => {
            warn!(
                "[H2 CONNECT] Missing Proxy-Authorization for {} (duration={:?})",
                target_host, duration
            );
            (StatusCode::PROXY_AUTHENTICATION_REQUIRED, "Proxy authentication required. Please provide a valid Bearer token in the Proxy-Authorization header.")
        }
        AuthError::InvalidFormat => {
            warn!(
                "[H2 CONNECT] Invalid auth format for {} (duration={:?})",
                target_host, duration
            );
            (
                StatusCode::BAD_REQUEST,
                "Invalid Proxy-Authorization format. Expected: Bearer <token>",
            )
        }
        AuthError::TokenExpired => {
            warn!(
                "[H2 CONNECT] Expired token for {} (duration={:?})",
                target_host, duration
            );
            (
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "Token expired. Please obtain a new authentication token.",
            )
        }
        AuthError::ValidationFailed(ref msg) => {
            warn!(
                "[H2 CONNECT] Token validation failed for {}: {} (duration={:?})",
                target_host, msg, duration
            );
            (
                StatusCode::FORBIDDEN,
                "Token validation failed. The provided token is invalid.",
            )
        }
        AuthError::RegionNotAllowed(ref msg) => {
            warn!(
                "[H2 CONNECT] Region not allowed for {}: {} (duration={:?})",
                target_host, msg, duration
            );
            (
                StatusCode::FORBIDDEN,
                "Access denied: Region not in allowed list for this token.",
            )
        }
    };

    // Build response with Proxy-Authenticate header for 407 and content-type
    let mut response = Response::builder()
        .status(status)
        .header("content-type", "text/plain");

    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response = response.header(
            "proxy-authenticate",
            "Basic realm=\"ProbeOps Forward Proxy\"",
        );
    }

    let response = response.body(()).unwrap();
    let mut send_stream = respond
        .send_response(response, false)
        .map_err(|e| anyhow::anyhow!("Failed to send auth error response: {}", e))?;

    // Send descriptive error body
    let body = Bytes::from(message.to_string());
    send_stream
        .send_data(body, true)
        .map_err(|e| anyhow::anyhow!("Failed to send auth error body: {}", e))?;

    Ok(())
}

/// Handle HTTP/2 rate limit errors
/// Phase 4 Audit Fix: Send descriptive error bodies
async fn handle_h2_rate_limit_error(
    error: RateLimitError,
    target_host: &str,
    token_id: &str,
    start_time: std::time::Instant,
    respond: &mut h2::server::SendResponse<Bytes>,
) -> Result<()> {
    let duration = start_time.elapsed();

    let (status, message): (StatusCode, String) = match error {
        RateLimitError::LimitExceeded(_) => {
            warn!(
                "[H2 CONNECT] Rate limit exceeded for {} - token_id={} (duration={:?})",
                target_host, token_id, duration
            );
            (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded. Please retry after a short delay.".to_string(),
            )
        }
        RateLimitError::TooManyTokens(max) => {
            error!(
                "[H2 CONNECT] Too many tokens for {} - max={} (duration={:?})",
                target_host, max, duration
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "Service temporarily unavailable. Maximum {} concurrent tokens reached.",
                    max
                ),
            )
        }
    };

    let response = Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(())
        .unwrap();

    let mut send_stream = respond
        .send_response(response, false)
        .map_err(|e| anyhow::anyhow!("Failed to send rate limit error response: {}", e))?;

    // Send descriptive error body
    let body = Bytes::from(message);
    send_stream
        .send_data(body, true)
        .map_err(|e| anyhow::anyhow!("Failed to send rate limit error body: {}", e))?;

    Ok(())
}

/// Send data to client with proper HTTP/2 flow control
/// Phase 4 Addendum: Implements async capacity polling per addendum specification
async fn send_with_flow_control(
    send_stream: &mut h2::SendStream<Bytes>,
    data: Bytes,
    len: usize,
) -> Result<()> {
    use tokio::time::{sleep, Duration};

    // Reserve capacity (signals intent to send)
    send_stream.reserve_capacity(len);

    // Poll for available capacity with exponential backoff
    let mut backoff = Duration::from_millis(10);
    let max_backoff = Duration::from_millis(500);
    let mut attempts = 0;
    let max_attempts = 100; // ~50 seconds max wait

    loop {
        let available = send_stream.capacity();

        if available >= len {
            // Sufficient capacity - send immediately
            send_stream
                .send_data(data, false)
                .map_err(|e| anyhow::anyhow!("Failed to send data: {}", e))?;
            return Ok(());
        }

        // Check if stream was closed/reset
        if available == 0 && attempts > 10 {
            // After some attempts, check if we're making progress
            // h2 doesn't have is_closed(), so we try send and catch error
            match send_stream.send_data(Bytes::new(), false) {
                Ok(_) => {
                    // Stream still open, continue waiting
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Stream closed or reset: {}", e));
                }
            }
        }

        if attempts >= max_attempts {
            return Err(anyhow::anyhow!(
                "Flow control timeout: needed {} bytes, available {} after {} attempts",
                len,
                available,
                attempts
            ));
        }

        // Wait for WINDOW_UPDATE with exponential backoff
        if attempts % 10 == 0 {
            debug!(
                "Waiting for capacity: need={}, available={}, attempt={}, backoff={:?}",
                len, available, attempts, backoff
            );
        }

        sleep(backoff).await;

        // Exponential backoff (capped at max)
        backoff = (backoff * 2).min(max_backoff);
        attempts += 1;
    }
}

/// Bidirectional tunnel for HTTP/2 streams
/// Phase 4: Copy data between h2 streams and TCP upstream
async fn tunnel_h2_streams(
    mut recv_stream: h2::RecvStream,
    mut send_stream: h2::SendStream<Bytes>,
    upstream: TcpStream,
    target_host: String,
    user_id: i32,
    token_id: String,
    start_time: std::time::Instant,
) -> Result<(u64, u64)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let mut bytes_client_to_upstream = 0u64;
    let mut bytes_upstream_to_client = 0u64;
    let mut upstream_buf = vec![0u8; 16384]; // 16KB buffer

    loop {
        tokio::select! {
            // Client → Upstream (via RecvStream)
            result = recv_stream.data() => {
                match result {
                    Some(Ok(data)) => {
                        let len = data.len();

                        // Write to upstream
                        upstream_write.write_all(&data).await?;
                        bytes_client_to_upstream += len as u64;

                        // Release flow control capacity
                        let _ = recv_stream.flow_control().release_capacity(len);
                    }
                    Some(Err(e)) => {
                        error!(
                            "[H2 TUNNEL] RecvStream error for {} - user_id={}, token_id={}, error={}",
                            target_host, user_id, token_id, e
                        );
                        break;
                    }
                    None => {
                        // Client closed stream
                        debug!(
                            "[H2 TUNNEL] Client closed stream for {} - user_id={}, token_id={}",
                            target_host, user_id, token_id
                        );
                        break;
                    }
                }
            }

            // Upstream → Client (via SendStream)
            result = upstream_read.read(&mut upstream_buf) => {
                match result {
                    Ok(0) => {
                        // Upstream closed connection
                        debug!(
                            "[H2 TUNNEL] Upstream closed for {} - user_id={}, token_id={}",
                            target_host, user_id, token_id
                        );
                        break;
                    }
                    Ok(n) => {
                        let data = Bytes::copy_from_slice(&upstream_buf[..n]);

                        // Phase 4 Flow Control: Send with proper capacity management
                        if let Err(e) = send_with_flow_control(&mut send_stream, data, n).await {
                            error!(
                                "[H2 TUNNEL] SendStream error for {} - user_id={}, token_id={}, error={}",
                                target_host, user_id, token_id, e
                            );
                            break;
                        }

                        bytes_upstream_to_client += n as u64;
                    }
                    Err(e) => {
                        error!(
                            "[H2 TUNNEL] Upstream read error for {} - user_id={}, token_id={}, error={}",
                            target_host, user_id, token_id, e
                        );
                        break;
                    }
                }
            }
        }
    }

    // Close SendStream with END_STREAM flag
    let _ = send_stream.send_data(Bytes::new(), true);

    let duration = start_time.elapsed();
    info!(
        "[H2 TUNNEL] Closed {} - user_id={}, token_id={}, duration={:?}, \
         client→upstream={} bytes, upstream→client={} bytes",
        target_host,
        user_id,
        token_id,
        duration,
        bytes_client_to_upstream,
        bytes_upstream_to_client
    );

    Ok((bytes_client_to_upstream, bytes_upstream_to_client))
}

/// Serve HTTP/1.1 connections using Hyper
pub async fn serve_http1(tls_stream: TlsStream<TcpStream>, config: Arc<Config>) -> Result<()> {
    info!("HTTP/1.1 connection handler started");

    // Wrap TLS stream in TokioIo for Hyper compatibility
    let io = TokioIo::new(tls_stream);

    // Create HTTP/1.1 connection
    let conn = hyper::server::conn::http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                let config = Arc::clone(&config);
                async move { handle_request(req, config).await }
            }),
        )
        .with_upgrades(); // Enable HTTP upgrades for CONNECT

    // Serve the connection
    if let Err(e) = conn.await {
        error!("HTTP/1.1 connection error: {}", e);
    }

    Ok(())
}

/// Handle individual HTTP/1.1 requests
async fn handle_request(
    req: Request<Incoming>,
    config: Arc<Config>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();

    debug!("Received {} request for {}", method, uri);

    // Support CONNECT method for HTTPS tunneling
    if method == Method::CONNECT {
        // Handle CONNECT request for HTTPS tunneling
        handle_connect(req, config).await
    } else {
        // Forward HTTP requests (GET, POST, etc.) if enabled
        if config.http_proxy_enabled {
            forward_http_request(req, config).await
        } else {
            // HTTP forwarding disabled - return 204
            info!(
                "[HTTP] Non-CONNECT {} request for {} - HTTP forwarding disabled, returning 204",
                method, uri
            );
            Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header("Connection", "close")
                .body(Full::new(Bytes::new()))
                .unwrap())
        }
    }
}

/// Forward regular HTTP requests (GET, POST, HEAD, etc.) through the proxy
/// This handles plain HTTP traffic and Chrome's connectivity checks
///
/// Security Policy:
/// - SSRF protection via destination_filter (blocks RFC1918, localhost, metadata)
/// - IP-per-token limits via ip_tracker
/// - JWT authentication and rate limiting
/// - Blocks TRACE method to prevent XST attacks
/// - Validates absolute-form URIs per RFC 7230
/// - Filters hop-by-hop headers per RFC 7230 Section 6.1
/// - Body size limits (413 request, 502 response)
async fn forward_http_request(
    req: Request<Incoming>,
    config: Arc<Config>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start_time = std::time::Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let target_url = uri.to_string();

    // 1. Validate request method (block TRACE)
    if method == Method::TRACE {
        warn!("[HTTP] Blocked TRACE method");
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header("Allow", "GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS")
            .header("Connection", "close")
            .body(Full::new(Bytes::from("TRACE method not allowed")))
            .unwrap());
    }

    // 2. Validate absolute-form URI
    if uri.scheme().is_none() || uri.authority().is_none() {
        warn!(
            "[HTTP] Invalid URI (missing scheme/authority): {}",
            target_url
        );
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Connection", "close")
            .body(Full::new(Bytes::from(
                "Proxy requests must use absolute-form URI",
            )))
            .unwrap());
    }

    debug!("[HTTP] {} {}", method, target_url);

    // 3. JWT Authentication
    let claims = match config.jwt_validator.validate_request(&req) {
        Ok(claims) => claims,
        Err(AuthError::MissingHeader) => {
            return Ok(Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header("Proxy-Authenticate", "Bearer")
                .header("Connection", "close")
                .body(Full::new(Bytes::from("Proxy authentication required")))
                .unwrap());
        }
        Err(e) => {
            warn!("[HTTP] Auth failed: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Connection", "close")
                .body(Full::new(Bytes::from(format!(
                    "Authentication failed: {}",
                    e
                ))))
                .unwrap());
        }
    };

    // 4. Extract client IP
    let client_ip = req
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|addr| addr.ip())
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap());

    // 5. IP-per-token check
    if let Err(e) = config
        .ip_tracker
        .check_and_track(&claims.token_id, client_ip)
        .await
    {
        warn!("[HTTP] IP limit exceeded: {}", e);
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("Connection", "close")
            .body(Full::new(Bytes::from(e.to_string())))
            .unwrap());
    }

    // 6. Rate limiting
    if let Err(e) = config.rate_limiter.check_limit(&claims.token_id).await {
        warn!("[HTTP] Rate limit exceeded: {}", e);
        return Ok(Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("Connection", "close")
            .body(Full::new(Bytes::from(format!(
                "Rate limit exceeded: {}",
                e
            ))))
            .unwrap());
    }

    // 7. Mixed content policy check
    // Extract headers first for mixed content detection
    let request_headers = req.headers().clone();

    // Check and handle mixed content (HTTP request with HTTPS Referer/Origin)
    // This may upgrade HTTP→HTTPS or block the request based on policy
    let (mut parts, body) = req.into_parts();
    match crate::mixed_content::handle_mixed_content_request(
        &mut parts.uri,
        &request_headers,
        &config,
    )
    .await
    {
        Ok(Some(response)) => {
            // Request was blocked or modified - return early
            return Ok(response);
        }
        Ok(None) => {
            // Continue with potentially upgraded URI
        }
        Err(e) => {
            error!("[HTTP] Mixed content policy error: {}", e);
            // Continue on error (fail open)
        }
    }

    // 8. Stream body with size limit enforcement (Phase 4: no full buffering)
    // Note: parts and body already extracted above for mixed content check
    let body_bytes =
        match crate::body_limiter::read_body_with_limit(body, config.max_request_body_size).await {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("[HTTP] Body limit error: {}", e);
                return Ok(Response::builder()
                    .status(e.status_code())
                    .header("Connection", "close")
                    .body(Full::new(Bytes::from(e.to_response_message())))
                    .unwrap());
            }
        };

    // Reconstruct URI info from potentially modified parts.uri
    let uri = &parts.uri;
    let scheme = uri.scheme_str().unwrap_or("http");
    let authority = uri.authority().unwrap();
    let host = authority.host();
    let port = authority
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // 9. SSRF protection - resolve and check destination
    let vetted_ips = match config.destination_filter.check_and_resolve(host).await {
        Ok(ips) => ips,
        Err(e) => {
            warn!("[HTTP] Destination blocked: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Connection", "close")
                .body(Full::new(Bytes::from(format!(
                    "Destination not allowed: {}",
                    e
                ))))
                .unwrap());
        }
    };

    // 10. Forward request using http_client
    let body_option = if body_bytes.is_empty() {
        None
    } else {
        Some(body_bytes.clone())
    };

    match crate::http_client::forward_request(
        vetted_ips,
        port,
        scheme,
        method.as_str(),
        path,
        host,
        &request_headers,
        body_option,
        &config,
    )
    .await
    {
        Ok((status, headers, body)) => {
            // Success - build response
            let mut response = Response::builder()
                .status(status)
                .header("Connection", "close");

            for (name, value) in &headers {
                response = response.header(name, value);
            }

            // Log successful request
            config
                .request_logger
                .log_request(
                    claims.token_id.clone(),
                    claims.user_id as i32,
                    method.as_str().to_string(),
                    target_url.clone(),
                    Some(status.as_u16() as i32),
                    body.len() as i64,
                    Some(start_time.elapsed().as_millis() as i64),
                    true,
                    false,
                    None,
                )
                .await;

            Ok(response.body(Full::new(body)).unwrap())
        }
        Err(e) => {
            // Error - return 502 Bad Gateway
            error!("[HTTP] Forward failed: {}", e);

            let error_msg = match e {
                crate::http_client::HttpClientError::ResponseTooLarge { size, limit } => {
                    format!(
                        "Upstream response too large: {} bytes (limit: {})",
                        size, limit
                    )
                }
                _ => format!("Failed to connect to upstream: {}", e),
            };

            // Log failed request
            config
                .request_logger
                .log_request(
                    claims.token_id.clone(),
                    claims.user_id as i32,
                    method.as_str().to_string(),
                    target_url.clone(),
                    Some(502),
                    0,
                    Some(start_time.elapsed().as_millis() as i64),
                    false,
                    false,
                    Some(error_msg.clone()),
                )
                .await;

            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("Connection", "close")
                .body(Full::new(Bytes::from(error_msg)))
                .unwrap())
        }
    }
}

/// Handle HTTP/1.1 CONNECT requests for TLS tunneling
/// Generic over body type to allow testing with Empty<Bytes>
async fn handle_connect<B>(
    mut req: Request<B>,
    config: Arc<Config>,
) -> Result<Response<Full<Bytes>>, hyper::Error>
where
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync,
{
    let start_time = std::time::Instant::now();

    // Phase 3.0: Validate CONNECT target authority
    let target_host = match req.uri().authority() {
        Some(auth) => auth.to_string(),
        None => {
            warn!("[CONNECT] Missing authority in CONNECT request");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(
                    "Bad Request: CONNECT requires a valid host:port authority",
                )))
                .unwrap());
        }
    };

    // Validate and parse host:port format
    let (_host, _port) = match parse_authority(&target_host) {
        Ok((h, p)) => (h, p),
        Err(err_msg) => {
            warn!("[CONNECT] Invalid authority {}: {}", target_host, err_msg);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(format!("Bad Request: {}", err_msg))))
                .unwrap());
        }
    };

    // Note: target_host is used for TCP connection (already validated above)

    info!("[CONNECT] {} from client", target_host);

    // Phase 3.1: JWT Authentication
    let claims = match config.jwt_validator.validate_request(&req) {
        Ok(claims) => claims,
        Err(e) => {
            return handle_auth_error(e, &target_host, start_time);
        }
    };

    debug!(
        "[CONNECT] Authenticated user_id={}, token_id={}, allowed_regions={:?}",
        claims.user_id, claims.token_id, claims.allowed_regions
    );

    // Note: Region validation is now handled in JwtValidator::validate()
    // which checks for wildcard "*" or specific region match

    // Phase 3.3: Rate Limiting
    match config.rate_limiter.check_limit(&claims.token_id).await {
        Ok(()) => {}
        Err(e) => {
            return handle_rate_limit_error(e, &target_host, &claims.token_id, start_time);
        }
    };

    debug!(
        "[CONNECT] Rate limit check passed for token_id={}",
        claims.token_id
    );

    // Phase 3.4: Establish connection to target
    let upstream = match tokio::net::TcpStream::connect(&target_host).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("[CONNECT] Failed to connect to {}: {}", target_host, e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Failed to connect to target")))
                .unwrap());
        }
    };

    info!("[CONNECT] Connected to upstream {}", target_host);

    // Phase 3.5: Spawn tunnel task and upgrade connection
    let target_host_for_log = target_host.clone();
    let config_for_tunnel = Arc::clone(&config);
    tokio::spawn(async move {
        match hyper::upgrade::on(&mut req).await {
            Ok(upgraded) => {
                if let Err(e) = tunnel(
                    upgraded,
                    upstream,
                    target_host.clone(),
                    claims.user_id as i64,
                    claims.token_id,
                    start_time,
                    config_for_tunnel,
                )
                .await
                {
                    error!("[CONNECT] Tunnel error for {}: {}", target_host, e);
                }
            }
            Err(e) => {
                error!("[CONNECT] Upgrade error for {}: {}", target_host, e);
            }
        }
    });

    // Phase 3.6: Send 200 Connection Established
    info!(
        "[CONNECT] Sending 200 Connection Established for {}",
        target_host_for_log
    );
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

/// Bidirectional tunnel between client and upstream
async fn tunnel(
    upgraded: Upgraded,
    upstream: TcpStream,
    target_host: String,
    user_id: i64,
    token_id: String,
    start_time: std::time::Instant,
    config: Arc<Config>,
) -> Result<()> {
    let client = TokioIo::new(upgraded);
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    // Bidirectional copy: client <-> upstream
    let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
    let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

    let (c_to_u, u_to_c) = tokio::try_join!(client_to_upstream, upstream_to_client)?;

    let duration = start_time.elapsed();
    let total_bytes = c_to_u + u_to_c;

    info!(
        "[CONNECT] Completed {} - user_id={}, token_id={}, duration={:?}, \
         client→upstream={} bytes, upstream→client={} bytes, total={} bytes",
        target_host, user_id, token_id, duration, c_to_u, u_to_c, total_bytes
    );

    // Log request to backend (best-effort, non-blocking)
    config
        .request_logger
        .log_request(
            token_id.clone(),
            user_id as i32,
            "CONNECT".to_string(),
            target_host.clone(),
            Some(200), // HTTP/1.1 CONNECT returns 200 on success
            total_bytes as i64,
            Some(duration.as_millis() as i64),
            true,  // success = true
            false, // rate_limited = false (made it through tunnel)
            None,  // no error
        )
        .await;

    Ok(())
}

/// Handle JWT authentication errors
fn handle_auth_error(
    error: AuthError,
    target_host: &str,
    start_time: std::time::Instant,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let duration = start_time.elapsed();

    let (status, message) = match error {
        AuthError::MissingHeader => {
            warn!(
                "[CONNECT] Authentication failed for {}: missing header (duration={:?})",
                target_host, duration
            );
            (
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "Proxy authentication required. Please provide a valid JWT token in the Proxy-Authorization or Authorization header."
            )
        }
        AuthError::InvalidFormat => {
            warn!(
                "[CONNECT] Authentication failed for {}: invalid format (duration={:?})",
                target_host, duration
            );
            (
                StatusCode::BAD_REQUEST,
                "Invalid authentication format. Expected: Proxy-Authorization: Bearer <token>",
            )
        }
        AuthError::TokenExpired => {
            warn!(
                "[CONNECT] Authentication failed for {}: token expired (duration={:?})",
                target_host, duration
            );
            (
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "JWT token has expired. Please refresh your token or login again to the ProbeOps platform."
            )
        }
        AuthError::ValidationFailed(ref msg) => {
            warn!(
                "[CONNECT] Authentication failed for {}: {} (duration={:?})",
                target_host, msg, duration
            );
            (
                StatusCode::FORBIDDEN,
                "Authentication failed: Invalid JWT token",
            )
        }
        AuthError::RegionNotAllowed(ref msg) => {
            warn!(
                "[CONNECT] Authentication failed for {}: {} (duration={:?})",
                target_host, msg, duration
            );
            (
                StatusCode::FORBIDDEN,
                "Access denied: Region not in allowed list",
            )
        }
    };

    let mut response = Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(message)))
        .unwrap();

    // Add Proxy-Authenticate header for 407 responses (required for proper proxy auth)
    // Use Basic scheme for Chromium/Playwright compatibility (Chromium doesn't support Bearer for proxy auth)
    // Clients should send: Proxy-Authorization: Basic <base64(jwt:)>
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response.headers_mut().insert(
            "Proxy-Authenticate",
            "Basic realm=\"ProbeOps Forward Proxy\"".parse().unwrap(),
        );
    }

    Ok(response)
}

/// Handle rate limiting errors
fn handle_rate_limit_error(
    error: RateLimitError,
    target_host: &str,
    token_id: &str,
    start_time: std::time::Instant,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let duration = start_time.elapsed();

    match error {
        RateLimitError::LimitExceeded(_) => {
            warn!(
                "[CONNECT] Rate limit exceeded for {} - token_id={} (duration={:?})",
                target_host, token_id, duration
            );

            Ok(Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(Full::new(Bytes::from(
                    "Rate limit exceeded. Please retry later.",
                )))
                .unwrap())
        }
        RateLimitError::TooManyTokens(max) => {
            error!(
                "[CONNECT] Too many tokens error for {} - max={} (duration={:?})",
                target_host, max, duration
            );

            Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::from(format!(
                    "Service temporarily unavailable. Maximum {} concurrent tokens.",
                    max
                ))))
                .unwrap())
        }
    }
}

// // Week 1 tests disabled - Config struct needs updating
// // #[cfg(test)]
// // #[allow(dead_code)]
// // mod tests_disabled {
//     use super::*;
//     use chrono::Utc;
//     use http_body_util::BodyExt;
//     use jsonwebtoken::{encode, EncodingKey, Header};
//     use crate::auth::{JwtClaims, JwtValidator};
//     use crate::rate_limiter::{RateLimiter, RateLimiterConfig};
//
//     // Helper to create a test config
//     fn create_test_config() -> Arc<Config> {
//         use crate::logger::RequestLogger;
//
//         let jwt_validator = Arc::new(JwtValidator::new(
//             "test_secret_key_32_chars_minimum!!".to_string(),
//             "HS256".to_string(),
//             "us-east".to_string(),
//             None, // No issuer validation in tests
//             None, // No audience validation in tests
//         ).unwrap());
//
//         let rate_limiter_config = RateLimiterConfig {
//             requests_per_minute: 60,
//             burst_size: 10,
//             bucket_ttl_seconds: 60,
//             max_buckets: 100,
//         };
//         let rate_limiter = Arc::new(RateLimiter::new(rate_limiter_config));
//
//         let request_logger = Arc::new(RequestLogger::new(
//             "http://localhost:8000".to_string(),
//             "test-node".to_string(),
//             "us-east".to_string(),
//             100,
//             5,
//         ));
//
//         Arc::new(Config {
//             jwt_validator,
//             rate_limiter,
//             request_logger,
//             ..Config::default()
//         })
//     }
//
//     // Helper to create a valid JWT token
//     fn create_test_token(secret: &str, allowed_regions: Vec<String>) -> String {
//         let claims = JwtClaims {
//             token_id: "test_token_123".to_string(),
//             user_id: 42,
//             allowed_regions,
//             exp: (Utc::now() + chrono::Duration::hours(1)).timestamp(),
//             iat: Utc::now().timestamp(),
//             iss: None,
//             aud: None,
//         };
//
//         encode(
//             &Header::default(),
//             &claims,
//             &EncodingKey::from_secret(secret.as_bytes()),
//         ).unwrap()
//     }
//
//     // Note: Full integration tests for handle_request and handle_connect would require
//     // setting up actual TCP connections and Hyper servers. Instead, we test the
//     // error handler functions directly which cover all the critical logic paths.
//
//     #[test]
//     fn test_parse_authority_valid() {
//         // Valid host:port
//         assert_eq!(
//             parse_authority("example.com:443"),
//             Ok(("example.com".to_string(), 443))
//         );
//
//         // IPv4 with port
//         assert_eq!(
//             parse_authority("192.168.1.1:8080"),
//             Ok(("192.168.1.1".to_string(), 8080))
//         );
//
//         // IPv6 with port (simplified, real IPv6 would be [::1]:443)
//         assert_eq!(
//             parse_authority("[::1]:443"),
//             Ok(("[::1]".to_string(), 443))
//         );
//
//         // High port number
//         assert_eq!(
//             parse_authority("example.com:65535"),
//             Ok(("example.com".to_string(), 65535))
//         );
//
//         // Low port number
//         assert_eq!(
//             parse_authority("example.com:1"),
//             Ok(("example.com".to_string(), 1))
//         );
//     }
//
//     #[test]
//     fn test_parse_authority_invalid() {
//         // Missing port
//         assert!(parse_authority("example.com").is_err());
//
//         // Empty host
//         assert!(parse_authority(":443").is_err());
//
//         // Empty string
//         assert!(parse_authority("").is_err());
//
//         // Port is zero
//         assert!(parse_authority("example.com:0").is_err());
//
//         // Port is not a number
//         assert!(parse_authority("example.com:abc").is_err());
//
//         // Port out of range (too high)
//         assert!(parse_authority("example.com:65536").is_err());
//
//         // Port is negative (will fail parse)
//         assert!(parse_authority("example.com:-1").is_err());
//
//         // Multiple colons without brackets
//         assert!(parse_authority("example.com:80:443").is_ok()); // Will take last :443
//
//         // No colon separator
//         assert!(parse_authority("example_com_443").is_err());
//     }
//
//     #[tokio::test]
//     async fn test_handle_auth_error_messages() {
//         // Test that error messages are descriptive
//         let error = AuthError::MissingHeader;
//         let response = handle_auth_error(error, "example.com:443", std::time::Instant::now()).unwrap();
//         assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
//
//         let error = AuthError::InvalidFormat;
//         let response = handle_auth_error(error, "example.com:443", std::time::Instant::now()).unwrap();
//         assert_eq!(response.status(), StatusCode::BAD_REQUEST);
//
//         let error = AuthError::TokenExpired;
//         let response = handle_auth_error(error, "example.com:443", std::time::Instant::now()).unwrap();
//         assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
//
//         let error = AuthError::ValidationFailed("test".to_string());
//         let response = handle_auth_error(error, "example.com:443", std::time::Instant::now()).unwrap();
//         assert_eq!(response.status(), StatusCode::FORBIDDEN);
//
//         let error = AuthError::RegionNotAllowed("us-west".to_string());
//         let response = handle_auth_error(error, "example.com:443", std::time::Instant::now()).unwrap();
//         assert_eq!(response.status(), StatusCode::FORBIDDEN);
//     }
//
//     #[tokio::test]
//     async fn test_handle_rate_limit_errors() {
//         use crate::rate_limiter::RateLimitError;
//
//         // Test LimitExceeded error
//         let error = RateLimitError::LimitExceeded("Rate limit exceeded".to_string());
//         let response = handle_rate_limit_error(
//             error,
//             "example.com:443",
//             "test_token",
//             std::time::Instant::now()
//         ).unwrap();
//         assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
//
//         // Test TooManyTokens error
//         let error = RateLimitError::TooManyTokens(1000);
//         let response = handle_rate_limit_error(
//             error,
//             "example.com:443",
//             "test_token",
//             std::time::Instant::now()
//         ).unwrap();
//         assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
//     }
//
//     // Phase 3 Integration Tests
//     // These tests exercise the full CONNECT handler flow through handle_connect()
//     // Testing: auth validation, rate limiting, authority parsing, and error responses
//
//     #[tokio::test]
//     async fn test_connect_flow_missing_auth() {
//         // Integration Test: CONNECT without Proxy-Authorization should return 407 with Bearer challenge
//         let config = create_test_config();
//
//         let req = Request::builder()
//             .method(Method::CONNECT)
//             .uri("example.com:443")
//             .body(Empty::<Bytes>::new())
//             .unwrap();
//
//         let response = handle_connect(req, config).await.unwrap();
//
//         assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
//         assert!(response.headers().contains_key("proxy-authenticate"));
//         assert_eq!(
//             response.headers().get("proxy-authenticate").unwrap(),
//             "Bearer realm=\"ProbeOps Forward Proxy\""
//         );
//
//         let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
//         let body_str = String::from_utf8_lossy(&body_bytes);
//         assert!(body_str.contains("Proxy-Authorization"));
//     }
//
//     #[tokio::test]
//     async fn test_connect_flow_invalid_auth_format() {
//         // Integration Test: Malformed Proxy-Authorization should return 400
//         let config = create_test_config();
//
//         let req = Request::builder()
//             .method(Method::CONNECT)
//             .uri("example.com:443")
//             .header("Proxy-Authorization", "Invalid Token Format")
//             .body(Empty::<Bytes>::new())
//             .unwrap();
//
//         let response = handle_connect(req, config).await.unwrap();
//
//         assert_eq!(response.status(), StatusCode::BAD_REQUEST);
//
//         let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
//         let body_str = String::from_utf8_lossy(&body_bytes);
//         assert!(body_str.contains("Bearer"));
//     }
//
//     #[tokio::test]
//     async fn test_connect_flow_expired_token() {
//         // Integration Test: Expired JWT should return 407
//         let config = create_test_config();
//         let secret = "test_secret_key_32_chars_minimum!!";
//
//         let claims = JwtClaims {
//             token_id: "test_token_expired".to_string(),
//             user_id: 42,
//             allowed_regions: vec!["us-east".to_string()],
//             exp: (Utc::now() - chrono::Duration::hours(1)).timestamp(),
//             iat: (Utc::now() - chrono::Duration::hours(2)).timestamp(),
//             iss: None,
//             aud: None,
//         };
//
//         let token = encode(
//             &Header::default(),
//             &claims,
//             &EncodingKey::from_secret(secret.as_bytes()),
//         ).unwrap();
//
//         let req = Request::builder()
//             .method(Method::CONNECT)
//             .uri("example.com:443")
//             .header("Proxy-Authorization", format!("Bearer {}", token))
//             .body(Empty::<Bytes>::new())
//             .unwrap();
//
//         let response = handle_connect(req, config).await.unwrap();
//
//         assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
//         assert!(response.headers().contains_key("proxy-authenticate"));
//     }
//
//     #[tokio::test]
//     async fn test_connect_flow_wrong_region() {
//         // Integration Test: Token with wrong region should return 403
//         let config = create_test_config();
//         let secret = "test_secret_key_32_chars_minimum!!";
//
//         // Token for eu-west, but config expects us-east
//         let token = create_test_token(secret, vec!["eu-west".to_string()]);
//
//         let req = Request::builder()
//             .method(Method::CONNECT)
//             .uri("example.com:443")
//             .header("Proxy-Authorization", format!("Bearer {}", token))
//             .body(Empty::<Bytes>::new())
//             .unwrap();
//
//         let response = handle_connect(req, config).await.unwrap();
//
//         assert_eq!(response.status(), StatusCode::FORBIDDEN);
//
//         let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
//         let body_str = String::from_utf8_lossy(&body_bytes);
//         assert!(body_str.contains("Region") || body_str.contains("denied"));
//     }
//
//     #[tokio::test]
//     async fn test_connect_flow_wildcard_region_passes_auth() {
//         // Integration Test: Token with ["*"] should pass region check for any region
//         let config = create_test_config();
//         let secret = "test_secret_key_32_chars_minimum!!";
//
//         let token = create_test_token(secret, vec!["*".to_string()]);
//
//         let req = Request::builder()
//             .method(Method::CONNECT)
//             .uri("127.0.0.1:1234") // Use unreachable address for test
//             .header("Proxy-Authorization", format!("Bearer {}", token))
//             .body(Empty::<Bytes>::new())
//             .unwrap();
//
//         let response = handle_connect(req, config).await.unwrap();
//
//         // Should pass auth (wildcard allows all regions)
//         // Will be 502 Bad Gateway because 127.0.0.1:1234 is unreachable
//         // But NOT 403 Forbidden or 407 Auth Required
//         assert_ne!(response.status(), StatusCode::FORBIDDEN);
//         assert_ne!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
//     }
//
//     #[tokio::test]
//     async fn test_connect_flow_malformed_authorities() {
//         // Integration Test: Various malformed authorities should return 400
//         let config = create_test_config();
//         let secret = "test_secret_key_32_chars_minimum!!";
//         let token = create_test_token(secret, vec!["us-east".to_string()]);
//
//         let test_cases = vec![
//             ("example.com", "Missing port"),
//             (":443", "Empty host"),
//             ("example.com:abc", "Non-numeric port"),
//             ("example.com:0", "Port zero"),
//             ("example.com:99999", "Port out of range"),
//         ];
//
//         for (authority, description) in test_cases {
//             let req = Request::builder()
//                 .method(Method::CONNECT)
//                 .uri(authority)
//                 .header("Proxy-Authorization", format!("Bearer {}", token))
//                 .body(Empty::<Bytes>::new())
//                 .unwrap();
//
//             let response = handle_connect(req, config.clone()).await.unwrap();
//
//             assert_eq!(
//                 response.status(),
//                 StatusCode::BAD_REQUEST,
//                 "{}: Authority '{}' should return 400",
//                 description,
//                 authority
//             );
//
//             let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
//             let body_str = String::from_utf8_lossy(&body_bytes);
//             assert!(
//                 body_str.contains("Bad Request") || body_str.contains("Invalid"),
//                 "{}: Should have error in body",
//                 description
//             );
//         }
//     }
//
//     #[tokio::test]
//     async fn test_connect_flow_valid_auth_attempts_upstream() {
//         // Integration Test: Valid auth + valid authority should attempt upstream connection
//         let config = create_test_config();
//         let secret = "test_secret_key_32_chars_minimum!!";
//         let token = create_test_token(secret, vec!["us-east".to_string()]);
//
//         let req = Request::builder()
//             .method(Method::CONNECT)
//             .uri("127.0.0.1:1") // Unreachable address
//             .header("Proxy-Authorization", format!("Bearer {}", token))
//             .body(Empty::<Bytes>::new())
//             .unwrap();
//
//         let response = handle_connect(req, config).await.unwrap();
//
//         // Should pass auth (not 407) and authority validation (not 400)
//         assert_ne!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
//         assert_ne!(response.status(), StatusCode::FORBIDDEN);
//         assert_ne!(response.status(), StatusCode::BAD_REQUEST);
//
//         // Will be 502 Bad Gateway because upstream is unreachable
//         // or 200 if upgrade somehow succeeds (shouldn't in tests)
//         assert!(
//             response.status() == StatusCode::OK
//                 || response.status() == StatusCode::BAD_GATEWAY,
//             "Expected 200 or 502, got {}",
//             response.status()
//         );
//     }
//
//     // Phase 4 HTTP/2 Integration Tests
//     // These tests validate error response logic for HTTP/2 CONNECT handler
//     // Note: Full end-to-end h2 client/server tests require complex connection lifecycle management
//     // and are better suited for separate integration test suite. These tests focus on verifying
//     // the critical auth/rate-limit/authority validation logic.
//
//     #[test]
//     fn test_h2_parse_authority_validation() {
//         // Integration Test: Verify parse_authority works correctly for HTTP/2 Extended CONNECT
//         // HTTP/2 Extended CONNECT uses :authority pseudo-header which should be in host:port format
//
//         // Valid authorities
//         assert_eq!(
//             parse_authority("example.com:443"),
//             Ok(("example.com".to_string(), 443))
//         );
//         assert_eq!(
//             parse_authority("192.168.1.1:8080"),
//             Ok(("192.168.1.1".to_string(), 8080))
//         );
//         assert_eq!(
//             parse_authority("[2001:db8::1]:443"),
//             Ok(("[2001:db8::1]".to_string(), 443))
//         );
//
//         // Invalid authorities
//         assert!(parse_authority("example.com").is_err()); // Missing port
//         assert!(parse_authority(":443").is_err()); // Missing host
//         assert!(parse_authority("").is_err()); // Empty
//         assert!(parse_authority("example.com:0").is_err()); // Port 0
//         assert!(parse_authority("example.com:99999").is_err()); // Port out of range
//     }
// }
