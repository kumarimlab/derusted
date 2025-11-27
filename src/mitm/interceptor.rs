//! MITM Interceptor - Main interception logic
//!
//! This module handles the core MITM interception flow:
//! 1. Accept client TLS connection with fake certificate
//! 2. Establish upstream TLS connection with real verification
//! 3. Proxy data bidirectionally with optional inspection

use crate::connection_pool::ConnectionPool;
use crate::mitm::{
    bypass::{BypassManager, BypassReason},
    certificate_authority::{CertificateAuthority, HostIdentifier, MitmError},
    hsts::HstsManager,
    http_parser::{parse_http1_request, parse_http1_response, ParseError},
    log_storage::LogStorage,
    logging::{LoggingPolicy, PiiRedactor, RequestMetadata},
    pinning::{PinningDetector, PinningPatterns},
    tls_config::{ClientTlsConfig, SniUtils, UpstreamTlsConfig},
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, error, info, warn};

/// Interception errors
#[derive(Debug, Error)]
pub enum InterceptionError {
    #[error("MITM error: {0}")]
    MitmError(#[from] MitmError),

    #[error("TLS handshake failed: {0}")]
    TlsHandshakeFailed(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Bypass required: {0}")]
    BypassRequired(BypassReason),

    #[error("Logging failed: {0}")]
    LoggingFailed(String),
}

/// Result of interception attempt
#[derive(Debug)]
pub enum InterceptionResult {
    /// Successfully intercepted
    Intercepted { metadata: RequestMetadata },

    /// Bypassed (tunneled without inspection)
    Bypassed {
        reason: BypassReason,
        metadata: RequestMetadata,
    },

    /// Failed
    Failed { error: InterceptionError },
}

/// MITM Interceptor
pub struct MitmInterceptor {
    /// Certificate authority for generating fake certs
    ca: Arc<CertificateAuthority>,

    /// Bypass manager for smart bypass decisions
    bypass_manager: Arc<BypassManager>,

    /// Logging policy
    logging_policy: Arc<LoggingPolicy>,

    /// Upstream TLS config
    upstream_tls: Arc<UpstreamTlsConfig>,

    /// HSTS manager
    hsts_manager: Arc<HstsManager>,

    /// Pinning detector
    pinning_detector: Arc<PinningDetector>,

    /// Log storage (optional)
    log_storage: Option<Arc<LogStorage>>,

    /// Connection pool for reusing upstream TLS connections
    connection_pool: Arc<ConnectionPool>,
}

impl MitmInterceptor {
    /// Create new interceptor
    pub fn new(
        ca: Arc<CertificateAuthority>,
        bypass_manager: Arc<BypassManager>,
        logging_policy: Arc<LoggingPolicy>,
    ) -> Result<Self, InterceptionError> {
        let upstream_tls = Arc::new(
            UpstreamTlsConfig::new()
                .map_err(|e| InterceptionError::TlsHandshakeFailed(e.to_string()))?,
        );

        let hsts_manager = Arc::new(HstsManager::new());
        let pinning_detector =
            Arc::new(PinningDetector::new().with_bypass_manager(Arc::clone(&bypass_manager)));

        // Create connection pool with default config
        let connection_pool = Arc::new(ConnectionPool::new());

        // Start background cleanup task
        crate::connection_pool::start_cleanup_task(Arc::clone(&connection_pool));

        Ok(Self {
            ca,
            bypass_manager,
            logging_policy,
            upstream_tls,
            hsts_manager,
            pinning_detector,
            log_storage: None,
            connection_pool,
        })
    }

    /// Create new interceptor with custom HSTS manager
    pub fn with_hsts(
        ca: Arc<CertificateAuthority>,
        bypass_manager: Arc<BypassManager>,
        logging_policy: Arc<LoggingPolicy>,
        hsts_manager: Arc<HstsManager>,
    ) -> Result<Self, InterceptionError> {
        let upstream_tls = Arc::new(
            UpstreamTlsConfig::new()
                .map_err(|e| InterceptionError::TlsHandshakeFailed(e.to_string()))?,
        );

        let pinning_detector =
            Arc::new(PinningDetector::new().with_bypass_manager(Arc::clone(&bypass_manager)));

        // Create connection pool with default config
        let connection_pool = Arc::new(ConnectionPool::new());

        // Start background cleanup task
        crate::connection_pool::start_cleanup_task(Arc::clone(&connection_pool));

        Ok(Self {
            ca,
            bypass_manager,
            logging_policy,
            upstream_tls,
            hsts_manager,
            pinning_detector,
            log_storage: None,
            connection_pool,
        })
    }

    /// Create new interceptor with custom pinning detector
    pub fn with_pinning(
        ca: Arc<CertificateAuthority>,
        bypass_manager: Arc<BypassManager>,
        logging_policy: Arc<LoggingPolicy>,
        hsts_manager: Arc<HstsManager>,
        pinning_detector: Arc<PinningDetector>,
    ) -> Result<Self, InterceptionError> {
        let upstream_tls = Arc::new(
            UpstreamTlsConfig::new()
                .map_err(|e| InterceptionError::TlsHandshakeFailed(e.to_string()))?,
        );

        // Create connection pool with default config
        let connection_pool = Arc::new(ConnectionPool::new());

        // Start background cleanup task
        crate::connection_pool::start_cleanup_task(Arc::clone(&connection_pool));

        Ok(Self {
            ca,
            bypass_manager,
            logging_policy,
            upstream_tls,
            hsts_manager,
            pinning_detector,
            log_storage: None,
            connection_pool,
        })
    }

    /// Enable SQLite logging
    ///
    /// This method enables request/response logging to SQLite database.
    /// Logging is performed asynchronously and does not block the proxy.
    pub async fn with_logging(mut self, db_path: &str) -> Result<Self, InterceptionError> {
        let storage = LogStorage::new(db_path)
            .await
            .map_err(|e| InterceptionError::LoggingFailed(e.to_string()))?;

        self.log_storage = Some(Arc::new(storage));
        Ok(self)
    }

    /// Attempt to intercept connection
    pub async fn intercept(
        &self,
        client_stream: TcpStream,
        target_host: String,
        target_port: u16,
    ) -> InterceptionResult {
        debug!(
            target_host = %target_host,
            target_port = target_port,
            "Attempting MITM interception"
        );

        // Check HSTS protection
        if self.hsts_manager.is_hsts_domain(&target_host).await {
            info!(
                target_host = %target_host,
                "Domain is HSTS-protected, bypassing MITM"
            );

            match self
                .tunnel_connection(client_stream, &target_host, target_port)
                .await
            {
                Ok(metadata) => {
                    return InterceptionResult::Bypassed {
                        reason: BypassReason::HstsPolicy,
                        metadata,
                    };
                }
                Err(e) => {
                    return InterceptionResult::Failed { error: e };
                }
            }
        }

        // Check if should bypass
        if let Some(reason) = self.bypass_manager.should_bypass(&target_host).await {
            info!(
                target_host = %target_host,
                reason = ?reason,
                "Bypassing MITM"
            );

            // Implement transparent tunneling (no inspection)
            match self
                .tunnel_connection(client_stream, &target_host, target_port)
                .await
            {
                Ok(metadata) => {
                    return InterceptionResult::Bypassed { reason, metadata };
                }
                Err(e) => {
                    return InterceptionResult::Failed { error: e };
                }
            }
        }

        // Parse host identifier
        let host_id = HostIdentifier::from_hostname(&target_host);

        // Check for localhost bypass
        if matches!(host_id, HostIdentifier::Localhost) {
            warn!("Localhost bypass triggered");
            match self
                .tunnel_connection(client_stream, &target_host, target_port)
                .await
            {
                Ok(metadata) => {
                    return InterceptionResult::Bypassed {
                        reason: BypassReason::Localhost,
                        metadata,
                    };
                }
                Err(e) => {
                    return InterceptionResult::Failed { error: e };
                }
            }
        }

        // Generate fake certificate
        let cert = match self.ca.get_or_generate(host_id).await {
            Ok(cert) => cert,
            Err(e) => {
                return InterceptionResult::Failed {
                    error: InterceptionError::MitmError(e),
                }
            }
        };

        // Perform MITM interception
        match self
            .intercept_with_inspection(client_stream, &target_host, target_port, cert)
            .await
        {
            Ok(metadata) => InterceptionResult::Intercepted { metadata },
            Err(e) => InterceptionResult::Failed { error: e },
        }
    }

    /// Intercept connection with full TLS inspection
    async fn intercept_with_inspection(
        &self,
        client_stream: TcpStream,
        target_host: &str,
        target_port: u16,
        fake_cert: Arc<rcgen::Certificate>,
    ) -> Result<RequestMetadata, InterceptionError> {
        debug!(
            target_host = %target_host,
            target_port = target_port,
            "Starting TLS inspection"
        );

        // 1. Build client-facing TLS config with fake certificate
        let client_tls_config = self.build_client_tls_config(&fake_cert)?;
        let tls_acceptor = TlsAcceptor::from(client_tls_config.server_config());

        // 2. Accept client TLS connection
        let mut client_tls = match tls_acceptor.accept(client_stream).await {
            Ok(stream) => stream,
            Err(e) => {
                error!(
                    target_host = %target_host,
                    error = %e,
                    "Client TLS handshake failed"
                );
                return Err(InterceptionError::TlsHandshakeFailed(e.to_string()));
            }
        };

        info!(
            target_host = %target_host,
            "Client TLS handshake successful"
        );

        // Detect ALPN protocol negotiation
        let alpn_protocol = client_tls.get_ref().1.alpn_protocol();
        debug!(
            target_host = %target_host,
            alpn = ?alpn_protocol,
            "ALPN protocol detected"
        );

        // Clone ALPN protocol for later use (after client_tls is moved/borrowed)
        let alpn_protocol_owned = alpn_protocol.map(|p| p.to_vec());

        // 3. Establish upstream TLS connection (try pool first)
        let upstream_addr = format!("{}:{}", target_host, target_port);
        let pool_key = upstream_addr.clone();

        // Try to get connection from pool first
        let mut upstream_tls = match self.connection_pool.get(&pool_key).await {
            Some(stream) => {
                debug!(
                    upstream_addr = %upstream_addr,
                    "Reusing pooled TLS connection (cache hit)"
                );
                stream
            }
            None => {
                debug!(
                    upstream_addr = %upstream_addr,
                    "No pooled connection available, creating new connection (cache miss)"
                );

                // Record cache miss
                self.connection_pool.record_miss().await;

                // Create new TCP connection
                let upstream_stream = match TcpStream::connect(&upstream_addr).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        error!(
                            upstream_addr = %upstream_addr,
                            error = %e,
                            "Failed to connect to upstream"
                        );
                        return Err(InterceptionError::IoError(e));
                    }
                };

                // Parse server name for SNI
                let server_name = match SniUtils::parse_server_name(target_host) {
                    Ok(name) => name,
                    Err(e) => {
                        error!(
                            target_host = %target_host,
                            error = %e,
                            "Invalid server name for SNI"
                        );
                        return Err(InterceptionError::TlsHandshakeFailed(e.to_string()));
                    }
                };

                // Establish TLS handshake
                let tls_connector = TlsConnector::from(self.upstream_tls.client_config());
                match tls_connector.connect(server_name, upstream_stream).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        let error_str = e.to_string();
                        error!(
                            target_host = %target_host,
                            error = %error_str,
                            "Upstream TLS handshake failed"
                        );

                        // Check if this looks like certificate pinning
                        if PinningPatterns::is_pinning_error(&error_str) {
                            let detection = self
                                .pinning_detector
                                .record_failure(target_host, &error_str)
                                .await;

                            if detection.detected {
                                warn!(
                                    target_host = %target_host,
                                    count = detection.failure_count,
                                    auto_bypassed = detection.auto_bypassed,
                                    "Certificate pinning detected"
                                );
                            }
                        }

                        return Err(InterceptionError::TlsHandshakeFailed(error_str));
                    }
                }
            }
        };

        info!(
            target_host = %target_host,
            "Upstream TLS handshake successful"
        );

        // 4. Proxy data bidirectionally with inspection based on ALPN protocol
        let bytes_transferred = match alpn_protocol_owned.as_deref() {
            Some(b"h2") => {
                debug!(target_host = %target_host, "Using production HTTP/2 MITM with flow control");
                // Week 6: Use production-grade h2 crate handler with proper flow control
                // Note: HTTP/2 handler takes ownership of both streams, cannot return to pool
                match crate::mitm::handle_http2_mitm(
                    client_tls,
                    upstream_tls,
                    target_host.to_string(),
                    target_port,
                    Arc::clone(&self.logging_policy),
                    self.log_storage.clone(),
                    crate::mitm::Http2Config::default(),
                )
                .await
                {
                    Ok(()) => {
                        debug!(target_host = %target_host, "HTTP/2 connection consumed by handler");
                        0 // HTTP/2 handler manages its own byte counting
                    }
                    Err(e) => {
                        error!(
                            target_host = %target_host,
                            error = %e,
                            "HTTP/2 MITM failed"
                        );
                        return Err(InterceptionError::IoError(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("HTTP/2 MITM error: {}", e),
                        )));
                    }
                }
            }
            Some(b"http/1.1") | None => {
                debug!(target_host = %target_host, "Using HTTP/1.1 inspection");
                let bytes = match self
                    .proxy_with_inspection(
                        &mut client_tls,
                        &mut upstream_tls,
                        target_host,
                        target_port,
                    )
                    .await
                {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error!(
                            target_host = %target_host,
                            error = %e,
                            "HTTP/1.1 proxying failed"
                        );
                        return Err(e);
                    }
                };

                // Return connection to pool (we still own it for HTTP/1.1)
                debug!(target_host = %target_host, "Returning HTTP/1.1 connection to pool");
                self.connection_pool
                    .put(pool_key.clone(), upstream_tls)
                    .await;
                bytes
            }
            Some(proto) => {
                warn!(
                    target_host = %target_host,
                    protocol = ?proto,
                    "Unknown ALPN protocol, using bidirectional copy without inspection"
                );
                // For unknown protocols, just forward data without inspection
                let bytes =
                    match tokio::io::copy_bidirectional(&mut client_tls, &mut upstream_tls).await {
                        Ok((client_bytes, upstream_bytes)) => client_bytes + upstream_bytes,
                        Err(e) => {
                            debug!(error = %e, "Bidirectional copy failed");
                            0
                        }
                    };

                // Return connection to pool (we still own it for unknown protocols)
                debug!(target_host = %target_host, protocol = ?proto, "Returning connection to pool");
                self.connection_pool.put(pool_key, upstream_tls).await;
                bytes
            }
        };

        info!(
            target_host = %target_host,
            bytes_transferred = bytes_transferred,
            "MITM interception completed"
        );

        // 5. Build metadata
        let metadata = RequestMetadata {
            timestamp: chrono::Utc::now().timestamp(),
            method: "CONNECT".to_string(),
            host: target_host.to_string(),
            port: target_port,
            path: "/".to_string(), // TLS-level inspection, no HTTP path yet
            http_version: "HTTPS".to_string(),
            status_code: None,
            request_size: 0, // TODO: Track in future
            response_size: 0,
            duration_ms: 0, // TODO: Track timing
            tls_version: Some("TLS 1.2+".to_string()),
            mitm_applied: true,
            bypass_reason: None,
        };

        Ok(metadata)
    }

    /// Tunnel connection without inspection (bypass mode)
    async fn tunnel_connection(
        &self,
        mut client_stream: TcpStream,
        target_host: &str,
        target_port: u16,
    ) -> Result<RequestMetadata, InterceptionError> {
        debug!(
            target_host = %target_host,
            target_port = target_port,
            "Tunneling without inspection"
        );

        // Establish upstream connection
        let upstream_addr = format!("{}:{}", target_host, target_port);
        let mut upstream_stream = TcpStream::connect(&upstream_addr).await?;

        // Proxy data bidirectionally (no inspection)
        let bytes_transferred =
            tokio::io::copy_bidirectional(&mut client_stream, &mut upstream_stream).await?;

        info!(
            target_host = %target_host,
            bytes_up = bytes_transferred.0,
            bytes_down = bytes_transferred.1,
            "Tunnel completed"
        );

        let metadata = RequestMetadata {
            timestamp: chrono::Utc::now().timestamp(),
            method: "CONNECT".to_string(),
            host: target_host.to_string(),
            port: target_port,
            path: "/".to_string(), // Tunneled, no HTTP inspection
            http_version: "HTTPS".to_string(),
            status_code: None,
            request_size: bytes_transferred.0 as usize,
            response_size: bytes_transferred.1 as usize,
            duration_ms: 0,    // TODO: Track timing
            tls_version: None, // Tunneled, not inspected
            mitm_applied: false,
            bypass_reason: None, // Set by caller
        };

        Ok(metadata)
    }

    /// Proxy data with inspection capabilities
    async fn proxy_with_inspection<C, U>(
        &self,
        client: &mut C,
        upstream: &mut U,
        target_host: &str,
        target_port: u16,
    ) -> Result<u64, InterceptionError>
    where
        C: AsyncRead + AsyncWrite + Unpin,
        U: AsyncRead + AsyncWrite + Unpin,
    {
        let start_time = std::time::Instant::now();

        // Read initial HTTP request (buffer up to 8KB for headers)
        let mut request_buffer = vec![0u8; 8192];
        let mut request_bytes = match client.read(&mut request_buffer).await {
            Ok(0) => {
                debug!(target_host = %target_host, "Client closed connection");
                return Ok(0);
            }
            Ok(n) => n,
            Err(e) => {
                warn!(target_host = %target_host, error = %e, "Failed to read request");
                return Err(InterceptionError::IoError(e));
            }
        };

        // Try to parse HTTP request (may fail for incomplete/binary data)
        let http_request = match parse_http1_request(&request_buffer[..request_bytes]) {
            Ok(req) => Some(req),
            Err(ParseError::Incomplete) if request_bytes < 8192 => {
                // Buffer not full - truly incomplete, not large headers
                debug!(target_host = %target_host, "Incomplete HTTP request (partial read), proxying transparently");
                None
            }
            Err(ParseError::Incomplete) => {
                // Buffer is full but headers incomplete - try reading more (up to 32KB total)
                debug!(target_host = %target_host, "Headers may be larger than 8KB, attempting extended read");

                // Expand buffer to 32KB and try reading more
                request_buffer.resize(32768, 0);
                match client.read(&mut request_buffer[request_bytes..]).await {
                    Ok(0) => {
                        debug!(target_host = %target_host, "No additional data available, proxying transparently");
                        None
                    }
                    Ok(n) => {
                        request_bytes += n;
                        // Retry parsing with extended buffer
                        match parse_http1_request(&request_buffer[..request_bytes]) {
                            Ok(req) => {
                                debug!(target_host = %target_host, bytes = request_bytes, "Successfully parsed large headers");
                                Some(req)
                            }
                            Err(e) => {
                                debug!(target_host = %target_host, error = %e, "Still cannot parse after extended read, proxying transparently");
                                None
                            }
                        }
                    }
                    Err(e) => {
                        warn!(target_host = %target_host, error = %e, "Failed to read additional header data");
                        None
                    }
                }
            }
            Err(e) => {
                debug!(target_host = %target_host, error = %e, "HTTP parse error, proxying transparently");
                None
            }
        };

        // Forward request to upstream
        upstream.write_all(&request_buffer[..request_bytes]).await?;

        // Read initial HTTP response (buffer up to 8KB for headers)
        let mut response_buffer = vec![0u8; 8192];
        let mut response_bytes = match upstream.read(&mut response_buffer).await {
            Ok(0) => {
                debug!(target_host = %target_host, "Upstream closed connection");
                return Ok(request_bytes as u64);
            }
            Ok(n) => n,
            Err(e) => {
                warn!(target_host = %target_host, error = %e, "Failed to read response");
                return Err(InterceptionError::IoError(e));
            }
        };

        // Try to parse HTTP response
        let http_response = match parse_http1_response(&response_buffer[..response_bytes]) {
            Ok(resp) => Some(resp),
            Err(ParseError::Incomplete) if response_bytes < 8192 => {
                // Buffer not full - truly incomplete, not large headers
                debug!(target_host = %target_host, "Incomplete HTTP response (partial read), proxying transparently");
                None
            }
            Err(ParseError::Incomplete) => {
                // Buffer is full but headers incomplete - try reading more (up to 32KB total)
                debug!(target_host = %target_host, "Response headers may be larger than 8KB, attempting extended read");

                // Expand buffer to 32KB and try reading more
                response_buffer.resize(32768, 0);
                match upstream.read(&mut response_buffer[response_bytes..]).await {
                    Ok(0) => {
                        debug!(target_host = %target_host, "No additional response data available, proxying transparently");
                        None
                    }
                    Ok(n) => {
                        response_bytes += n;
                        // Retry parsing with extended buffer
                        match parse_http1_response(&response_buffer[..response_bytes]) {
                            Ok(resp) => {
                                debug!(target_host = %target_host, bytes = response_bytes, "Successfully parsed large response headers");
                                Some(resp)
                            }
                            Err(e) => {
                                debug!(target_host = %target_host, error = %e, "Still cannot parse response after extended read, proxying transparently");
                                None
                            }
                        }
                    }
                    Err(e) => {
                        warn!(target_host = %target_host, error = %e, "Failed to read additional response header data");
                        None
                    }
                }
            }
            Err(e) => {
                debug!(target_host = %target_host, error = %e, "HTTP response parse error, proxying transparently");
                None
            }
        };

        // Forward response to client
        client.write_all(&response_buffer[..response_bytes]).await?;

        // Continue proxying remaining data bidirectionally
        let (bytes_up_remaining, bytes_down_remaining) =
            tokio::io::copy_bidirectional(client, upstream).await?;

        let total_bytes_up = request_bytes as u64 + bytes_up_remaining;
        let total_bytes_down = response_bytes as u64 + bytes_down_remaining;
        let duration_ms = start_time.elapsed().as_millis() as u64;

        debug!(
            target_host = %target_host,
            bytes_up = total_bytes_up,
            bytes_down = total_bytes_down,
            duration_ms = duration_ms,
            "Data proxied with inspection"
        );

        // Log request if policy allows and we successfully parsed HTTP
        if let (Some(req), Some(resp)) = (&http_request, &http_response) {
            if PiiRedactor::should_sample(self.logging_policy.sampling_rate) {
                let mut metadata = RequestMetadata {
                    timestamp: chrono::Utc::now().timestamp(),
                    method: req.method.clone(),
                    host: target_host.to_string(),
                    port: target_port,
                    path: req.path.clone(),
                    http_version: req.version.clone(),
                    status_code: Some(resp.status_code),
                    request_size: total_bytes_up as usize,
                    response_size: total_bytes_down as usize,
                    duration_ms,
                    tls_version: Some("TLS 1.2+".to_string()),
                    mitm_applied: true,
                    bypass_reason: None,
                };

                // Apply PII redaction if enabled
                if self.logging_policy.enable_pii_redaction {
                    metadata.path = PiiRedactor::redact(&metadata.path);
                }

                // Log asynchronously (non-blocking)
                if let Some(storage) = &self.log_storage {
                    let storage_clone = Arc::clone(storage);
                    tokio::spawn(async move {
                        if let Err(e) = storage_clone.log_request(&metadata).await {
                            warn!(error = %e, "Failed to log request to database");
                        }
                    });
                }
            }
        }

        Ok(total_bytes_up + total_bytes_down)
    }

    /// Proxy data bidirectionally with HTTP/2 inspection and logging
    async fn proxy_with_http2_inspection<C, U>(
        &self,
        client: &mut C,
        upstream: &mut U,
        target_host: &str,
        target_port: u16,
    ) -> Result<u64, InterceptionError>
    where
        C: AsyncRead + AsyncWrite + Unpin,
        U: AsyncRead + AsyncWrite + Unpin,
    {
        use crate::mitm::http2_parser::{
            extract_http2_request, extract_http2_response, has_end_stream, is_client_stream,
            parse_frame_header, FrameType, HpackDecoder, Http2Frame,
        };

        let start_time = Instant::now();
        let mut total_bytes = 0u64;

        // Initialize HPACK decoders (one for client, one for upstream)
        let mut client_decoder = HpackDecoder::new();
        let mut upstream_decoder = HpackDecoder::new();

        // Track frames per stream
        let mut stream_buffers: HashMap<u32, Vec<Http2Frame>> = HashMap::new();

        // Track pending requests (waiting for response) with start time
        // Key: stream_id, Value: (RequestMetadata, request_start_time)
        let mut pending_requests: HashMap<u32, (RequestMetadata, Instant)> = HashMap::new();

        // Buffers for reading frame headers (9 bytes)
        let mut client_frame_header = vec![0u8; 9];
        let mut upstream_frame_header = vec![0u8; 9];

        loop {
            tokio::select! {
                // Read from client, forward to upstream
                result = client.read_exact(&mut client_frame_header) => {
                    match result {
                        Ok(_) => {
                            // Parse frame header
                            let (frame_type, flags, stream_id, length) = match parse_frame_header(&client_frame_header) {
                                Ok(header) => header,
                                Err(e) => {
                                    warn!(error = ?e, "Failed to parse client HTTP/2 frame header");
                                    break;
                                }
                            };

                            // Read frame payload
                            let mut payload = vec![0u8; length];
                            if let Err(e) = client.read_exact(&mut payload).await {
                                debug!(error = %e, "Failed to read client HTTP/2 frame payload");
                                break;
                            }

                            total_bytes += (9 + length) as u64;

                            // Buffer HEADERS and DATA frames for request extraction
                            if matches!(frame_type, FrameType::Headers | FrameType::Data | FrameType::Continuation) && is_client_stream(stream_id) {
                                let frame = Http2Frame {
                                    frame_type,
                                    flags,
                                    stream_id,
                                    payload_length: length,
                                    payload: payload.clone(),
                                };
                                stream_buffers.entry(stream_id).or_insert_with(Vec::new).push(frame.clone());

                                // If END_STREAM flag set on client stream, extract request
                                if has_end_stream(&frame) {
                                    if let Some(frames) = stream_buffers.get(&stream_id) {
                                        match extract_http2_request(frames, &mut client_decoder) {
                                            Ok(request) => {
                                                debug!(
                                                    method = %request.method,
                                                    path = %request.path,
                                                    stream_id = stream_id,
                                                    "HTTP/2 request extracted"
                                                );

                                                // Create metadata and store for correlation with response
                                                let metadata = RequestMetadata {
                                                    timestamp: chrono::Utc::now().timestamp(),
                                                    host: target_host.to_string(),
                                                    port: target_port,
                                                    method: request.method.clone(),
                                                    path: request.path.clone(),
                                                    http_version: "HTTP/2".to_string(),
                                                    status_code: None, // Will be filled when response arrives
                                                    request_size: request.content_length.unwrap_or(0),
                                                    response_size: 0, // Will be filled when response arrives
                                                    duration_ms: 0, // Will be calculated when response arrives
                                                    tls_version: Some("TLS 1.3".to_string()),
                                                    mitm_applied: true,
                                                    bypass_reason: None,
                                                };

                                                // Store request metadata and start time for correlation
                                                pending_requests.insert(stream_id, (metadata, Instant::now()));

                                                // Clear request frames from buffer (keep space for response)
                                                stream_buffers.get_mut(&stream_id).unwrap().clear();
                                            }
                                            Err(e) => {
                                                debug!(error = ?e, stream_id = stream_id, "Failed to extract HTTP/2 request");
                                                // Clean up on error
                                                stream_buffers.remove(&stream_id);
                                            }
                                        }
                                    }
                                }
                            }

                            // Forward frame to upstream
                            if let Err(e) = upstream.write_all(&client_frame_header).await {
                                debug!(error = %e, "Failed to forward frame header to upstream");
                                break;
                            }
                            if let Err(e) = upstream.write_all(&payload).await {
                                debug!(error = %e, "Failed to forward frame payload to upstream");
                                break;
                            }
                        }
                        Err(_) => {
                            debug!("Client closed HTTP/2 connection");
                            break;
                        }
                    }
                }

                // Read from upstream, forward to client
                result = upstream.read_exact(&mut upstream_frame_header) => {
                    match result {
                        Ok(_) => {
                            // Parse frame header
                            let (frame_type, flags, stream_id, length) = match parse_frame_header(&upstream_frame_header) {
                                Ok(header) => header,
                                Err(e) => {
                                    warn!(error = ?e, "Failed to parse upstream HTTP/2 frame header");
                                    break;
                                }
                            };

                            // Read frame payload
                            let mut payload = vec![0u8; length];
                            if let Err(e) = upstream.read_exact(&mut payload).await {
                                debug!(error = %e, "Failed to read upstream HTTP/2 frame payload");
                                break;
                            }

                            total_bytes += (9 + length) as u64;

                            // Buffer HEADERS and DATA frames for response extraction
                            // Responses come on the SAME client-initiated (odd) stream ID
                            if matches!(frame_type, FrameType::Headers | FrameType::Data | FrameType::Continuation) && is_client_stream(stream_id) {
                                let frame = Http2Frame {
                                    frame_type,
                                    flags,
                                    stream_id,
                                    payload_length: length,
                                    payload: payload.clone(),
                                };
                                stream_buffers.entry(stream_id).or_insert_with(Vec::new).push(frame.clone());

                                // If END_STREAM flag set, extract response and correlate with request
                                if has_end_stream(&frame) {
                                    if let Some(frames) = stream_buffers.get(&stream_id) {
                                        match extract_http2_response(frames, &mut upstream_decoder) {
                                            Ok(response) => {
                                                debug!(
                                                    status = response.status,
                                                    stream_id = stream_id,
                                                    "HTTP/2 response extracted"
                                                );

                                                // Correlate with pending request
                                                if let Some((mut metadata, request_start)) = pending_requests.remove(&stream_id) {
                                                    // Fill in response details
                                                    metadata.status_code = Some(response.status);
                                                    metadata.response_size = response.content_length.unwrap_or(0);
                                                    metadata.duration_ms = request_start.elapsed().as_millis() as u64;

                                                    // Apply PII redaction if enabled
                                                    if self.logging_policy.enable_pii_redaction {
                                                        metadata.path = PiiRedactor::redact(&metadata.path);
                                                    }

                                                    // Log complete request/response
                                                    if let Some(storage) = &self.log_storage {
                                                        let storage_clone = Arc::clone(storage);
                                                        tokio::spawn(async move {
                                                            if let Err(e) = storage_clone.log_request(&metadata).await {
                                                                warn!(error = %e, "Failed to log HTTP/2 request/response");
                                                            }
                                                        });
                                                    }
                                                } else {
                                                    debug!(stream_id = stream_id, "Received response without matching request");
                                                }
                                            }
                                            Err(e) => {
                                                debug!(error = ?e, stream_id = stream_id, "Failed to extract HTTP/2 response");
                                            }
                                        }

                                        // Clear stream buffer to free memory
                                        stream_buffers.remove(&stream_id);
                                    }
                                }
                            }

                            // Forward frame to client
                            if let Err(e) = client.write_all(&upstream_frame_header).await {
                                debug!(error = %e, "Failed to forward frame header to client");
                                break;
                            }
                            if let Err(e) = client.write_all(&payload).await {
                                debug!(error = %e, "Failed to forward frame payload to client");
                                break;
                            }
                        }
                        Err(_) => {
                            debug!("Upstream closed HTTP/2 connection");
                            break;
                        }
                    }
                }
            }
        }

        let duration = start_time.elapsed();
        debug!(
            target_host = %target_host,
            bytes_transferred = total_bytes,
            duration_ms = duration.as_millis(),
            pending_requests = pending_requests.len(),
            buffered_streams = stream_buffers.len(),
            "HTTP/2 proxying completed"
        );

        Ok(total_bytes)
    }

    /// Build client-facing TLS config from fake certificate
    fn build_client_tls_config(
        &self,
        fake_cert: &rcgen::Certificate,
    ) -> Result<ClientTlsConfig, InterceptionError> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        // Serialize certificate
        let cert_der = fake_cert.serialize_der().map_err(|e| {
            InterceptionError::MitmError(MitmError::CertGenerationFailed(e.to_string()))
        })?;

        let cert_chain = vec![CertificateDer::from(cert_der)];

        // Serialize private key
        let key_der = fake_cert.serialize_private_key_der();
        let private_key = PrivateKeyDer::Pkcs8(key_der.into());

        // Build TLS config
        ClientTlsConfig::new(cert_chain, private_key)
            .map_err(|e| InterceptionError::TlsHandshakeFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    

    // TODO: Add tests for:
    // - Successful interception flow
    // - Bypass logic (static rules, localhost)
    // - TLS handshake (client and upstream)
    // - Certificate generation
    // - Logging policy enforcement
}
