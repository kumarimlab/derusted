use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{info, warn, error};

mod config;
mod tls;
mod server;
mod reload;
mod auth;                // Phase 2: JWT authentication
mod rate_limiter;        // Phase 2: Rate limiting
mod logger;              // Request logging to backend
mod destination_filter;  // SSRF protection
mod ip_tracker;          // IP-per-token limits
mod http_client;         // Minimal HTTP client (TcpStream + httparse)
mod body_limiter;        // Streaming body size enforcement
mod http_metrics;        // Prometheus metrics for HTTP forwarding
mod mixed_content;       // Mixed content policy enforcement

use config::Config;
use reload::ReloadableTlsAcceptor;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
        )
        .json()
        .init();

    info!("Starting Rust Forward Proxy Server...");

    // Load configuration
    let config = Arc::new(Config::from_env()?);
    info!("Configuration loaded");

    // Start background cleanup task for rate limiter (runs every 60 seconds)
    rate_limiter::RateLimiter::start_cleanup_task(Arc::clone(&config.rate_limiter), 60);
    info!("Rate limiter cleanup task started (interval: 60s)");

    // Start background logging task (flushes every log_batch_interval_secs)
    Arc::clone(&config.request_logger).start_background_flush();
    info!(
        "Request logger started (batch_size={}, interval={}s)",
        config.log_batch_size, config.log_batch_interval_secs
    );

    // Setup reloadable TLS acceptor with HTTP/2 ALPN
    let tls_acceptor = ReloadableTlsAcceptor::new(
        config.cert_path.clone(),
        config.key_path.clone(),
    )?;
    info!("TLS configured with ALPN protocols: h2, http/1.1");
    info!("Certificate hot-reload enabled via SIGHUP");

    // Bind TCP listener
    let bind_addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("Listening on {}", bind_addr);

    // Setup signal handlers
    let tls_acceptor_for_reload = tls_acceptor.clone();
    let _reload_handle = tokio::spawn(async move {
        reload_signal_handler(tls_acceptor_for_reload).await;
    });

    let mut shutdown = tokio::spawn(async {
        shutdown_signal().await;
        info!("Shutdown signal received");
    });

    // Accept connections
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer_addr)) => {
                        info!("Accepted connection from {}", peer_addr);

                        let tls_acceptor = tls_acceptor.clone();
                        let config = Arc::clone(&config);

                        tokio::spawn(async move {
                            // Get current TLS acceptor (supports hot-reload)
                            let acceptor = tls_acceptor.get().await;
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    // Get negotiated ALPN protocol
                                    let alpn_protocol = tls_stream
                                        .get_ref()
                                        .1
                                        .alpn_protocol()
                                        .map(|p| String::from_utf8_lossy(p).to_string());

                                    info!("ALPN negotiated: {:?}", alpn_protocol);

                                    // Route based on ALPN protocol
                                    match alpn_protocol.as_deref() {
                                        Some("h2") => {
                                            info!("HTTP/2 connection established");
                                            if let Err(e) = server::serve_h2(tls_stream, config).await {
                                                error!("HTTP/2 server error: {}", e);
                                            }
                                        }
                                        Some("http/1.1") | None => {
                                            info!("HTTP/1.1 connection established");
                                            if let Err(e) = server::serve_http1(tls_stream, config).await {
                                                error!("HTTP/1.1 server error: {}", e);
                                            }
                                        }
                                        Some(proto) => {
                                            warn!("Unsupported ALPN protocol: {}", proto);
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("TLS handshake failed: {}", e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
            _ = &mut shutdown => {
                info!("Shutting down server...");
                break;
            }
        }
    }

    Ok(())
}

/// Certificate reload signal handler (SIGHUP)
async fn reload_signal_handler(tls_acceptor: ReloadableTlsAcceptor) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sighup = signal(SignalKind::hangup())
            .expect("Failed to install SIGHUP handler");

        loop {
            sighup.recv().await;
            info!("SIGHUP received - initiating certificate reload");

            if let Err(e) = tls_acceptor.reload().await {
                error!("Certificate reload failed: {}", e);
            }
        }
    }

    #[cfg(not(unix))]
    {
        // Windows doesn't support SIGHUP
        info!("Certificate hot-reload via SIGHUP not supported on Windows");
        info!("Certificates can only be reloaded by restarting the server");
        std::future::pending::<()>().await;
    }
}

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    // Handle SIGINT (Ctrl+C)
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received SIGINT (Ctrl+C)");
        },
        _ = terminate => {
            info!("Received SIGTERM");
        },
    }
}
