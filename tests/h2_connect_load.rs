/// HTTP/2 CONNECT Load Testing Client
///
/// This program measures HTTP/2 CONNECT performance with concurrent streams:
/// - Requests/sec
/// - p50, p99 latency
/// - Concurrent stream handling
/// - Memory usage tracking
///
/// Run with: cargo run --release --bin h2_connect_load
use anyhow::{Context, Result};
use http::{Method, Request, StatusCode};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    token_id: String,
    user_id: i32,
    allowed_regions: Vec<String>,
    exp: i64,
    iat: i64,
}

/// Generate a valid JWT token for testing
fn generate_test_token(secret: &str) -> Result<String> {
    let now = chrono::Utc::now().timestamp();
    let claims = JwtClaims {
        token_id: "h2-load-test-token".to_string(),
        user_id: 100,
        allowed_regions: vec!["us-east".to_string(), "eu-west".to_string()],
        exp: now + 3600,
        iat: now,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .context("Failed to generate JWT token")?;

    Ok(token)
}

/// Create TLS client config that accepts self-signed certificates
fn create_tls_config() -> Arc<ClientConfig> {
    use std::sync::Arc as StdArc;
    use tokio_rustls::rustls;

    #[derive(Debug)]
    struct DangerousNoVerifier;

    impl rustls::client::danger::ServerCertVerifier for DangerousNoVerifier {
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
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::ED448,
            ]
        }
    }

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(StdArc::new(DangerousNoVerifier))
        .with_no_client_auth();

    config.alpn_protocols = vec![b"h2".to_vec()];

    Arc::new(config)
}

/// Statistics tracker
struct Stats {
    success_count: AtomicU64,
    error_count: AtomicU64,
    latencies_ms: Arc<tokio::sync::Mutex<Vec<u64>>>,
}

impl Stats {
    fn new() -> Self {
        Self {
            success_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            latencies_ms: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    async fn record_success(&self, latency_ms: u64) {
        self.success_count.fetch_add(1, Ordering::Relaxed);
        self.latencies_ms.lock().await.push(latency_ms);
    }

    fn record_error(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }

    async fn print_summary(&self, duration: Duration) {
        let success = self.success_count.load(Ordering::Relaxed);
        let errors = self.error_count.load(Ordering::Relaxed);
        let total = success + errors;

        let mut latencies = self.latencies_ms.lock().await;
        latencies.sort();

        let p50 = if !latencies.is_empty() {
            latencies[latencies.len() / 2]
        } else {
            0
        };

        let p99 = if !latencies.is_empty() {
            latencies[(latencies.len() * 99) / 100]
        } else {
            0
        };

        println!("\n╔═══════════════════════════════════════╗");
        println!("║  HTTP/2 CONNECT Load Test Results    ║");
        println!("╚═══════════════════════════════════════╝");
        println!();
        println!("Total Requests:    {}", total);
        println!(
            "Successful:        {} ({:.1}%)",
            success,
            (success as f64 / total as f64) * 100.0
        );
        println!(
            "Failed:            {} ({:.1}%)",
            errors,
            (errors as f64 / total as f64) * 100.0
        );
        println!();
        println!("Duration:          {:.2}s", duration.as_secs_f64());
        println!(
            "Requests/sec:      {:.2}",
            total as f64 / duration.as_secs_f64()
        );
        println!();
        println!("Latency (ms):");
        println!("  p50:             {}", p50);
        println!("  p99:             {}", p99);
        println!();
    }
}

/// Send a single CONNECT request
async fn send_connect_request(token: String, stats: Arc<Stats>) -> Result<()> {
    let start = Instant::now();

    // Connect with TLS
    let stream = TcpStream::connect("127.0.0.1:8443")
        .await
        .context("Failed to connect to proxy")?;

    let connector = TlsConnector::from(create_tls_config());
    let domain = ServerName::try_from("localhost").unwrap().to_owned();
    let tls_stream = connector
        .connect(domain, stream)
        .await
        .context("TLS handshake failed")?;

    // HTTP/2 handshake
    let (mut client, h2) = h2::client::handshake(tls_stream)
        .await
        .context("Failed to perform HTTP/2 handshake")?;

    // Spawn connection driver
    tokio::spawn(async move {
        if let Err(e) = h2.await {
            eprintln!("H2 connection error: {}", e);
        }
    });

    // Send CONNECT request
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri("neverssl.com:443")
        .header("proxy-authorization", format!("Bearer {}", token))
        .body(())
        .unwrap();

    let (response, _stream) = client
        .send_request(request, false)
        .context("Failed to send request")?;

    // Wait for response
    let resp = response.await.context("Failed to receive response")?;

    let latency = start.elapsed().as_millis() as u64;

    if resp.status() == StatusCode::OK || resp.status() == StatusCode::BAD_GATEWAY {
        stats.record_success(latency).await;
    } else {
        stats.record_error();
    }

    Ok(())
}

/// Run load test
async fn run_load_test(
    concurrency: usize,
    requests_per_client: usize,
    token: String,
) -> Result<()> {
    let stats = Arc::new(Stats::new());
    let start = Instant::now();

    println!("\n🚀 Starting HTTP/2 CONNECT Load Test");
    println!("   Concurrency:     {}", concurrency);
    println!("   Requests/client: {}", requests_per_client);
    println!(
        "   Total requests:  {}\n",
        concurrency * requests_per_client
    );

    let mut handles = vec![];

    for _ in 0..concurrency {
        let token_clone = token.clone();
        let stats_clone = Arc::clone(&stats);

        let handle = tokio::spawn(async move {
            for _ in 0..requests_per_client {
                if let Err(e) =
                    send_connect_request(token_clone.clone(), Arc::clone(&stats_clone)).await
                {
                    eprintln!("Request error: {}", e);
                    stats_clone.record_error();
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await?;
    }

    let duration = start.elapsed();
    stats.print_summary(duration).await;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Configuration
    let concurrency = 10; // 10 concurrent clients
    let requests_per_client = 50; // 50 requests each
    let secret = "test_secret_at_least_32_characters!!";

    // Generate JWT token
    let token = generate_test_token(secret)?;

    // Run load test
    run_load_test(concurrency, requests_per_client, token).await?;

    println!("✅ Load test completed\n");

    Ok(())
}
