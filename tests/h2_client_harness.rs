/// HTTP/2 Extended CONNECT Client Test Harness
///
/// This standalone test program validates the HTTP/2 proxy handler by:
/// 1. Establishing an HTTP/2 connection to the proxy
/// 2. Sending CONNECT requests with various auth scenarios
/// 3. Validating responses (407, 403, 200, etc.)
///
/// Run with: cargo test --test h2_client_harness -- --nocapture
use anyhow::{Context, Result};
use http::{Method, Request, StatusCode};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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
        token_id: "test-token-h2-client".to_string(),
        user_id: 42,
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

    // Dangerous: Skip certificate verification for testing with self-signed certs
    // DO NOT use this in production!
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
            // Accept any certificate
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
            // Support all common signature schemes
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

    // Create config with dangerous no-op verifier
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(StdArc::new(DangerousNoVerifier))
        .with_no_client_auth();

    // Enable ALPN for HTTP/2
    config.alpn_protocols = vec![b"h2".to_vec()];

    Arc::new(config)
}

/// Test 1: Missing authentication should return 407
#[tokio::test]
async fn test_h2_missing_auth_returns_407() -> Result<()> {
    println!("\n=== Test 1: Missing Auth → 407 ===");

    // Connect to proxy
    let stream = TcpStream::connect("127.0.0.1:8443")
        .await
        .context("Failed to connect to proxy")?;

    // TLS handshake (accepts self-signed certs via custom verifier)
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
            eprintln!("HTTP/2 connection error: {}", e);
        }
    });

    // Send CONNECT request without auth
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri("example.com:443")
        .body(())
        .unwrap();

    let (response, _) = client
        .send_request(request, true)
        .context("Failed to send request")?;

    let response = response.await.context("Failed to receive response")?;

    println!("Status: {:?}", response.status());
    println!("Headers: {:?}", response.headers());

    assert_eq!(
        response.status(),
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "Expected 407 for missing auth"
    );

    assert!(
        response.headers().contains_key("proxy-authenticate"),
        "Expected Proxy-Authenticate header"
    );

    println!("✅ Test passed: 407 with Bearer challenge");

    Ok(())
}

/// Test 2: Invalid JWT should return 403
#[tokio::test]
async fn test_h2_invalid_jwt_returns_403() -> Result<()> {
    println!("\n=== Test 2: Invalid JWT → 403 ===");

    let stream = TcpStream::connect("127.0.0.1:8443")
        .await
        .context("Failed to connect to proxy")?;

    let connector = TlsConnector::from(create_tls_config());
    let domain = ServerName::try_from("localhost").unwrap().to_owned();
    let tls_stream = connector
        .connect(domain, stream)
        .await
        .context("TLS handshake failed")?;

    let (mut client, h2) = h2::client::handshake(tls_stream)
        .await
        .context("Failed to perform HTTP/2 handshake")?;

    tokio::spawn(async move {
        if let Err(e) = h2.await {
            eprintln!("HTTP/2 connection error: {}", e);
        }
    });

    // Send CONNECT with invalid JWT
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri("example.com:443")
        .header("proxy-authorization", "Bearer invalid.jwt.token")
        .body(())
        .unwrap();

    let (response, _) = client
        .send_request(request, true)
        .context("Failed to send request")?;

    let response = response.await.context("Failed to receive response")?;

    println!("Status: {:?}", response.status());

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Expected 403 for invalid JWT"
    );

    println!("✅ Test passed: 403 for invalid JWT");

    Ok(())
}

/// Test 3: Valid JWT should return 200 or 502 (depending on upstream)
#[tokio::test]
async fn test_h2_valid_jwt_returns_200() -> Result<()> {
    println!("\n=== Test 3: Valid JWT → 200 or 502 ===");

    let stream = TcpStream::connect("127.0.0.1:8443")
        .await
        .context("Failed to connect to proxy")?;

    let connector = TlsConnector::from(create_tls_config());
    let domain = ServerName::try_from("localhost").unwrap().to_owned();
    let tls_stream = connector
        .connect(domain, stream)
        .await
        .context("TLS handshake failed")?;

    let (mut client, h2) = h2::client::handshake(tls_stream)
        .await
        .context("Failed to perform HTTP/2 handshake")?;

    tokio::spawn(async move {
        if let Err(e) = h2.await {
            eprintln!("HTTP/2 connection error: {}", e);
        }
    });

    // Generate valid JWT
    let token = generate_test_token("test_secret_at_least_32_characters!!")?;

    // Send CONNECT with valid JWT
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri("neverssl.com:443")
        .header("proxy-authorization", format!("Bearer {}", token))
        .body(())
        .unwrap();

    let (response, _stream) = client
        .send_request(request, false)
        .context("Failed to send request")?;

    let response = response.await.context("Failed to receive response")?;

    println!("Status: {:?}", response.status());

    // Accept either 200 (success) or 502 (upstream unreachable)
    assert!(
        response.status() == StatusCode::OK || response.status() == StatusCode::BAD_GATEWAY,
        "Expected 200 or 502, got {:?}",
        response.status()
    );

    println!("✅ Test passed: Valid JWT accepted");

    Ok(())
}

/// Main test runner that provides instructions
#[test]
fn test_instructions() {
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║  HTTP/2 Extended CONNECT Test Harness                    ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("To run these tests:");
    println!();
    println!("1. Start the proxy server in another terminal:");
    println!("   $ TLS_CERT_PATH=/tmp/test-certs/cert.pem \\");
    println!("     TLS_KEY_PATH=/tmp/test-certs/key.pem \\");
    println!("     PROXY_PORT=8443 \\");
    println!("     JWT_SECRET='test_secret_at_least_32_characters!!' \\");
    println!("     cargo run --release");
    println!();
    println!("2. Run the HTTP/2 client tests:");
    println!("   $ cargo test --test h2_client_harness -- --nocapture");
    println!();
    println!("Tests will validate:");
    println!("  ✓ Missing auth → 407 Proxy Authentication Required");
    println!("  ✓ Invalid JWT → 403 Forbidden");
    println!("  ✓ Valid JWT → 200 OK or 502 Bad Gateway");
    println!();
    println!("Note: TLS verification is disabled for self-signed certs");
    println!();
}
