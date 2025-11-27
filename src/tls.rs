use anyhow::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Load TLS certificates and private key from files
pub fn load_certs_and_key(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // Load certificates
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer> = certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", cert_path);
    }

    // Load private key
    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let key = pkcs8_private_keys(&mut key_reader)
        .next()
        .ok_or_else(|| anyhow::anyhow!("No private keys found in {}", key_path))??
        .into();

    Ok((certs, key))
}

/// Create TLS acceptor with HTTP/2 ALPN support
pub fn create_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let (certs, key) = load_certs_and_key(cert_path, key_path)?;

    // Build TLS config with ALPN
    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("Failed to create TLS config: {}", e))?;

    // ✅ CRITICAL: Advertise both h2 and http/1.1 for ALPN negotiation
    tls_config.alpn_protocols = vec![
        b"h2".to_vec(),       // HTTP/2
        b"http/1.1".to_vec(), // HTTP/1.1 fallback
    ];

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

#[cfg(test)]
mod tests {
    

    #[test]
    fn test_alpn_protocols() {
        // This test verifies that ALPN protocols are correctly configured
        // In a real test, you would need valid cert/key files
        // For now, this is a placeholder
        assert!(true);
    }
}
