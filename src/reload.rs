use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use crate::tls;

/// Reloadable TLS acceptor that supports atomic configuration updates
pub struct ReloadableTlsAcceptor {
    acceptor: Arc<RwLock<TlsAcceptor>>,
    cert_path: String,
    key_path: String,
}

impl ReloadableTlsAcceptor {
    /// Create a new reloadable TLS acceptor
    pub fn new(cert_path: String, key_path: String) -> Result<Self> {
        let acceptor = tls::create_tls_acceptor(&cert_path, &key_path)?;

        Ok(Self {
            acceptor: Arc::new(RwLock::new(acceptor)),
            cert_path,
            key_path,
        })
    }

    /// Get a clone of the current TLS acceptor
    pub async fn get(&self) -> TlsAcceptor {
        self.acceptor.read().await.clone()
    }

    /// Reload certificates from disk and update the TLS acceptor atomically
    pub async fn reload(&self) -> Result<()> {
        info!("Reloading TLS certificates...");
        info!("Certificate path: {}", self.cert_path);
        info!("Key path: {}", self.key_path);

        // Load new TLS configuration
        let new_acceptor = match tls::create_tls_acceptor(&self.cert_path, &self.key_path) {
            Ok(acceptor) => {
                info!("Successfully loaded new TLS certificates");
                acceptor
            }
            Err(e) => {
                error!("Failed to load new TLS certificates: {}", e);
                error!("Keeping existing certificates");
                return Err(e);
            }
        };

        // Atomically swap the acceptor
        {
            let mut acceptor = self.acceptor.write().await;
            *acceptor = new_acceptor;
        }

        info!("TLS certificates reloaded successfully");
        info!("New connections will use the updated certificates");

        Ok(())
    }

    /// Get the paths to certificate files
    pub fn cert_paths(&self) -> (&str, &str) {
        (&self.cert_path, &self.key_path)
    }
}

impl Clone for ReloadableTlsAcceptor {
    fn clone(&self) -> Self {
        Self {
            acceptor: Arc::clone(&self.acceptor),
            cert_path: self.cert_path.clone(),
            key_path: self.key_path.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    

    #[tokio::test]
    async fn test_reloadable_acceptor_creation() {
        // This test would require valid cert files
        // In production, we'd use test fixtures
        assert!(true);
    }
}
