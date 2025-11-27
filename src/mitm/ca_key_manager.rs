//! CA Key Manager - Secure storage and retrieval of CA private keys
//!
//! This module handles loading CA private keys from Vault/KMS backends.
//! The private key is kept in memory using the `secrecy` crate for zero-on-drop.

use anyhow::{Context, Result};
use rcgen::{Certificate, CertificateParams, KeyPair};
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use thiserror::Error;
use tracing::{info, warn};

/// Environment for CA isolation (separate CAs per environment)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Staging,
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Development => "development",
            Environment::Staging => "staging",
            Environment::Production => "production",
        }
    }
}

/// Errors that can occur during startup when loading CA
#[derive(Debug, Error)]
pub enum StartupError {
    #[error("CA key missing or inaccessible: {0}")]
    CaKeyMissing(String),

    #[error("CA certificate invalid: {0}")]
    CaCertInvalid(String),

    #[error("Vault/KMS backend error: {0}")]
    BackendError(String),

    #[error("CA key format error: {0}")]
    KeyFormatError(String),
}

/// Trait for secret storage backends (Vault, KMS, etc.)
#[async_trait::async_trait]
pub trait SecretBackend: Send + Sync {
    /// Load CA private key from backend
    async fn load_ca_key(&self, environment: Environment) -> Result<SecretString, StartupError>;

    /// Load CA certificate from backend
    async fn load_ca_cert(&self, environment: Environment) -> Result<String, StartupError>;

    /// Health check for backend connectivity
    async fn health_check(&self) -> Result<(), StartupError>;
}

/// Vault backend implementation
pub struct VaultBackend {
    client: vaultrs::client::VaultClient,
    mount_path: String,
    key_path_template: String,  // e.g., "ca/{environment}/key"
    cert_path_template: String, // e.g., "ca/{environment}/cert"
}

impl VaultBackend {
    /// Create new Vault backend
    pub fn new(
        vault_addr: String,
        vault_token: SecretString,
        mount_path: String,
    ) -> Result<Self, StartupError> {
        let client = vaultrs::client::VaultClient::new(
            vaultrs::client::VaultClientSettingsBuilder::default()
                .address(&vault_addr)
                .token(vault_token.expose_secret())
                .build()
                .map_err(|e| StartupError::BackendError(e.to_string()))?,
        )
        .map_err(|e| StartupError::BackendError(e.to_string()))?;

        Ok(Self {
            client,
            mount_path,
            key_path_template: "ca/{environment}/key".to_string(),
            cert_path_template: "ca/{environment}/cert".to_string(),
        })
    }
}

#[async_trait::async_trait]
impl SecretBackend for VaultBackend {
    async fn load_ca_key(&self, environment: Environment) -> Result<SecretString, StartupError> {
        let path = self
            .key_path_template
            .replace("{environment}", environment.as_str());

        info!(
            environment = environment.as_str(),
            path = %path,
            "Loading CA key from Vault"
        );

        // Read secret from Vault KV v2
        let secret: std::collections::HashMap<String, String> =
            vaultrs::kv2::read(&self.client, &self.mount_path, &path)
                .await
                .map_err(|e| StartupError::BackendError(format!("Vault KV read failed: {}", e)))?;

        // Extract private key field
        let key_pem = secret.get("private_key").ok_or_else(|| {
            StartupError::CaKeyMissing(format!(
                "'private_key' field not found in Vault secret at {}",
                path
            ))
        })?;

        Ok(SecretString::new(key_pem.clone()))
    }

    async fn load_ca_cert(&self, environment: Environment) -> Result<String, StartupError> {
        let path = self
            .cert_path_template
            .replace("{environment}", environment.as_str());

        info!(
            environment = environment.as_str(),
            path = %path,
            "Loading CA certificate from Vault"
        );

        // Read secret from Vault KV v2
        let secret: std::collections::HashMap<String, String> =
            vaultrs::kv2::read(&self.client, &self.mount_path, &path)
                .await
                .map_err(|e| StartupError::BackendError(format!("Vault KV read failed: {}", e)))?;

        // Extract certificate field
        let cert_pem = secret.get("certificate").ok_or_else(|| {
            StartupError::CaCertInvalid(format!(
                "'certificate' field not found in Vault secret at {}",
                path
            ))
        })?;

        Ok(cert_pem.clone())
    }

    async fn health_check(&self) -> Result<(), StartupError> {
        // Check Vault health endpoint
        let health = vaultrs::sys::health(&self.client)
            .await
            .map_err(|e| StartupError::BackendError(format!("Vault health check failed: {}", e)))?;

        // Verify Vault is initialized and unsealed
        if !health.initialized {
            return Err(StartupError::BackendError(
                "Vault is not initialized".to_string(),
            ));
        }

        if health.sealed {
            return Err(StartupError::BackendError("Vault is sealed".to_string()));
        }

        info!("Vault health check passed");
        Ok(())
    }
}

/// CA Key Manager - Manages CA private key with secure storage
pub struct CaKeyManager {
    /// CA private key (zeroed on drop, never logged)
    key_pair: Arc<KeyPair>,

    /// CA certificate (public, safe to log)
    certificate: Arc<Certificate>,

    /// Environment this CA is for
    environment: Environment,

    /// Backend for key storage
    backend: Arc<dyn SecretBackend>,
}

impl CaKeyManager {
    /// Load CA from backend or fail fast
    ///
    /// This is a blocking operation that should be called during startup.
    /// If the CA key is missing or invalid, the proxy MUST NOT start.
    pub async fn load_or_fail(
        backend: Arc<dyn SecretBackend>,
        environment: Environment,
    ) -> Result<Self, StartupError> {
        info!(
            environment = environment.as_str(),
            "Loading CA key from backend"
        );

        // Health check backend first
        backend.health_check().await.map_err(|e| {
            StartupError::BackendError(format!("Backend health check failed: {}", e))
        })?;

        // Load CA private key (will be zeroed on drop)
        let key_pem = backend.load_ca_key(environment).await?;

        // Load CA certificate
        let cert_pem = backend.load_ca_cert(environment).await?;

        // Parse key pair (rcgen 0.12 from_ca_cert_pem takes ownership, so parse twice)
        let key_pair_for_cert = KeyPair::from_pem(key_pem.expose_secret())
            .map_err(|e| StartupError::KeyFormatError(e.to_string()))?;

        let key_pair = KeyPair::from_pem(key_pem.expose_secret())
            .map_err(|e| StartupError::KeyFormatError(e.to_string()))?;

        // Parse certificate with key pair (rcgen 0.12 API - takes ownership)
        let cert_params = CertificateParams::from_ca_cert_pem(&cert_pem, key_pair_for_cert)
            .map_err(|e| StartupError::CaCertInvalid(e.to_string()))?;

        let certificate = Certificate::from_params(cert_params)
            .map_err(|e| StartupError::CaCertInvalid(e.to_string()))?;

        // Validate certificate is a proper CA
        Self::validate_ca_certificate(&cert_pem)?;

        info!(
            environment = environment.as_str(),
            "CA key loaded and validated successfully"
        );

        Ok(Self {
            key_pair: Arc::new(key_pair),
            certificate: Arc::new(certificate),
            environment,
            backend,
        })
    }

    /// Get CA certificate (safe to expose)
    pub fn certificate(&self) -> Arc<Certificate> {
        Arc::clone(&self.certificate)
    }

    /// Get CA key pair (for signing certificates)
    pub(crate) fn key_pair(&self) -> Arc<KeyPair> {
        Arc::clone(&self.key_pair)
    }

    /// Get environment
    pub fn environment(&self) -> Environment {
        self.environment
    }

    /// Export CA certificate in PEM format (for trust distribution)
    ///
    /// This returns the public CA certificate that can be distributed
    /// to client systems for trust. The private key is never exported.
    pub fn export_ca_certificate_pem(&self) -> Result<String> {
        self.certificate
            .serialize_pem()
            .context("Failed to serialize CA certificate to PEM")
    }

    /// Export CA certificate to file (for trust distribution)
    ///
    /// Writes the CA certificate to the specified path in PEM format.
    /// This is the certificate that should be installed on client systems.
    pub fn export_ca_certificate_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let pem = self.export_ca_certificate_pem()?;
        std::fs::write(path.as_ref(), pem).context("Failed to write CA certificate to file")?;

        info!(
            path = ?path.as_ref(),
            environment = self.environment.as_str(),
            "CA certificate exported successfully"
        );

        Ok(())
    }

    /// Validate CA certificate properties
    fn validate_ca_certificate(cert_pem: &str) -> Result<(), StartupError> {
        use x509_parser::prelude::*;

        // Parse PEM to DER using x509-parser's built-in PEM parser
        let (_, pem_data) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| StartupError::CaCertInvalid(format!("PEM parse failed: {}", e)))?;

        // Parse X.509 certificate
        let (_, cert) = X509Certificate::from_der(&pem_data.contents)
            .map_err(|e| StartupError::CaCertInvalid(format!("X.509 parse failed: {}", e)))?;

        // 1. Check basicConstraints extension
        if let Some(basic_constraints) = cert.basic_constraints().map_err(|e| {
            StartupError::CaCertInvalid(format!("Failed to read basicConstraints: {}", e))
        })? {
            if !basic_constraints.value.ca {
                return Err(StartupError::CaCertInvalid(
                    "Certificate is not a CA (basicConstraints.ca = false)".to_string(),
                ));
            }

            info!("CA validation: basicConstraints.ca = true ✓");
        } else {
            warn!("CA certificate missing basicConstraints extension (will accept but not recommended)");
        }

        // 2. Check keyUsage extension
        if let Some(key_usage) = cert
            .key_usage()
            .map_err(|e| StartupError::CaCertInvalid(format!("Failed to read keyUsage: {}", e)))?
        {
            let has_key_cert_sign = key_usage.value.key_cert_sign();
            let has_crl_sign = key_usage.value.crl_sign();

            if !has_key_cert_sign {
                return Err(StartupError::CaCertInvalid(
                    "Certificate missing keyCertSign usage (required for CA)".to_string(),
                ));
            }

            info!(
                key_cert_sign = has_key_cert_sign,
                crl_sign = has_crl_sign,
                "CA validation: keyUsage checked ✓"
            );
        } else {
            warn!("CA certificate missing keyUsage extension (will accept but not recommended)");
        }

        // 3. Check validity period
        let now = chrono::Utc::now();
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        let current = now.timestamp();

        if current < not_before {
            return Err(StartupError::CaCertInvalid(format!(
                "Certificate not yet valid (notBefore: {})",
                cert.validity().not_before
            )));
        }

        if current > not_after {
            return Err(StartupError::CaCertInvalid(format!(
                "Certificate expired (notAfter: {})",
                cert.validity().not_after
            )));
        }

        info!(
            not_before = %cert.validity().not_before,
            not_after = %cert.validity().not_after,
            "CA validation: validity period checked ✓"
        );

        Ok(())
    }
}

// Ensure KeyPair doesn't leak in Debug output
impl std::fmt::Debug for CaKeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaKeyManager")
            .field("environment", &self.environment)
            .field("key_pair", &"<REDACTED>")
            .field("certificate", &"<present>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    

    // TODO: Add tests for:
    // - CA loading from mock backend
    // - Fail-fast behavior when CA missing
    // - Per-environment CA isolation
    // - Key pair never logged
}
