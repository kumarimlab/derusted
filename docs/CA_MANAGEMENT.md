# CA Certificate Management

## Overview

The CA (Certificate Authority) management system handles loading, validating, and exporting CA certificates for MITM operations.

## Architecture

```
┌─────────────────┐
│  Vault/KMS      │  ← CA private key + certificate stored securely
│  (Secret Store) │
└────────┬────────┘
         │ Load via SecretBackend trait
         ↓
┌─────────────────┐
│  CaKeyManager   │  ← Zero-on-drop, fail-fast, per-environment
└────────┬────────┘
         │ Provides CA for signing
         ↓
┌──────────────────┐
│ CertificateAuth  │  ← Generates certificates on-demand
└──────────────────┘
```

## Loading CA from Vault

### Step 1: Store CA in Vault

```bash
# Store CA private key and certificate in Vault KV v2
vault kv put secret/ca/production \
  private_key=@ca-key.pem \
  certificate=@ca-cert.pem

# Verify
vault kv get secret/ca/production
```

### Step 2: Load CA in Code

```rust
use derusted::{CaKeyManager, VaultBackend, Environment};
use secrecy::SecretString;
use std::sync::Arc;

// Create Vault backend
let vault_backend = VaultBackend::new(
    "https://vault.example.com:8200".to_string(),
    SecretString::new(vault_token),
    "secret".to_string(), // Mount path
)?;

// Load CA (fail-fast if missing/invalid)
let ca_manager = CaKeyManager::load_or_fail(
    Arc::new(vault_backend),
    Environment::Production
).await?;

// CA is now loaded and validated
println!("CA loaded for environment: {:?}", ca_manager.environment());
```

## CA Validation

The system automatically validates CA certificates on load:

### 1. Basic Constraints
- **Check**: `basicConstraints.ca = true`
- **Requirement**: MUST be a CA certificate
- **Error**: "Certificate is not a CA (basicConstraints.ca = false)"

### 2. Key Usage
- **Check**: `keyUsage.keyCertSign = true`
- **Requirement**: MUST have certificate signing capability
- **Error**: "Certificate missing keyCertSign usage (required for CA)"
- **Optional**: `keyUsage.cRLSign = true` (for CRL support)

### 3. Validity Period
- **Check**: Current time within `notBefore` and `notAfter`
- **Errors**:
  - "Certificate not yet valid (notBefore: ...)"
  - "Certificate expired (notAfter: ...)"

### Validation Logs

```
[INFO] CA validation: basicConstraints.ca = true ✓
[INFO] CA validation: keyUsage checked ✓ (keyCertSign=true, crlSign=true)
[INFO] CA validation: validity period checked ✓ (notBefore=2025-01-01, notAfter=2030-01-01)
[INFO] CA key loaded and validated successfully
```

## Exporting CA Certificate

### For Trust Distribution

Export the CA certificate (public key only) for installation on client systems:

```rust
// Export to string
let ca_pem = ca_manager.export_ca_certificate_pem()?;
println!("{}", ca_pem);

// Export to file
ca_manager.export_ca_certificate_to_file("./ca.crt")?;
```

### Using Trust Distribution Scripts

Once exported, use the platform-specific scripts:

```bash
# Linux
sudo ./scripts/install-ca-linux.sh ./ca.crt

# macOS
sudo ./scripts/install-ca-macos.sh ./ca.crt

# Windows (PowerShell as Administrator)
.\scripts\install-ca-windows.ps1 .\ca.crt

# Firefox (all platforms)
./scripts/install-ca-firefox.sh ./ca.crt
```

See [Trust Distribution Scripts](../scripts/README.md) for details.

## Per-Environment CA Isolation

The system supports separate CAs for different environments:

```rust
// Development CA
let dev_ca = CaKeyManager::load_or_fail(
    Arc::clone(&backend),
    Environment::Development
).await?;

// Staging CA
let staging_ca = CaKeyManager::load_or_fail(
    Arc::clone(&backend),
    Environment::Staging
).await?;

// Production CA
let prod_ca = CaKeyManager::load_or_fail(
    Arc::clone(&backend),
    Environment::Production
).await?;
```

### Vault Path Structure

```
secret/
├── ca/
│   ├── development/
│   │   ├── private_key
│   │   └── certificate
│   ├── staging/
│   │   ├── private_key
│   │   └── certificate
│   └── production/
│       ├── private_key
│       └── certificate
```

## Security Features

### 1. Zero-on-Drop
Private keys use `secrecy::SecretString` and are zeroed when dropped:
```rust
// CA private key is automatically zeroed on drop
drop(ca_manager); // Private key securely erased from memory
```

### 2. No Logging
Private keys never appear in logs:
```rust
println!("{:?}", ca_manager);
// Output: CaKeyManager { environment: Production, key_pair: "<REDACTED>", ... }
```

### 3. Fail-Fast
Proxy refuses to start if CA is missing or invalid:
```rust
match CaKeyManager::load_or_fail(backend, env).await {
    Ok(ca) => { /* Continue startup */ },
    Err(e) => {
        eprintln!("FATAL: Failed to load CA: {}", e);
        std::process::exit(1);
    }
}
```

## Troubleshooting

### CA Not Loading

**Error**: "CA key missing or inaccessible"
```
[ERROR] Vault KV read failed: secret not found
```

**Solution**: Verify CA exists in Vault:
```bash
vault kv get secret/ca/production
```

### Validation Failures

**Error**: "Certificate is not a CA"
```
[ERROR] Certificate is not a CA (basicConstraints.ca = false)
```

**Solution**: Ensure certificate has `basicConstraints` with `ca=true`:
```bash
openssl x509 -in ca.crt -text -noout | grep -A 1 "Basic Constraints"
# Should show: CA:TRUE
```

**Error**: "Certificate missing keyCertSign usage"
```
[ERROR] Certificate missing keyCertSign usage (required for CA)
```

**Solution**: Ensure certificate has proper key usage:
```bash
openssl x509 -in ca.crt -text -noout | grep -A 1 "Key Usage"
# Should show: Certificate Sign, CRL Sign
```

**Error**: "Certificate expired"
```
[ERROR] Certificate expired (notAfter: 2024-01-01 00:00:00 UTC)
```

**Solution**: Generate new CA certificate or renew existing one.

### Vault Connection Issues

**Error**: "Vault health check failed"
```
[ERROR] Vault health check failed: connection refused
```

**Solutions**:
1. Verify Vault is running:
   ```bash
   vault status
   ```

2. Check Vault address:
   ```bash
   echo $VAULT_ADDR
   ```

3. Verify Vault is unsealed:
   ```bash
   vault status | grep Sealed
   # Should show: Sealed   false
   ```

## CA Rotation

### Emergency Rotation (< 4 hours)

See [SECURITY.md](./SECURITY.md) for emergency CA rotation playbook.

### Planned Rotation

1. Generate new CA certificate
2. Store in Vault under new path
3. Update environment configuration
4. Restart proxy with new CA
5. Distribute new CA to clients
6. Deprecate old CA after grace period

## Best Practices

### 1. Use Separate CAs per Environment
```rust
// ✓ Good: Separate CAs
let dev_ca = load_ca(Environment::Development);
let prod_ca = load_ca(Environment::Production);

// ✗ Bad: Shared CA
let ca = load_ca(Environment::Production);
// Using same CA for all environments
```

### 2. Secure Vault Access
```bash
# Use AppRole or Kubernetes auth, not root token
vault auth enable approle
vault write auth/approle/role/derusted \
  secret_id_ttl=10m \
  token_ttl=20m \
  token_max_ttl=30m \
  policies="ca-read"
```

### 3. Monitor CA Expiration
```rust
// Check CA expiration periodically
let ca = ca_manager.certificate();
// Parse and check notAfter date
// Alert if < 30 days remaining
```

### 4. Audit CA Access
```bash
# Enable Vault audit logging
vault audit enable file file_path=/var/log/vault/audit.log

# Review CA access
grep "secret/ca/" /var/log/vault/audit.log
```

## API Reference

### `CaKeyManager`

```rust
impl CaKeyManager {
    /// Load CA from backend or fail (blocking)
    pub async fn load_or_fail(
        backend: Arc<dyn SecretBackend>,
        environment: Environment,
    ) -> Result<Self, StartupError>;

    /// Get CA certificate (safe to expose)
    pub fn certificate(&self) -> Arc<Certificate>;

    /// Get environment
    pub fn environment(&self) -> Environment;

    /// Export CA certificate in PEM format
    pub fn export_ca_certificate_pem(&self) -> Result<String>;

    /// Export CA certificate to file
    pub fn export_ca_certificate_to_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<()>;
}
```

### `SecretBackend` Trait

```rust
#[async_trait::async_trait]
pub trait SecretBackend: Send + Sync {
    /// Load CA private key from backend
    async fn load_ca_key(&self, environment: Environment) 
        -> Result<SecretString, StartupError>;

    /// Load CA certificate from backend
    async fn load_ca_cert(&self, environment: Environment) 
        -> Result<String, StartupError>;

    /// Health check for backend connectivity
    async fn health_check(&self) -> Result<(), StartupError>;
}
```

### `VaultBackend`

```rust
impl VaultBackend {
    /// Create new Vault backend
    pub fn new(
        vault_addr: String,
        vault_token: SecretString,
        mount_path: String,
    ) -> Result<Self, StartupError>;
}
```

## See Also

- [Trust Distribution Scripts](../scripts/README.md)
- [Security Guidelines](./SECURITY.md)
- [MITM Architecture](./MITM.md)
