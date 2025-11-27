# Trust Distribution Scripts

These scripts help install the Derusted CA certificate on various platforms and browsers.

## Prerequisites

Before running these scripts, you need to export your CA certificate:

### Method 1: Programmatically (Recommended)

```rust
use derusted::{CaKeyManager, Environment};
use std::sync::Arc;

// Load CA manager
let backend = Arc::new(your_vault_backend);
let ca_manager = CaKeyManager::load_or_fail(backend, Environment::Production).await?;

// Export CA certificate to file
ca_manager.export_ca_certificate_to_file("./ca.crt")?;
```

### Method 2: From Vault Directly

If your CA is stored in Vault:

```bash
# Read from Vault KV v2
vault kv get -field=certificate secret/ca/production > ca.crt

# Verify it's a valid PEM certificate
openssl x509 -in ca.crt -text -noout
```

### Method 3: Using derusted CLI (if available)

```bash
# Export CA for current environment
derusted ca export --environment production --output ca.crt

# Verify the certificate
openssl x509 -in ca.crt -text -noout | grep -A 2 "Subject:"
```

**Important**: The exported file should be the **certificate only** (public key), never the private key.

## Linux (Debian/Ubuntu/Mint)

```bash
sudo ./install-ca-linux.sh /path/to/ca.crt
```

**What it does:**
- Copies CA certificate to `/usr/local/share/ca-certificates/`
- Runs `update-ca-certificates` to update system trust store
- Works with Chrome, Chromium, curl, wget, and most system tools

**Requires:** Root access (sudo)

## macOS

```bash
sudo ./install-ca-macos.sh /path/to/ca.crt
```

**What it does:**
- Imports CA certificate into System Keychain
- Marks it as trusted for SSL/TLS
- Works with Safari, Chrome, curl, and most macOS applications

**Requires:** Administrator privileges (sudo)

## Windows

```powershell
# Run PowerShell as Administrator
.\install-ca-windows.ps1 C:\path\to\ca.crt
```

**What it does:**
- Imports CA certificate into Trusted Root Certification Authorities
- Works with Edge, Chrome, and most Windows applications

**Requires:** Administrator privileges

## Firefox (Linux/macOS)

```bash
./install-ca-firefox.sh /path/to/ca.crt
```

**What it does:**
- Installs CA certificate to all Firefox profiles
- Uses `certutil` (part of NSS tools)
- Firefox uses its own certificate store, separate from the OS

**Requires:**
- `certutil` installed (see below)
- Firefox must have been run at least once

**Installing certutil:**
```bash
# Ubuntu/Debian
sudo apt-get install libnss3-tools

# Fedora/RHEL
sudo dnf install nss-tools

# macOS
brew install nss
```

## Verification

### Linux
```bash
# Check system trust store
ls -l /etc/ssl/certs/ | grep -i derusted

# Test with curl
curl -v https://example.com 2>&1 | grep "SSL certificate"
```

### macOS
```bash
# Check System Keychain
security find-certificate -c "Derusted" -a

# Test with curl
curl -v https://example.com 2>&1 | grep "SSL certificate"
```

### Windows
```powershell
# List certificates in Trusted Root CA store
Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*Derusted*"}
```

### Firefox
```bash
# List certificates in Firefox profile
certutil -L -d sql:$HOME/.mozilla/firefox/*.default-release/
```

## Troubleshooting

### Certificate not trusted after installation

**Browsers:**
- Restart the browser completely (close all windows)
- Clear SSL state/cache
- Check that the certificate was installed to the correct store

**System tools (curl, wget):**
- Verify certificate is in the system trust store
- Check file permissions (should be 644)
- Try running with verbose mode to see SSL errors

### Firefox-specific issues

**"certutil: command not found"**
- Install NSS tools (see Firefox section above)

**"Firefox profile not found"**
- Make sure Firefox has been run at least once
- Check the profile directory path for your OS

### Permission denied

All installation scripts require elevated privileges:
- Linux/macOS: Use `sudo`
- Windows: Run PowerShell as Administrator

## Uninstallation

### Linux
```bash
sudo rm /usr/local/share/ca-certificates/derusted-ca.crt
sudo update-ca-certificates --fresh
```

### macOS
```bash
sudo security delete-certificate -c "Derusted" -t /Library/Keychains/System.keychain
```

### Windows
```powershell
# Run as Administrator
$cert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*Derusted*"}
$cert | Remove-Item
```

### Firefox
```bash
certutil -D -n "Derusted-CA" -d sql:$HOME/.mozilla/firefox/*.default-release/
```

## Security Notes

1. **Only install CA certificates you trust**
   - These scripts give the CA full authority to intercept HTTPS traffic
   - Only use in controlled environments (development, corporate networks)

2. **Per-environment isolation**
   - Use separate CAs for dev/staging/production
   - Never share CA private keys between environments

3. **Certificate rotation**
   - Periodically rotate CA certificates
   - Update trust stores when rotating

4. **Auditing**
   - Monitor which hosts/domains are being intercepted
   - Review bypass rules regularly

## Platform Support

| Platform | System Trust | Chrome | Firefox | Safari | Edge |
|----------|--------------|--------|---------|--------|------|
| Linux (Debian/Ubuntu) | ✅ | ✅ | ⚠️ (separate script) | N/A | N/A |
| macOS | ✅ | ✅ | ⚠️ (separate script) | ✅ | N/A |
| Windows | ✅ | ✅ | ⚠️ (separate script) | N/A | ✅ |

⚠️ Firefox requires separate installation using the Firefox-specific script.

## Future Enhancements

- [ ] Automated CA export from Vault
- [ ] Certificate rotation script
- [ ] Health check/verification script
- [ ] Docker container trust installation
- [ ] Group Policy deployment (Windows)
- [ ] MDM deployment (macOS)
