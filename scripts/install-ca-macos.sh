#!/bin/bash
# Install Derusted CA certificate on macOS
#
# Usage: sudo ./install-ca-macos.sh [path-to-ca.crt]

set -e

CA_CERT_PATH="${1:-./ca.crt}"

if [ ! -f "$CA_CERT_PATH" ]; then
    echo "Error: CA certificate not found at $CA_CERT_PATH"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

echo "Installing Derusted CA certificate to System Keychain..."

# Import certificate into System Keychain
security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CA_CERT_PATH"

echo "✓ Derusted CA certificate installed successfully"
echo ""
echo "The certificate has been added to the System Keychain and marked as trusted."
echo "You may need to restart your applications for changes to take effect."
