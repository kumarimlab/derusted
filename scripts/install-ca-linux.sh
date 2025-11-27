#!/bin/bash
# Install Derusted CA certificate on Linux (Debian/Ubuntu)
#
# Usage: sudo ./install-ca-linux.sh [path-to-ca.crt]

set -e

CA_CERT_PATH="${1:-./ca.crt}"
INSTALL_PATH="/usr/local/share/ca-certificates/derusted-ca.crt"

if [ ! -f "$CA_CERT_PATH" ]; then
    echo "Error: CA certificate not found at $CA_CERT_PATH"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

echo "Installing Derusted CA certificate..."
cp "$CA_CERT_PATH" "$INSTALL_PATH"
chmod 644 "$INSTALL_PATH"

echo "Updating system CA certificates..."
update-ca-certificates

echo "✓ Derusted CA certificate installed successfully"
echo ""
echo "You may need to restart your applications for changes to take effect."
