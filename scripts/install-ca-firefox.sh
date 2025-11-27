#!/bin/bash
# Install Derusted CA certificate in Firefox
#
# Firefox uses its own certificate store (NSS), separate from the system store.
# This script installs the CA certificate for all Firefox profiles.
#
# Usage: ./install-ca-firefox.sh [path-to-ca.crt]

set -e

CA_CERT_PATH="${1:-./ca.crt}"
CA_NAME="Derusted-CA"

if [ ! -f "$CA_CERT_PATH" ]; then
    echo "Error: CA certificate not found at $CA_CERT_PATH"
    exit 1
fi

# Check if certutil is installed
if ! command -v certutil &> /dev/null; then
    echo "Error: certutil is not installed"
    echo ""
    echo "Install it with:"
    echo "  Ubuntu/Debian: sudo apt-get install libnss3-tools"
    echo "  Fedora/RHEL:   sudo dnf install nss-tools"
    echo "  macOS:         brew install nss"
    exit 1
fi

# Find Firefox profile directories
if [ "$(uname)" == "Darwin" ]; then
    # macOS
    FIREFOX_PROFILES="$HOME/Library/Application Support/Firefox/Profiles"
elif [ "$(uname)" == "Linux" ]; then
    # Linux
    FIREFOX_PROFILES="$HOME/.mozilla/firefox"
else
    echo "Error: Unsupported operating system"
    exit 1
fi

if [ ! -d "$FIREFOX_PROFILES" ]; then
    echo "Error: Firefox profile directory not found"
    echo "Make sure Firefox is installed and has been run at least once."
    exit 1
fi

# Install certificate to all Firefox profiles
INSTALLED_COUNT=0

for profile in "$FIREFOX_PROFILES"/*.*/; do
    if [ -f "$profile/cert9.db" ] || [ -f "$profile/cert8.db" ]; then
        echo "Installing CA to Firefox profile: $(basename "$profile")"
        certutil -A -n "$CA_NAME" -t "C,," -i "$CA_CERT_PATH" -d "sql:$profile" 2>/dev/null || \
        certutil -A -n "$CA_NAME" -t "C,," -i "$CA_CERT_PATH" -d "$profile"
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
    fi
done

if [ $INSTALLED_COUNT -eq 0 ]; then
    echo "Error: No Firefox profiles found"
    exit 1
fi

echo ""
echo "✓ Derusted CA certificate installed to $INSTALLED_COUNT Firefox profile(s)"
echo ""
echo "Restart Firefox for changes to take effect."
