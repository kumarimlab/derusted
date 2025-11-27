#!/bin/bash
# Generate self-signed certificates for testing Derusted proxy

set -e

CERTS_DIR="${1:-./certs}"
mkdir -p "$CERTS_DIR"

echo "Generating test certificates in $CERTS_DIR..."

# Generate CA private key and certificate
openssl req -x509 -new -nodes \
    -keyout "$CERTS_DIR/ca-key.pem" \
    -out "$CERTS_DIR/ca-cert.pem" \
    -days 365 \
    -subj "/C=US/ST=Test/L=Test/O=Derusted Test CA/CN=Derusted Test Root CA"

echo "✓ CA certificate generated"

# Generate server private key
openssl genrsa -out "$CERTS_DIR/key.pem" 2048

# Generate server certificate signing request
openssl req -new \
    -key "$CERTS_DIR/key.pem" \
    -out "$CERTS_DIR/cert.csr" \
    -subj "/C=US/ST=Test/L=Test/O=Derusted Proxy/CN=localhost"

# Sign server certificate with CA
openssl x509 -req \
    -in "$CERTS_DIR/cert.csr" \
    -CA "$CERTS_DIR/ca-cert.pem" \
    -CAkey "$CERTS_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERTS_DIR/cert.pem" \
    -days 365 \
    -extfile <(printf "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1")

echo "✓ Server certificate generated"

# Clean up CSR
rm "$CERTS_DIR/cert.csr"

# Set permissions
chmod 600 "$CERTS_DIR"/*.pem

echo ""
echo "Certificates generated successfully!"
echo "  CA Certificate:     $CERTS_DIR/ca-cert.pem"
echo "  CA Key:             $CERTS_DIR/ca-key.pem"
echo "  Server Certificate: $CERTS_DIR/cert.pem"
echo "  Server Key:         $CERTS_DIR/key.pem"
echo ""
echo "To trust the CA certificate:"
echo "  - macOS:   security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain $CERTS_DIR/ca-cert.pem"
echo "  - Linux:   sudo cp $CERTS_DIR/ca-cert.pem /usr/local/share/ca-certificates/derusted-ca.crt && sudo update-ca-certificates"
echo "  - curl:    curl --cacert $CERTS_DIR/ca-cert.pem https://localhost:8443"
