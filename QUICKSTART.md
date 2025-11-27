# Pinaka Rust Proxy - Quick Start Guide

**For Developers**: Get up and running in 5 minutes

---

## What is Pinaka Rust Proxy?

A **production-ready HTTP/HTTPS forward proxy** built in Rust that serves browser traffic through ProbeOps probe nodes.

**Key Features**:
- ✅ HTTP/2 + HTTP/1.1 dual-protocol support
- ✅ HTTPS tunneling (CONNECT method)
- ✅ HTTP forwarding (GET, POST, etc.)
- ✅ JWT authentication
- ✅ Rate limiting (10k req/min per token)
- ✅ Request logging & analytics

---

## Quick Test (No Build Required)

**Test the live deployment on probe node 2 (us-east)**:

```bash
# 1. Generate a test JWT token from ProbeOps staging
# Login to https://staging.probeops.com and get your session token

# 2. Test HTTP GET forwarding
JWT="your-jwt-token-here"

printf "GET http://neverssl.com/ HTTP/1.1\r\nHost: neverssl.com\r\nProxy-Authorization: Bearer $JWT\r\nConnection: close\r\n\r\n" | \
  openssl s_client -connect 54.173.189.152:443 -quiet 2>&1 | head -30

# Expected: HTTP 200 OK with neverssl.com HTML
```

**Test HTTPS tunneling**:
```bash
printf "CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\nProxy-Authorization: Bearer $JWT\r\n\r\n" | \
  openssl s_client -connect 54.173.189.152:443 -quiet 2>&1 | head -20

# Expected: HTTP/1.1 200 Connection established
```

---

## Local Development Setup

### 1. Install Rust

**Linux/Mac**:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
cargo --version  # Verify: cargo 1.91.x
```

**Windows**:
1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/)
2. Install Rust from [rustup.rs](https://rustup.rs)
3. Restart terminal: `cargo --version`

### 2. Clone & Build

```bash
# Clone repository
git clone https://github.com/kumarprobeops/pinaka-rust-proxy.git
cd pinaka-rust-proxy

# Check for errors
cargo check

# Build release binary (optimized, 2.5MB)
cargo build --release

# Binary location
ls -lh target/release/probe-proxy
```

### 3. Configure Environment

Create `.env` file:

```bash
cat > .env << 'EOF'
# Server
PROXY_HOST=0.0.0.0
PROXY_PORT=8443

# TLS (use your own certs for testing)
TLS_CERT_PATH=/path/to/cert.pem
TLS_KEY_PATH=/path/to/key.pem

# JWT Authentication
JWT_SECRET=test_secret_at_least_32_characters!!
JWT_ALGORITHM=HS256

# HTTP Forwarding
HTTP_PROXY_ENABLED=true

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=10000
RATE_LIMIT_BURST_SIZE=500

# Backend Integration (optional)
BACKEND_URL=https://staging.probeops.com
PROBE_NODE_NAME=local-dev
PROBE_NODE_REGION=local
EOF
```

**Generate Test Certificates** (for local development):
```bash
mkdir -p /tmp/test-certs

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /tmp/test-certs/key.pem \
  -out /tmp/test-certs/cert.pem \
  -days 365 \
  -subj "/CN=localhost"

# Update .env
sed -i 's|TLS_CERT_PATH=.*|TLS_CERT_PATH=/tmp/test-certs/cert.pem|' .env
sed -i 's|TLS_KEY_PATH=.*|TLS_KEY_PATH=/tmp/test-certs/key.pem|' .env
```

### 4. Run Locally

```bash
# Development mode (with debug logs)
RUST_LOG=info cargo run

# Or run release build
RUST_LOG=info ./target/release/probe-proxy
```

**Expected output**:
```
INFO probe_proxy: Starting Pinaka Rust Proxy
INFO probe_proxy: Listening on 0.0.0.0:8443
INFO probe_proxy: ALPN protocols: ["h2", "http/1.1"]
INFO probe_proxy: JWT authentication: enabled
INFO probe_proxy: HTTP proxy enabled: true
INFO probe_proxy: Rate limit: 10000 req/min, burst 500
```

### 5. Test Locally

**Generate Test JWT**:
```python
# test_jwt.py
import jwt
from datetime import datetime, timedelta

payload = {
    "sub": "test-user-1",
    "user_id": 1,
    "token_id": "test-token-123",
    "allowed_regions": ["us-east", "eu-west", "local"],
    "exp": int((datetime.utcnow() + timedelta(hours=24)).timestamp()),
    "iat": int(datetime.utcnow().timestamp())
}

token = jwt.encode(payload, "test_secret_at_least_32_characters!!", algorithm="HS256")
print(f"JWT={token}")
```

```bash
python3 test_jwt.py
# Copy the JWT output
```

**Test HTTP GET**:
```bash
JWT="your-generated-jwt-here"

printf "GET http://neverssl.com/ HTTP/1.1\r\nHost: neverssl.com\r\nProxy-Authorization: Bearer $JWT\r\nConnection: close\r\n\r\n" | \
  openssl s_client -connect localhost:8443 -quiet 2>&1 | head -30
```

**Test HTTPS CONNECT**:
```bash
printf "CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\nProxy-Authorization: Bearer $JWT\r\n\r\n" | \
  openssl s_client -connect localhost:8443 -quiet 2>&1 | head -20
```

---

## Running Tests

```bash
# Unit tests
cargo test

# Integration tests (requires proxy running)
cargo test --test '*'

# HTTP/2 load test
cargo build --release --bin h2_connect_load
./target/release/h2_connect_load

# HTTP/1.1 load test
cargo build --release --bin h1_connect_load
./target/release/h1_connect_load

# Phase 5 integration tests (bash script)
export PROXY_HOST=localhost
export PROXY_PORT=8443
export TOKEN="your-jwt-token"
/tmp/test_http_proxy.sh
```

---

## Common Issues

### Certificate Error
```
Error: Failed to load TLS certificate
```
**Fix**: Check certificate paths in `.env`, ensure files exist and are readable

### JWT Validation Failed
```
WARN JWT validation failed: InvalidSignature
```
**Fix**: Ensure `JWT_SECRET` matches between proxy and token generation

### Port Already in Use
```
Error: Address already in use (os error 98)
```
**Fix**: Change `PROXY_PORT` in `.env` or kill existing process: `pkill probe-proxy`

### Connection Refused
```
Error: Connection refused (os error 111)
```
**Fix**:
1. Verify proxy is running: `ps aux | grep probe-proxy`
2. Check port: `ss -tulpn | grep 8443`
3. Check firewall: `sudo ufw status`

---

## Next Steps

1. **Read Full Documentation**: `README.md` - Comprehensive feature guide
2. **Check Production Status**: `STATUS.md` - Current deployment status
3. **Operations Guide**: `docs/OPERATIONS.md` - Deployment & monitoring
4. **Test Results**: `docs/PHASE5_SUMMARY.md` - Integration & load tests

---

## Production Deployment

**Docker Compose** (recommended):
```bash
# See docker-compose-server2.yml on probe nodes
docker compose -f docker-compose-server2.yml up -d rust-proxy

# Check logs
docker compose -f docker-compose-server2.yml logs rust-proxy -f

# Restart
docker compose -f docker-compose-server2.yml restart rust-proxy
```

**Systemd Service**:
```bash
# See README.md for full systemd configuration
sudo systemctl start probe-proxy
sudo systemctl status probe-proxy
sudo journalctl -u probe-proxy -f
```

---

## Support

- **Documentation**: `README.md`, `STATUS.md`, `docs/`
- **Issues**: GitHub Issues
- **Team**: ProbeOps Engineering

**Last Updated**: November 21, 2025
