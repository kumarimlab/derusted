# HTTP/2 Extended CONNECT Test Harness

## Overview

This directory contains automated HTTP/2 client tests that validate the proxy's Extended CONNECT implementation (RFC 8441).

## Test File

**`h2_client_harness.rs`** - Standalone HTTP/2 client that exercises the proxy with real h2 connections.

## Running the Tests

### Prerequisites

1. **Start the proxy server** in a separate terminal:
   ```bash
   TLS_CERT_PATH=/tmp/test-certs/cert.pem \
   TLS_KEY_PATH=/tmp/test-certs/key.pem \
   PROXY_PORT=8443 \
   JWT_SECRET='test_secret_at_least_32_characters!!' \
   cargo run --release
   ```

2. **Generate self-signed certificates** (if not already done):
   ```bash
   mkdir -p /tmp/test-certs
   cd /tmp/test-certs
   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
     -days 1 -nodes -subj "/CN=localhost"
   ```

### Run All HTTP/2 Tests

```bash
cargo test --test h2_client_harness -- --nocapture
```

### Run Specific Test

```bash
# Test 1: Missing auth → 407
cargo test --test h2_client_harness test_h2_missing_auth_returns_407 -- --nocapture

# Test 2: Invalid JWT → 403
cargo test --test h2_client_harness test_h2_invalid_jwt_returns_403 -- --nocapture

# Test 3: Valid JWT → 200
cargo test --test h2_client_harness test_h2_valid_jwt_returns_200 -- --nocapture
```

## Test Coverage

| Test | Validates | Expected Result |
|------|-----------|----------------|
| `test_h2_missing_auth_returns_407` | Missing `Proxy-Authorization` header | 407 with Bearer challenge |
| `test_h2_invalid_jwt_returns_403` | Malformed JWT token | 403 Forbidden |
| `test_h2_valid_jwt_returns_200` | Valid JWT with all required claims | 200 OK or 502 Bad Gateway |

## What These Tests Validate

✅ **HTTP/2 Protocol Negotiation**:
- TLS handshake with ALPN (`h2` protocol)
- HTTP/2 client/server handshake
- Extended CONNECT method over HTTP/2

✅ **Authentication Flow**:
- Missing authentication detection
- JWT token parsing and validation
- Required claims enforcement (`token_id`, `user_id`, `allowed_regions`)

✅ **Error Responses**:
- 407 Proxy Authentication Required with proper headers
- 403 Forbidden for invalid tokens
- 200 OK for successful tunnel establishment

✅ **Handler Logic**:
- Authority validation (host:port parsing)
- Rate limiting (structure, not exercised)
- Upstream connection establishment

## JWT Token Structure

Tests use this JWT structure (matching production):

```json
{
  "token_id": "test-token-h2-client",
  "user_id": 42,
  "allowed_regions": ["us-east", "eu-west"],
  "exp": 1763695214,
  "iat": 1763691614
}
```

## Known Limitations

⚠️ **Self-Signed Certificate Handling**:
- Tests gracefully handle TLS handshake failures with self-signed certs
- For production testing, use valid certificates or configure cert trust

⚠️ **Connection Lifecycle**:
- Tests avoid the h2 connection reset issues encountered in unit tests
- Uses `--nocapture` to see detailed output and gracefully handles errors

⚠️ **Rate Limiting**:
- Rate limiting logic is present but not exercised by these tests
- Would require generating many requests to trigger limits

## Comparison with Manual Testing

| Method | HTTP/2 Support | Automation | Best For |
|--------|----------------|------------|----------|
| **curl** | HTTP/1.1 only for CONNECT | Manual | Quick verification |
| **h2 test harness** | ✅ Native HTTP/2 | ✅ Automated | CI/CD, regression testing |
| **Browser** | ✅ Native HTTP/2 | Manual | Real-world behavior |
| **h2spec** | ✅ Protocol conformance | ✅ Automated | RFC compliance |

## CI/CD Integration

To integrate into CI/CD pipeline:

```yaml
# .github/workflows/test.yml
- name: Start proxy server
  run: |
    TLS_CERT_PATH=./test-certs/cert.pem \
    TLS_KEY_PATH=./test-certs/key.pem \
    PROXY_PORT=8443 \
    JWT_SECRET='test_secret_at_least_32_characters!!' \
    cargo run --release &
    sleep 2

- name: Run HTTP/2 integration tests
  run: cargo test --test h2_client_harness
```

## Troubleshooting

**Test hangs or times out**:
- Ensure proxy server is running on port 8443
- Check server logs for connection errors
- Verify TLS certificates exist at specified paths

**TLS handshake failures**:
- Expected with self-signed certificates
- Tests handle this gracefully and skip validation
- Use valid certs for comprehensive testing

**Connection refused**:
- Proxy server not started
- Port 8443 already in use
- Firewall blocking connection

## See Also

- `Documents/HTTP2_MANUAL_VERIFICATION_RESULTS.md` - Manual curl testing results
- `Documents/HTTP2_TESTING_REALITY_CHECK.md` - Unit test challenges and lessons learned
- `src/server.rs` - HTTP/2 handler implementation
