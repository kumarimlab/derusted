# Derusted

**Production-ready Rust library for HTTPS MITM proxy with enterprise-grade security**

[![Crates.io Version](https://img.shields.io/crates/v/derusted.svg)](https://crates.io/crates/derusted)
[![docs.rs](https://docs.rs/derusted/badge.svg)](https://docs.rs/derusted)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/kumarimlab/derusted/blob/main/LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

Derusted is a high-performance forward proxy library built in Rust for HTTPS traffic inspection via dynamic TLS certificate generation. Built for safety, security, and developer experience.

**Version**: 0.2.0 | **Status**: ✅ Production Ready

> **⚠️ v0.2.0 Breaking Changes**: If upgrading from v0.1.x, see [Migration Guide](#-migrating-from-v01x-to-v020) below.

---

## 🚀 Features

### MITM & Certificate Management
- ✅ **Dynamic Certificate Generation** - On-the-fly TLS certificates per domain
- ✅ **CA Key Management** - Secure integration with HashiCorp Vault, AWS KMS, or environment variables
- ✅ **Certificate Caching** - LRU + TTL cache (default 24-hour TTL, max 1000 certs)
- ✅ **Thread-Safe Operations** - Arc/Mutex for concurrent access
- ✅ **Memory Protection** - CA private key never logged, proper zeroing on drop

### HTTP/1.1 MITM
- ✅ **Request Interception** - Full HTTP/1.1 request inspection and modification
- ✅ **Response Interception** - Complete response capture with streaming support
- ✅ **Method Support** - GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
- ✅ **Header Manipulation** - Read, modify, add, remove headers
- ✅ **Body Inspection** - Access to request/response bodies

### Logging & Privacy
- ✅ **SQLite Request Logging** - Persistent storage of HTTP transactions
- ✅ **PII Redaction** - Automatic redaction of 6 sensitive data types:
  - Email addresses → `[EMAIL REDACTED]`
  - Credit cards → `[CC REDACTED]`
  - Social Security Numbers → `[SSN REDACTED]`
  - Phone numbers → `[PHONE REDACTED]`
  - Bearer tokens → `[TOKEN REDACTED]`
  - API keys → `[API_KEY REDACTED]`
- ✅ **Sensitive Header Redaction** - Authorization, Cookie, Set-Cookie, X-API-Key, etc.
- ✅ **13 Unit Tests** - Comprehensive PII redaction test coverage

### Smart Bypass System
- ✅ **60+ Static Bypass Rules** - Pre-configured for certificate-pinned services
- ✅ **Dynamic Pinning Detection** - Automatic bypass after 3 failed TLS handshakes
- ✅ **HSTS Support** - Honors Strict-Transport-Security headers
- ✅ **Localhost Bypass** - Never MITM localhost/127.0.0.1
- ✅ **Bypass Categories**: Banking, payments, government, cloud providers, developer tools

### HTTP/2 MITM
- ✅ **Full HTTP/2 Support** - Stream multiplexing with flow control
- ✅ **ALPN Negotiation** - Automatic protocol selection
- ✅ **Stream Management** - Concurrent stream handling
- ✅ **Chunked Transfer** - Streaming response support
- ✅ **Error Handling** - Proper HTTP/2 error codes

### Performance Optimization
- ✅ **Connection Pooling** - Reuses TLS connections (HTTP/1.1 + unknown protocols)
  - Per-host pools with max 10 idle connections
  - 90-second idle timeout, 10-minute max lifetime
  - Background cleanup every 60 seconds
- ✅ **Certificate Cache TTL** - Bounded memory with dual eviction (LRU + TTL)
- ✅ **Pool Statistics** - Hits, misses, evictions tracking

### Security & Hardening
- ✅ **Comprehensive Security Audit** - No blocking vulnerabilities for v0.1.0
- ✅ **Threat Model** - 6 major threats documented with mitigations
- ✅ **CA Rotation Procedures** - Both scheduled and emergency rotation playbooks
- ✅ **Dependency Audit** - 6 CVEs found, all assessed as non-blocking
- ✅ **SSRF Protection** - Blocks private IPs (RFC1918), localhost, cloud metadata endpoints
- ✅ **Memory Safety** - 100% safe Rust (no `unsafe` blocks)

### Developer Experience
- ✅ **Library-First Design** - Clean API for integration
- ✅ **148 Passing Tests** - Comprehensive test coverage (150 with `network-tests` feature)
- ✅ **Detailed Documentation** - Security audit, threat model, guides
- ✅ **MIT License** - Maximum permissiveness for open source use

---

## 📦 Installation

Add Derusted to your `Cargo.toml`:

```toml
[dependencies]
derusted = "0.1.0"
```

Or use the latest from GitHub:

```toml
[dependencies]
derusted = { git = "https://github.com/your-org/derusted", tag = "v0.1.0" }
```

---

## 🎯 Quick Start

### 1. Generate CA Certificate

```bash
# Generate CA private key (4096-bit RSA)
openssl genrsa -out ca-key.pem 4096

# Generate CA certificate (valid for 10 years)
openssl req -new -x509 -days 3650 \
  -key ca-key.pem \
  -out ca-cert.pem \
  -subj "/C=US/ST=CA/L=SF/O=YourOrg/OU=IT/CN=YourOrg MITM CA"

# Set environment variables
export CA_CERT=$(cat ca-cert.pem)
export CA_KEY=$(cat ca-key.pem)
```

### 2. Basic MITM Setup

```rust
use derusted::mitm::{CaKeyManager, CertificateAuthority, MitmInterceptor};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize CA from environment variables
    let ca_manager = CaKeyManager::from_env("CA_CERT", "CA_KEY").await?;

    // Create certificate authority with default config
    let cert_authority = CertificateAuthority::new(ca_manager);

    // Create MITM interceptor
    let interceptor = Arc::new(MitmInterceptor::new(cert_authority));

    // Use interceptor to handle TLS connections
    // interceptor.intercept(client_stream, target_host, target_port).await?;

    Ok(())
}
```

### 3. With HashiCorp Vault

```rust
use derusted::mitm::CaKeyManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load CA from Vault
    let ca_manager = CaKeyManager::from_vault(
        "http://vault.example.com:8200",
        "s.YourVaultToken",
        "secret/data/mitm/ca"
    ).await?;

    // Use ca_manager as before...

    Ok(())
}
```

### 4. With AWS KMS

```rust
use derusted::mitm::CaKeyManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load CA from KMS
    let ca_manager = CaKeyManager::from_kms(
        "us-east-1",
        "alias/mitm-ca-key",
        "arn:aws:s3:::your-bucket/ca-cert.pem"
    ).await?;

    Ok(())
}
```

### 5. With Certificate Pinning Detection

```rust
use derusted::mitm::MitmInterceptor;
use std::time::Duration;

// Enable automatic bypass for pinned domains
let interceptor = MitmInterceptor::with_pinning(
    cert_authority,
    3,  // max failures before bypass
    Duration::from_secs(300),  // bypass duration: 5 minutes
);
```

---

## 📚 Library Structure

Built over 8 weeks with clear separation of concerns:

```
derusted/
├── src/
│   ├── lib.rs                      # Public API exports
│   ├── mitm/
│   │   ├── ca_key_manager.rs       # CA key management (Week 1)
│   │   ├── certificate_authority.rs # Certificate generation + caching (Week 1)
│   │   ├── interceptor.rs          # MITM decision engine (Week 2-3, 6)
│   │   ├── tls_config.rs           # TLS configuration (Week 1)
│   │   ├── logging.rs              # PII redaction (Week 4)
│   │   ├── log_storage.rs          # SQLite storage (Week 4)
│   │   ├── bypass.rs               # Smart bypass system (Week 5)
│   │   ├── pinning.rs              # Pinning detection (Week 5)
│   │   ├── http_parser.rs          # HTTP/1.1 parsing (Week 2-3)
│   │   ├── http2_mitm.rs           # HTTP/2 MITM (Week 6)
│   │   └── error.rs                # Error types
│   ├── connection_pool.rs          # Connection pooling (Week 7)
│   ├── destination_filter.rs       # SSRF protection
│   └── ...
│
├── docs/
│   ├── SECURITY_AUDIT.md           # Complete security audit (Week 8)
│   ├── THREAT_MODEL.md             # Threat analysis (Week 8)
│   ├── CA_ROTATION.md              # Rotation procedures (Week 8)
│   └── CI_CD_NOTE.md               # CI/CD decision (Week 8)
│
├── pdocs/                          # Weekly development summaries
│   ├── WEEK1_FINAL_SUMMARY.md
│   ├── WEEK2_SUMMARY.md
│   ├── WEEK3_SUMMARY.md
│   ├── WEEK4_FINAL_SUMMARY.md
│   ├── WEEK5_SUMMARY.md
│   ├── WEEK6_SUMMARY.md
│   ├── WEEK7_SUMMARY.md
│   └── WEEK8_PLAN.md
│
└── tests/
    └── (150 passing tests)
```

---

## 🧪 Testing

Run the full test suite:
```bash
# Default: 148/152 tests pass (DNS tests excluded)
cargo test --lib

# With network tests enabled: 150/152 tests pass (requires DNS)
cargo test --lib --features network-tests

# With output
cargo test --lib -- --nocapture

# Specific module
cargo test --lib mitm::logging::tests
```

**Note**: By default, **148/152** tests pass. Two DNS-dependent tests (`destination_filter::tests::test_allow_public_domain` and `test_dns_caching`) are gated behind the `network-tests` feature flag to ensure compatibility with restricted/sandboxed environments. Enable them with `--features network-tests` to run all **150/152** tests (2 remain ignored).

Run security checks:
```bash
# Clippy lints
cargo clippy --all-targets -- -D warnings

# Security audit (requires cargo-audit)
cargo audit

# Format check
cargo fmt --all -- --check
```

**Test Coverage**: 150 tests covering:
- CA key management
- Certificate generation and caching
- HTTP/1.1 request/response interception
- HTTP/2 MITM
- PII redaction (13 dedicated tests)
- Bypass system
- Connection pooling
- SSRF protection

---

## 📈 Performance Benchmarks

### Performance Optimizations

| Optimization | Expected Impact | Status |
|--------------|-----------------|--------|
| **Connection Pooling** | +20-30% throughput | ✅ Implemented |
| **Certificate Cache TTL** | Bounded memory <50MB | ✅ Implemented |
| **TLS Handshake Savings** | 150-300ms per pooled connection | ✅ Implemented |
| **Latency (p99)** | <500ms for cached connections | ✅ Target met |

### Connection Pool Configuration

```rust
use derusted::connection_pool::{ConnectionPool, PoolConfig};

let config = PoolConfig {
    max_idle_per_host: 10,           // Max idle connections per host
    idle_timeout: Duration::from_secs(90),   // 90-second idle timeout
    max_lifetime: Duration::from_secs(600),  // 10-minute max lifetime
    connection_timeout: Duration::from_secs(30),
};

let pool = ConnectionPool::with_config(config);
```

---

## 🔒 Security

### Security Audit Summary

**Overall Assessment**: ✅ **APPROVED FOR v0.1.0 RELEASE**

| Category | Status | Details |
|----------|--------|---------|
| **CA Private Key** | ✅ PASS | No logging, proper memory protection |
| **PII Redaction** | ✅ PASS | 6 patterns, 13 unit tests |
| **Error Messages** | ✅ PASS | No sensitive data exposure |
| **Memory Safety** | ✅ PASS | No `unsafe` blocks |
| **Input Validation** | ✅ PASS | SSRF protection, hostname validation |
| **Dependencies** | ⚠️ CONDITIONAL PASS | 6 CVEs, all non-blocking |

### Known Dependency Vulnerabilities

6 CVEs found, all assessed as **non-blocking for v0.1.0**:

1. **hpack v0.3.0** (CRITICAL): DoS via HTTP/2 headers - server recovers
2. **idna v0.4.0** (MEDIUM): Punycode validation - low risk for proxy
3. **protobuf v2.28.0** (HIGH): Recursion DoS - internal metrics only
4. **ring v0.16.20** (MEDIUM): AES panic - not default in release
5. **rsa v0.9.9** (MEDIUM): Timing attack - unused MySQL feature
6. **sqlx v0.7.4** (HIGH): Binary protocol - affects MySQL/PostgreSQL, not SQLite

**Action Items for v0.2.0**:
- Upgrade sqlx to 0.8.1+
- Upgrade rcgen to version using ring 0.17+
- Migrate trust-dns to hickory-dns

See [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) for complete details.

---

## 📖 Documentation

Comprehensive documentation created during Week 8:

- **[SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md)** - Complete security code audit
- **[THREAT_MODEL.md](docs/THREAT_MODEL.md)** - 6 major threats with mitigations
- **[CA_ROTATION.md](docs/CA_ROTATION.md)** - Scheduled and emergency rotation procedures
- **[CI_CD_NOTE.md](docs/CI_CD_NOTE.md)** - CI/CD decision and manual checks

---

## 🔄 Migrating from v0.1.x to v0.2.0

v0.2.0 introduces extensible JWT claims, which requires minor code changes.

### Breaking Change: JwtClaims Construction

**Before (v0.1.x):**
```rust
let claims = JwtClaims {
    token_id: "...".to_string(),
    user_id: 42,
    allowed_regions: vec!["us-east".to_string()],
    exp: ...,
    iat: ...,
    iss: Some("...".to_string()),
    aud: Some("...".to_string()),
};
```

**After (v0.2.0) - Recommended: Use constructor**
```rust
// Simple, clean, backwards-compatible
let claims = JwtClaims::new(
    "...".to_string(),    // token_id
    42,                   // user_id
    vec!["us-east".to_string()],  // allowed_regions
    exp,                  // expiration
    iat,                  // issued_at
    Some("...".to_string()),  // issuer
    Some("...".to_string()),  // audience
);
```

**After (v0.2.0) - Alternative: Add extra field**
```rust
let claims = JwtClaims {
    token_id: "...".to_string(),
    user_id: 42,
    // ... other fields ...
    extra: (), // ← Add this line
};
```

### Type Inference for JwtValidator

If you see type inference errors, add explicit type annotation:
```rust
// Before: let validator = JwtValidator::new(...)?;
// After:
let validator: JwtValidator<()> = JwtValidator::new(...)?;
```

---

## 🔧 Extensibility Patterns (v0.2.0+)

Derusted is designed as a foundation library. These patterns follow industry standards from [Envoy](https://www.envoyproxy.io/docs/envoy/latest/configuration/overview/extension), [goproxy](https://github.com/elazarl/goproxy), and [mitmproxy](https://docs.mitmproxy.org/stable/addons/overview/).

### Custom JWT Claims

Extend `JwtClaims` with application-specific fields:

```rust
use derusted::{JwtClaims, JwtValidator};
use serde::Deserialize;

// 1. Define your custom claims
#[derive(Debug, Clone, Default, Deserialize)]
struct SaasCustomClaims {
    tier: Option<String>,           // "free", "pro", "enterprise"
    rate_limit_per_hour: Option<usize>,
    features: Vec<String>,
}

// 2. Create validator for extended claims
let validator: JwtValidator<SaasCustomClaims> = JwtValidator::new(
    secret.to_string(),
    "HS256".to_string(),
    "us-east".to_string(),
    None,
    None,
)?;

// 3. Validate and access custom fields
let claims = validator.validate(&format!("Bearer {}", token))?;
println!("Tier: {:?}", claims.extra.tier);
println!("Rate limit: {:?}", claims.extra.rate_limit_per_hour);

// 4. Create tokens with custom claims
let claims = JwtClaims::with_extra(
    "token_123".to_string(),
    42,
    vec!["us-east".to_string()],
    exp, iat, iss, aud,
    SaasCustomClaims {
        tier: Some("pro".to_string()),
        rate_limit_per_hour: Some(10000),
        features: vec!["advanced_routing".to_string()],
    },
);
```

See [examples/custom_auth.rs](examples/custom_auth.rs) for a complete example.

### Dynamic Rate Limiting

Override rate limits per-request based on user tier:

```rust
use derusted::{RateLimiter, RateLimiterConfig};

let config = RateLimiterConfig {
    requests_per_minute: 100,  // Default (free tier)
    burst_size: 20,
    bucket_ttl_seconds: 3600,
    max_buckets: 100_000,
};

let limiter = RateLimiter::new(config);

// Free tier: use default
limiter.check_limit("free_user_token").await?;

// Pro tier: 10,000 req/min
limiter.check_limit_with_override("pro_user_token", Some(10_000)).await?;

// Enterprise: 100,000 req/min
limiter.check_limit_with_override("enterprise_token", Some(100_000)).await?;
```

See [examples/tiered_rate_limits.rs](examples/tiered_rate_limits.rs) for a complete example.

### Config Extension via Deref

Extend `Config` with custom fields using the Deref pattern:

```rust
use std::ops::Deref;
use derusted::Config;

// Your extended config
pub struct MyAppConfig {
    base: Config,
    pub custom_logger: Arc<MyLogger>,
    pub feature_flags: FeatureFlags,
}

// Implement Deref for transparent access
impl Deref for MyAppConfig {
    type Target = Config;
    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

// Now you can access both
config.destination_filter  // derusted field (via Deref)
config.custom_logger       // your custom field
```

See [examples/custom_config.rs](examples/custom_config.rs) for a complete example.

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linters:
   ```bash
   cargo test --all
   cargo clippy --all-targets -- -D warnings
   cargo fmt --all
   cargo audit
   ```
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

---

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

### v0.1.0 (November 25, 2025)

**Initial open source release after 8 weeks of development:**

- **Week 1**: CA key management + certificate generation
- **Week 2-3**: HTTP/1.1 MITM (request + response interception)
- **Week 4**: Logging + PII redaction
- **Week 5**: Smart bypass system (60+ rules + dynamic pinning)
- **Week 6**: HTTP/2 MITM support
- **Week 7**: Performance optimization (connection pooling + caching)
- **Week 8**: Security hardening + documentation

**Core Features**:
- Dynamic certificate generation with Vault/KMS/env support
- HTTP/1.1 and HTTP/2 MITM capabilities
- Automatic PII redaction (6 patterns)
- Smart bypass for certificate-pinned domains
- Connection pooling for HTTP/1.1
- 150 passing tests
- Comprehensive security audit

**Known Limitations**:
- HTTP/2 connections cannot be pooled (handler takes ownership)
- 6 dependency CVEs (all non-blocking, tracked for v0.2.0)
- Certificate cache: 24-hour TTL, max 1000 certs

---

## 📄 License

Licensed under the MIT License.

```
MIT License

Copyright (c) 2025 Kumar AS

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

See [LICENSE](LICENSE) for full details.

---

## 🔗 Related Projects

- **[Pinaka Edge V2](https://github.com/your-org/pinaka-edge-v2-rust)** - Enterprise proxy management platform (proprietary)
  - Uses Derusted as the core MITM proxy library
  - Adds centralized policy management, smart categorization, and DLP

---

## ⚠️ Known Issues (v0.1.0)

### Dependency CVEs

The following CVEs exist in indirect dependencies and are documented for transparency. None are blocking for v0.1.0 release:

| Dependency | Version | Advisory | Severity | Status | Notes |
|------------|---------|----------|----------|--------|-------|
| **hpack** | 0.3.0 | RUSTSEC-2024-0003 | CRITICAL | ❌ Unfixed | No patched version available. Tracked for v0.2.0 |
| **h2** | 0.3.27 (indirect) | Unknown | Unknown | ⚠️ Old version | Newer h2 0.4.12 also in tree. Review needed |
| **protobuf** | 2.28.0 | RUSTSEC-2021-0073 | HIGH | ❌ Unfixed | Via pprof (dev-dependency). Low risk |
| **idna** | 0.2.x | Multiple | MEDIUM | ❌ Unfixed | Indirect dependency |
| **ring** | Various | Various | MEDIUM | ❌ Unfixed | Indirect dependency |
| **rsa** | Various | Various | MEDIUM | ❌ Unfixed | Indirect dependency |
| **trust-dns-resolver** | Old | Deprecated | LOW | ⚠️ Migration needed | Should migrate to hickory-dns in v0.2.0 |

**Fixed in v0.1.0:**
- ✅ **sqlx** 0.7.4 → 0.8.6 (RUSTSEC-2024-0363, HIGH severity)

**Impact Assessment**: These CVEs are in HTTP/2 parsing, TLS, and DNS resolution libraries. The proxy operates in a trusted internal network environment where these risks are mitigated by network segmentation and access controls. Full remediation planned for v0.2.0.

**Recommendations**:
- Deploy behind firewall with restricted network access
- Monitor for updates to hpack, h2, and trust-dns-resolver
- Run `cargo audit` regularly for new advisories

### DNS-Dependent Tests

Two tests require network access and may fail in sandboxed CI environments:
- `destination_filter::tests::test_allow_public_domain`
- `destination_filter::tests::test_dns_caching`

These tests perform actual DNS resolution to `example.com`. In restricted environments without DNS access, they will fail with "Operation not permitted". This does not indicate a bug in the library.

**Solutions**:
- Run tests in Docker with network access: `docker-compose up`
- Use test feature flag (planned for v0.2.0)
- Accept 148/150 passing tests in sandboxed environments

For complete test results, see [TEST_STATUS.md](pdocs/TEST_STATUS.md).

---

## 📧 Support

- **Issues**: https://github.com/your-org/derusted/issues
- **Security**: kumar.imlab@outlook.com
- **Discussions**: https://github.com/your-org/derusted/discussions

---

## 🙏 Acknowledgments

Built on the shoulders of giants:

- **Tokio** - Async runtime
- **Hyper** - HTTP implementation
- **Rustls** - TLS library
- **rcgen** - Certificate generation
- **SQLx** - SQLite integration
- **h2** - HTTP/2 implementation

Special thanks to the Rust community.

---

**Built with ❤️ in Rust**

*Developed by the Pinaka Engineering Team | 8-week development cycle | November 2025*
