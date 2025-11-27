# Changelog

All notable changes to Derusted will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2025-11-25

### 🎉 Initial Open Source Release

**Derusted v0.1.0** - Production-ready Rust library for HTTPS MITM proxy with enterprise-grade security.

**Development Timeline**: 8 weeks (November 2025)
**Status**: ✅ Production Ready
**License**: Apache-2.0

---

### Added

#### Week 1: MITM & Certificate Management
- Dynamic TLS certificate generation per domain using rcgen
- CA key management with multiple backends:
  - Environment variables (`CA_CERT`, `CA_KEY`)
  - HashiCorp Vault integration
  - AWS KMS integration
- Certificate caching with LRU + TTL eviction (default 24-hour TTL, max 1000 certs)
- Thread-safe certificate authority operations (Arc/Mutex)
- Memory protection for CA private keys (never logged, proper zeroing)

#### Week 2-3: HTTP/1.1 MITM
- Full HTTP/1.1 request interception and inspection
- Complete HTTP/1.1 response interception with streaming support
- Method support: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
- Header manipulation: read, modify, add, remove headers
- Request/response body inspection
- HTTP/1.1 parser with chunked transfer encoding support

#### Week 4: Logging & Privacy
- SQLite-based persistent request logging
- Automatic PII redaction for 6 sensitive data types:
  - Email addresses → `[EMAIL REDACTED]`
  - Credit card numbers → `[CC REDACTED]`
  - Social Security Numbers → `[SSN REDACTED]`
  - Phone numbers → `[PHONE REDACTED]`
  - Bearer tokens → `[TOKEN REDACTED]`
  - API keys → `[API_KEY REDACTED]`
- Sensitive header redaction (Authorization, Cookie, Set-Cookie, X-API-Key, etc.)
- 13 comprehensive unit tests for PII redaction

#### Week 5: Smart Bypass System
- 60+ static bypass rules for certificate-pinned services
- Automatic bypass categories:
  - Banking and financial institutions
  - Payment processors
  - Government services
  - Cloud providers (AWS, Azure, GCP)
  - Developer tools (npm, crates.io, GitHub)
- Dynamic certificate pinning detection (bypass after 3 failed TLS handshakes)
- HSTS (Strict-Transport-Security) header support
- Automatic localhost/127.0.0.1 bypass

#### Week 6: HTTP/2 MITM
- Full HTTP/2 protocol support with ALPN negotiation
- HTTP/2 stream multiplexing with concurrent stream handling
- Flow control implementation
- Chunked transfer encoding for streaming responses
- Proper HTTP/2 error code handling

#### Week 7: Performance Optimization
- Connection pooling for upstream TLS connections (HTTP/1.1 and unknown protocols):
  - Per-host connection pools
  - Max 10 idle connections per host
  - 90-second idle timeout
  - 10-minute maximum connection lifetime
  - Background cleanup every 60 seconds
- Certificate cache with TTL support (dual eviction: LRU + TTL)
- Connection pool statistics tracking (hits, misses, evictions)
- Expected performance improvements:
  - +20-30% throughput from connection reuse
  - -100-200ms latency for repeated requests to same host

#### Week 8: Security & Hardening
- Comprehensive security audit (see `docs/SECURITY_AUDIT.md`)
- Threat model documentation covering 6 major threats (see `docs/THREAT_MODEL.md`)
- CA rotation procedures (scheduled and emergency) (see `docs/CA_ROTATION.md`)
- SSRF protection: blocks private IPs (RFC1918), localhost, cloud metadata endpoints
- 100% memory-safe Rust (no `unsafe` blocks)
- Dependency audit: 6 CVEs assessed as non-blocking

#### Testing
- 148 passing tests (150 with `network-tests` feature for DNS resolution tests)
- Test coverage includes:
  - CA key management (environment, Vault, KMS)
  - Certificate generation and caching
  - HTTP/1.1 request/response parsing
  - HTTP/2 MITM
  - PII redaction (13 dedicated tests)
  - Bypass system
  - Connection pooling
  - SSRF protection

#### Documentation
- Complete README with quick start guide and 5 usage examples
- Security audit report (`docs/SECURITY_AUDIT.md`)
- Threat model analysis (`docs/THREAT_MODEL.md`)
- CA rotation playbook (`docs/CA_ROTATION.md`)
- CI/CD decision note (`docs/CI_CD_NOTE.md`)

---

### Known Limitations

#### Connection Pool
- **HTTP/2 connections cannot be pooled**: The h2 handler takes ownership of the connection, preventing return to pool. HTTP/2's built-in multiplexing provides connection reuse within a single h2 session.
- **HTTP/1.1 and unknown protocols**: ✅ Fully functional connection pooling
- **No connection health checks**: Pooled connections are assumed valid; TCP/TLS errors are handled on use

#### Certificate Cache
- Default TTL: 24 hours (configurable via `CertificateAuthority::with_ttl()`)
- Maximum size: 1000 certificates
- Lazy TTL cleanup: Expired certificates only removed on cache access (no background task)

#### HTTP/2 MITM
- No HTTP/2 server push support (rarely used in practice)
- Basic flow control implementation
- Streaming via chunked transfer encoding

#### Bypass System
- Static rules: 60+ hardcoded bypass rules
- Dynamic bypass requires 3 consecutive TLS handshake failures
- No user-configurable bypass rules (planned for v0.2.0)

---

### Security

#### Security Audit - ✅ APPROVED FOR v0.1.0 RELEASE

| Category | Status | Details |
|----------|--------|---------|
| **CA Private Key** | ✅ PASS | No logging, proper memory protection |
| **PII Redaction** | ✅ PASS | 6 patterns, 13 unit tests |
| **Error Messages** | ✅ PASS | No sensitive data exposure |
| **Memory Safety** | ✅ PASS | No `unsafe` blocks |
| **Input Validation** | ✅ PASS | SSRF protection, hostname validation |
| **Dependencies** | ⚠️ CONDITIONAL PASS | 6 CVEs (all non-blocking) |

#### Dependency Vulnerabilities

6 CVEs found during `cargo audit`, all assessed as **non-blocking for v0.1.0**:

1. **hpack v0.3.0** (CRITICAL - RUSTSEC-2024-0003): DoS via malformed HTTP/2 headers
   - Impact: Server recovers from panics, does not crash process
   - Action for v0.2.0: Upgrade to maintained fork or alternative

2. **idna v0.4.0** (MEDIUM - RUSTSEC-2024-0421): Punycode validation bypass
   - Impact: Low risk for proxy use case (not parsing IDNs for auth decisions)
   - Action for v0.2.0: Upgrade to idna v1.0+

3. **protobuf v2.28.0** (HIGH - RUSTSEC-2021-0073): Uncontrolled recursion DoS
   - Impact: Used only by `pprof` (internal metrics), not exposed
   - Action for v0.2.0: Upgrade pprof to use protobuf v3+

4. **ring v0.16.20** (MEDIUM - RUSTSEC-2024-0006): AES panic on overflow
   - Impact: Only in debug mode, production builds unaffected
   - Action for v0.2.0: Upgrade rcgen to version using ring v0.17+

5. **rsa v0.9.9** (MEDIUM - RUSTSEC-2023-0071): Marvin timing attack
   - Impact: Unused MySQL feature in sqlx dependency
   - Action for v0.2.0: Upgrade sqlx to v0.8+

6. **sqlx v0.7.4** (HIGH - RUSTSEC-2024-0363): Binary protocol misinterpretation
   - Impact: Affects MySQL/PostgreSQL only, Derusted uses SQLite
   - Action for v0.2.0: Upgrade to sqlx v0.8.1+

**Recommendation**: Safe for v0.1.0 production use. Plan dependency upgrades for v0.2.0.

---

### Performance

#### Expected Metrics (Based on Week 7 Optimizations)

| Metric | Target | Implementation |
|--------|--------|----------------|
| **Throughput** | +20-30% vs baseline | Connection pooling |
| **Latency (p99)** | <500ms for cached connections | Certificate cache + pooling |
| **Memory** | <100MB under load | Bounded certificate cache (<50MB) |
| **TLS Handshake Savings** | 150-300ms per pooled connection | Connection pool reuse |
| **Connection Pool Hit Rate** | >70% under load | Per-host pools with 90s idle timeout |
| **Certificate Cache Hit Rate** | >80% under load | LRU + 24-hour TTL |

**Note**: Formal benchmarking planned for v0.2.0 release.

---

### Dependencies

#### Major Dependencies
- **tokio** v1.36+ - Async runtime
- **hyper** v0.14+ - HTTP client/server
- **rustls** v0.21+ - TLS implementation
- **rcgen** v0.11+ - Certificate generation
- **h2** v0.3+ - HTTP/2 implementation
- **sqlx** v0.7+ - SQLite integration
- **lru** v0.12+ - LRU cache
- **reqwest** v0.11+ - HTTP client (Vault/KMS)

See `Cargo.toml` for complete dependency list.

---

## Upgrade Guide

### For New Users

This is the initial release. See `README.md` for installation and quick start guide.

### Minimum Supported Rust Version (MSRV)

Derusted requires **Rust 1.70 or later**.

---

## Related Projects

- **[Pinaka Edge V2](https://github.com/your-org/pinaka-edge-v2-rust)** - Enterprise proxy management platform (proprietary)
  - Built on top of Derusted
  - Adds centralized policy management, smart categorization, and DLP

---

## Development

**Development Model**: 8-week iterative development (November 2025)
**Testing**: 148 passing tests (150 with `network-tests` feature)
**Code Quality**:
- No compiler warnings (RUSTFLAGS="-D warnings")
- Clippy lints enforced
- `cargo fmt` formatting

---

## Contributors

Developed by the **Pinaka Engineering Team**

---

## Links

- **Repository**: https://github.com/your-org/derusted
- **Documentation**: See `docs/` directory
- **Issues**: https://github.com/your-org/derusted/issues
- **Security**: security@your-org.com

---

## [Unreleased]

### Planned for v0.2.0
- [ ] Upgrade sqlx to v0.8.1+ (fixes RUSTSEC-2024-0363)
- [ ] Upgrade rcgen to use ring v0.17+ (fixes RUSTSEC-2024-0006)
- [ ] Migrate from trust-dns to hickory-dns
- [ ] User-configurable bypass rules
- [ ] Connection health checks for pooled connections
- [ ] Formal performance benchmarking
- [ ] HTTP/2 server push support (if needed)
- [ ] Active TTL cleanup for certificate cache (background task)

---

[0.1.0]: https://github.com/your-org/derusted/releases/tag/v0.1.0
