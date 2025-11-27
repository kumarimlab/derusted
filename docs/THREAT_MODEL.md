# Threat Model: Derusted MITM Proxy

**Version**: 0.1.0
**Last Updated**: November 25, 2025
**Status**: Production Ready

---

## Overview

Derusted is a forward proxy with Man-In-The-Middle (MITM) capabilities for HTTPS traffic inspection. This document identifies security threats, attack vectors, impacts, and mitigations.

**Scope**: This threat model covers the MITM functionality, CA certificate management, TLS interception, and data handling.

---

## Threat 1: CA Private Key Compromise

### Severity: **CRITICAL**

### Attack Vectors

1. **Secret Store Compromise**:
   - Attacker gains unauthorized access to Vault/KMS
   - Vault credentials leaked or stolen
   - KMS key policy misconfigured

2. **Log/Crash Dump Leakage**:
   - CA private key accidentally logged to stdout/files
   - Memory dump includes unprotected key material
   - Core dumps sent to crash reporting services
   - Debug builds with verbose logging

3. **Source Code Exposure**:
   - Private key hardcoded in source code
   - CA key committed to Git repository
   - Docker image layers contain secrets

4. **Memory Extraction**:
   - Attacker with root access dumps process memory
   - Cold boot attack on physical hardware
   - VM snapshot captures key in RAM

### Impact

If CA private key is compromised:
- **Complete Trust Violation**: Attacker can generate valid certificates for ANY domain
- **Credential Theft**: MITM attacks to steal passwords, API keys, session tokens
- **Data Exfiltration**: Intercept and modify all HTTPS traffic
- **Reputational Damage**: Loss of trust from users and customers
- **Legal/Compliance**: GDPR, SOC2, PCI-DSS violations

### Mitigations Implemented

#### ✅ Secret Management
- **External Secret Store**: CA key stored in Vault/AWS KMS (never in code/images)
- **Environment-Based**: Different CAs for dev/staging/prod environments
- **Access Control**: Vault policies restrict CA key access

**Code Reference**: `src/mitm/ca_key_manager.rs:180-260`

#### ✅ Memory Protection
- **Secrecy Crate**: CA private key wrapped in `Secret<KeyPair>`
- **Zero on Drop**: Key material zeroed when `CaKeyManager` drops
- **No Debug Trait**: `Secret` prevents accidental logging

**Code Reference**: `src/mitm/ca_key_manager.rs:182` (key_pair field)

#### ✅ Logging Safety
- **Never Log Key**: CA private key never serialized or logged
- **PII Redaction**: Sensitive data redacted from logs
- **Audit Trail**: All secret access logged to Vault audit log

**Code Reference**: `src/mitm/logging.rs:33-150` (PII redaction)

#### ✅ Code Safety
- **No Hardcoding**: CA key loaded from environment/Vault only
- **Git Ignore**: `.gitignore` excludes `*.pem`, `*.key` files
- **CI Secret Scanning**: GitHub secret scanning enabled

### Detection

**Monitoring**:
- Vault/KMS access logs for unusual CA key retrieval
- Alert on CA certificate changes (fingerprint mismatch)
- Periodic CA fingerprint verification

**Indicators of Compromise**:
- Unexpected TLS certificates issued by your CA
- Certificate transparency logs show suspicious certs
- User reports of certificate warnings

### Response Procedure

If CA compromise is detected or suspected:

1. **Immediate Actions** (<1 hour):
   - Revoke compromised CA certificate
   - Disable all proxy instances using compromised CA
   - Generate new CA with new private key
   - Alert all stakeholders

2. **Short-Term** (<24 hours):
   - Deploy new CA to all proxy instances
   - Distribute new CA certificate to all clients
   - Force client CA trust store updates

3. **Investigation** (1-7 days):
   - Audit Vault/KMS access logs
   - Review all certificates issued by compromised CA
   - Identify scope of compromise

4. **Long-Term** (7-30 days):
   - Update CA rotation procedures
   - Implement additional monitoring
   - Conduct security training

**See**: `docs/CA_ROTATION.md` for detailed rotation procedures.

---

## Threat 2: Fake Certificate Detection

### Severity: **HIGH**

### Attack Vectors

1. **User Inspection**:
   - User manually checks certificate in browser
   - Certificate issuer shows custom CA (not public CA)
   - Certificate details reveal proxy interception

2. **Certificate Transparency Logs**:
   - Fake certificates not submitted to CT logs
   - Monitoring tools detect missing CT records
   - Certificate monitoring services alert on anomalies

3. **Certificate Pinning**:
   - Mobile apps with hardcoded certificate pins
   - Browser extensions enforcing certificate pins
   - HSTS with `includeSubDomains` and pinning

4. **HPKP (Deprecated)**:
   - Legacy sites with Public Key Pinning headers
   - Pinned public keys don't match proxy certificates

### Impact

- **Service Disruption**: Pinned apps/sites fail to connect
- **User Trust Loss**: Security warnings alarm users
- **Compliance Issues**: May violate privacy policies
- **Detection**: Users discover MITM interception

### Mitigations Implemented

#### ✅ Proper CA Distribution
- **Trust Installation Scripts**: Automate CA installation on client devices
- **Documentation**: Clear instructions for CA trust setup
- **Platform Support**: Instructions for Windows, macOS, Linux, iOS, Android

**See**: `docs/MITM_GUIDE.md` for CA installation guide.

#### ✅ Valid Certificate Generation
- **DNS SANs**: Subject Alternative Names match target domain
- **IP SANs**: Support for IP-based connections
- **Serial Numbers**: Unique serial numbers using crypto RNG + timestamp
- **Validity Period**: 90-day certificates (industry standard)

**Code Reference**: `src/mitm/certificate_authority.rs:177-232`

#### ✅ Smart Bypass System
- **Static Rules**: 60+ hardcoded bypass rules for known pinned domains
- **Dynamic Detection**: Automatic bypass after 3 pinning failures
- **Localhost Bypass**: Never MITM localhost/127.0.0.1
- **Private IP Bypass**: SSRF protection blocks private IPs

**Code Reference**: `src/mitm/bypass.rs`, `src/mitm/bypass_config.rs`

#### ✅ HSTS Support
- **Preload List**: Built-in list of HSTS preloaded domains
- **Header Parsing**: Honor Strict-Transport-Security headers
- **Subdomain Support**: Respect `includeSubDomains` directive

**Code Reference**: `src/mitm/hsts.rs:1-350`

### Detection

**Monitoring**:
- Bypass system metrics (pinning detection count)
- User reports of connection failures
- Certificate warning complaints

**Metrics**:
- `bypass_static_count`: Static bypass rule hits
- `bypass_dynamic_count`: Dynamic pinning bypass hits
- `bypass_pinning_detections`: Pinning failures detected

### Response Procedure

1. **Identify Pinned Service**:
   - Review bypass logs and metrics
   - Identify domain/app causing pinning failures

2. **Add to Bypass List**:
   - Add domain to static bypass rules
   - Update `bypass_config.rs` with new rule

3. **Update Documentation**:
   - Document pinned service in bypass docs
   - Update user guide with known limitations

4. **Deploy Update**:
   - Release updated bypass rules
   - Notify users of pinned services

---

## Threat 3: Key Leakage in Logs/Crash Dumps

### Severity: **CRITICAL**

### Attack Vectors

1. **Accidental Logging**:
   - Developer accidentally logs CA key during debugging
   - Error messages include key material
   - Verbose logging in production exposes secrets

2. **Memory Dumps**:
   - Core dumps generated on crash
   - Memory snapshots include unprotected keys
   - Debugging tools expose process memory

3. **Crash Reporting**:
   - Crash dumps sent to external services (Sentry, Rollbar)
   - Stack traces include key material
   - Error context captures secrets

4. **Serialization**:
   - CA key accidentally serialized to JSON/TOML
   - Configuration exports include secrets
   - Backup archives contain keys

### Impact

Same as Threat 1 (CA Private Key Compromise):
- Complete trust violation
- Credential theft
- Data exfiltration

### Mitigations Implemented

#### ✅ Secrecy Crate
- **No Debug Trait**: `Secret<KeyPair>` prevents `{:?}` logging
- **No Clone Trait**: Prevents accidental copies
- **Zero on Drop**: Automatic memory zeroing

**Code Reference**: `src/mitm/ca_key_manager.rs:182`

```rust
/// CA private key (zeroed on drop, never logged)
key_pair: Arc<KeyPair>,
```

#### ✅ Logging Audit
- **PII Redaction**: All logs scrubbed for sensitive data
- **No Secret Logging**: CA key never passed to log statements
- **Structured Logging**: `tracing` crate for safe logging

**Code Reference**: `src/mitm/logging.rs:33-150`

#### ✅ Production Safeguards
- **Disable Core Dumps**: `ulimit -c 0` in production
- **No Debug Builds**: Release builds only in production
- **Minimal Logging**: Log level set to INFO/WARN in prod

#### ✅ Serialization Protection
- **No Serialize Trait**: CA key types don't implement `Serialize`
- **Config Separation**: Secrets loaded separately from config
- **Environment Variables**: Sensitive values via env vars only

### Detection

**Code Review**:
- Periodic audit of all log statements
- Search for patterns: `debug!`, `info!`, `println!`, `dbg!`
- Review error handling for secret exposure

**Secret Scanning**:
- GitHub secret scanning (enabled)
- Custom patterns for CA private keys
- CI/CD hooks for secret detection

**Monitoring**:
- Log aggregation for sensitive patterns
- Alert on suspicious log entries
- Periodic secret scanning of log files

### Response Procedure

1. **Identify Leakage**:
   - Determine where/how key was leaked
   - Identify affected logs/dumps/backups

2. **Immediate Containment**:
   - Rotate CA immediately (see Threat 1 response)
   - Delete affected logs/dumps
   - Revoke access to leaked material

3. **Root Cause Analysis**:
   - Identify code path that caused leak
   - Fix logging/serialization bug
   - Add tests to prevent regression

4. **Prevention**:
   - Update code review checklist
   - Add linting rules for secret patterns
   - Enhance CI/CD secret scanning

---

## Threat 4: TLS Downgrade Attack

### Severity: **MEDIUM**

### Attack Vectors

1. **Protocol Downgrade**:
   - Attacker forces TLS 1.0/1.1 usage
   - Weak cipher suites negotiated
   - Fallback to insecure protocols

2. **ALPN Manipulation**:
   - Attacker manipulates ALPN negotiation
   - Forces HTTP/1.1 when HTTP/2 available
   - Bypasses protocol-specific security features

### Impact

- **Weaker Encryption**: Vulnerable to BEAST, POODLE attacks
- **Protocol Limitations**: HTTP/1.1 lacks HTTP/2 security features
- **Compliance Violations**: PCI-DSS requires TLS 1.2+

### Mitigations Implemented

#### ✅ Modern TLS Only
- **TLS 1.2+**: Only TLS 1.2 and TLS 1.3 supported
- **Strong Ciphers**: ECDHE + AES-GCM cipher suites only
- **No Legacy Support**: TLS 1.0/1.1 disabled

**Code Reference**: `src/mitm/tls_config.rs:65-150`

#### ✅ ALPN Protection
- **Preference Order**: HTTP/2 preferred over HTTP/1.1
- **Fallback Safety**: HTTP/1.1 still secure (TLS 1.2+)
- **No SSLv3**: Ancient protocols completely disabled

**Code Reference**: `src/tls.rs:1-50`

### Detection

**Monitoring**:
- TLS version distribution metrics
- Cipher suite usage statistics
- ALPN negotiation outcomes

### Response Procedure

1. **Update Configuration**:
   - Review and harden TLS settings
   - Update cipher suite list

2. **Client Updates**:
   - Ensure clients support modern TLS
   - Deprecate legacy client support

---

## Threat 5: SSRF via Proxy

### Severity: **HIGH**

### Attack Vectors

1. **Internal Network Access**:
   - Attacker requests proxy to connect to internal IPs
   - Access to `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`
   - Cloud metadata endpoints (`169.254.169.254`)

2. **Localhost Access**:
   - Requests to `127.0.0.1`, `localhost`, `::1`
   - Access to local services (databases, admin panels)

### Impact

- **Internal Network Exposure**: Access to internal systems
- **Cloud Metadata Theft**: AWS/GCP/Azure credentials exposed
- **Service Disruption**: Attack internal services

### Mitigations Implemented

#### ✅ Destination Filtering
- **Private IP Blocking**: All RFC1918 ranges blocked
- **Localhost Blocking**: 127.0.0.0/8, ::1 blocked
- **Cloud Metadata Blocking**: 169.254.169.254 blocked
- **DNS Resolution**: Check IPs after DNS resolution

**Code Reference**: `src/destination_filter.rs:1-200`

#### ✅ MITM Localhost Bypass
- **Never MITM Localhost**: Automatic bypass for localhost
- **Early Detection**: Hostname check before TLS

**Code Reference**: `src/mitm/certificate_authority.rs:39-63`

### Detection

**Monitoring**:
- Blocked connection attempts
- Destination filter metrics
- Unusual internal IP requests

### Response Procedure

1. **Log Analysis**:
   - Review blocked requests
   - Identify attacker source

2. **Rate Limiting**:
   - Throttle suspicious clients
   - Block repeat offenders

---

## Threat 6: DoS via Resource Exhaustion

### Severity: **MEDIUM**

### Attack Vectors

1. **Certificate Generation Storm**:
   - Attacker requests unique domains rapidly
   - Certificate cache overwhelmed
   - CPU exhaustion from crypto operations

2. **Connection Pool Exhaustion**:
   - Attacker opens many connections
   - Connection pool fills up
   - Legitimate requests starved

3. **Memory Exhaustion**:
   - Large request/response bodies
   - Unbounded memory allocation
   - Out-of-memory crash

### Impact

- **Service Degradation**: Slow response times
- **Service Outage**: Proxy crashes or hangs
- **Resource Costs**: Excessive CPU/memory usage

### Mitigations Implemented

#### ✅ Certificate Cache
- **LRU Eviction**: Max 1000 certificates cached
- **TTL Expiration**: 24-hour default TTL
- **Bounded Memory**: <50MB maximum

**Code Reference**: `src/mitm/certificate_authority.rs:106-256`

#### ✅ Connection Pool
- **Max Idle Per Host**: 10 connections per host
- **Idle Timeout**: 90 seconds
- **Max Lifetime**: 10 minutes
- **Background Cleanup**: Removes stale connections

**Code Reference**: `src/connection_pool.rs:36-294`

#### ✅ Body Size Limiting
- **Max Body Size**: Configurable limit (default 10MB)
- **Early Termination**: Reject oversized bodies
- **Streaming**: No buffering of full bodies

**Code Reference**: `src/body_limiter.rs:1-100`

#### ✅ Rate Limiting
- **Token Bucket**: Per-client rate limiting
- **Configurable Limits**: Requests per second
- **Automatic Cleanup**: Expired buckets removed

**Code Reference**: `src/rate_limiter.rs:1-500`

### Detection

**Monitoring**:
- Certificate generation rate
- Connection pool utilization
- Memory usage trends
- Rate limit violations

### Response Procedure

1. **Identify Attack**:
   - Review metrics for anomalies
   - Identify attack patterns

2. **Throttle/Block**:
   - Rate limit aggressive clients
   - Block attacking IPs

3. **Scale Resources**:
   - Increase proxy instances
   - Adjust resource limits

---

## Security Best Practices

### Deployment

1. **Secret Management**:
   - ✅ Use Vault/KMS for CA keys
   - ✅ Rotate secrets regularly
   - ✅ Separate dev/staging/prod secrets

2. **Network Segmentation**:
   - Deploy proxy in DMZ
   - Isolate from internal systems
   - Use firewalls for access control

3. **Monitoring**:
   - Enable audit logging
   - Alert on anomalies
   - Dashboard for key metrics

4. **Updates**:
   - Regular dependency updates
   - Security patch cycle
   - Automated vulnerability scanning

### Development

1. **Code Review**:
   - Peer review all changes
   - Security-focused reviews for crypto code
   - Check for secret leakage

2. **Testing**:
   - 150+ unit tests
   - Integration tests for TLS
   - Fuzz testing (future)

3. **Linting**:
   - Clippy lints enforced
   - `#![forbid(unsafe_code)]` (no unsafe)
   - Format checks

4. **Dependencies**:
   - Minimal dependency tree
   - Audit dependencies regularly
   - Pin critical dependencies

---

## Compliance

### GDPR (General Data Protection Regulation)

- **PII Redaction**: Automatic redaction of personal data in logs
- **Data Minimization**: Only necessary data logged
- **Encryption**: TLS 1.2+ for data in transit
- **Access Control**: CA key access restricted

### SOC 2 (System and Organization Controls)

- **Security**: CA key protection, TLS hardening
- **Availability**: Rate limiting, DoS protection
- **Confidentiality**: Encryption, access control
- **Processing Integrity**: Request/response validation

### PCI-DSS (Payment Card Industry)

- **Requirement 4.1**: TLS 1.2+ for cardholder data
- **Requirement 6.5.4**: Secure coding practices
- **Requirement 10.2**: Audit logging
- **Requirement 11.3**: Vulnerability scanning

---

## Incident Response

### Security Incident Classifications

1. **P0 - Critical** (CA Compromise):
   - Immediate response (<1 hour)
   - Rotate CA immediately
   - Notify all stakeholders

2. **P1 - High** (Key Leakage Suspected):
   - Fast response (<4 hours)
   - Investigate and contain
   - Rotate if confirmed

3. **P2 - Medium** (DoS Attack):
   - Standard response (<24 hours)
   - Throttle/block attackers
   - Scale resources

4. **P3 - Low** (Config Issue):
   - Routine response (<1 week)
   - Fix and deploy update
   - Document lesson learned

### Incident Response Team

- **Incident Commander**: On-call engineer
- **Security Lead**: Security team member
- **Engineering Lead**: Derusted maintainer
- **Communication Lead**: Customer success/PR

---

## References

- **CA Rotation Playbook**: `docs/CA_ROTATION.md`
- **MITM Setup Guide**: `docs/MITM_GUIDE.md`
- **Performance Guide**: `docs/PERFORMANCE.md`
- **Architecture**: `docs/ARCHITECTURE.md`

---

**Document Version**: 1.0
**Last Review**: November 25, 2025
**Next Review**: February 25, 2026 (Quarterly)
**Owner**: Derusted Security Team
