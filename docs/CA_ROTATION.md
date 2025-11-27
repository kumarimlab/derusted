# CA Certificate Rotation Playbook

**Version**: 1.0
**Last Updated**: November 25, 2025
**Owner**: Derusted Security Team

---

## Overview

This playbook provides step-by-step procedures for rotating the Certificate Authority (CA) used by Derusted for MITM SSL/TLS interception.

**When to rotate**:
- **Scheduled**: Every 2-5 years (before CA expiration)
- **Emergency**: CA private key compromised or suspected compromise
- **Planned**: Major infrastructure changes or compliance requirements

---

## Prerequisites

### Tools Required

- `openssl` - Certificate generation
- `vault` CLI - HashiCorp Vault access (if using Vault)
- `aws` CLI - AWS KMS access (if using AWS)
- Text editor - For configuration updates
- SSH/kubectl access - To deploy updated configurations

### Access Requirements

- **Secret Store Access**: Vault/KMS write permissions
- **Deployment Access**: Ability to restart proxy instances
- **Client Distribution**: Ability to push CA updates to clients

### Pre-Flight Checklist

- [ ] Backup current CA certificate and key
- [ ] Document current CA fingerprint
- [ ] Test CA generation procedure in non-production
- [ ] Verify client distribution mechanism works
- [ ] Prepare communication plan for users

---

## Scenario 1: Scheduled Rotation (Normal)

**Frequency**: Every 2-5 years, before CA expiration

**Timeline**: 60 days total
- Week -4 to -1: Preparation
- Day 1-30: Dual-issue period
- Day 31-60: Cleanup

### Phase 1: Preparation (Week -4 to -1)

#### Step 1.1: Generate New CA

**On a secure workstation** (NOT on production servers):

```bash
# Set environment
export ENV=production  # or staging/dev
export CA_VERSION=v2   # Increment from current version

# Generate new CA private key (4096-bit RSA)
openssl genrsa -out ca-${ENV}-${CA_VERSION}-key.pem 4096

# Generate CA certificate (valid for 10 years)
openssl req -new -x509 -days 3650 \
  -key ca-${ENV}-${CA_VERSION}-key.pem \
  -out ca-${ENV}-${CA_VERSION}-cert.pem \
  -subj "/C=US/ST=California/L=San Francisco/O=YourOrg/OU=Security/CN=YourOrg MITM CA ${CA_VERSION}"

# Verify certificate
openssl x509 -in ca-${ENV}-${CA_VERSION}-cert.pem -text -noout

# Check expiration
openssl x509 -in ca-${ENV}-${CA_VERSION}-cert.pem -enddate -noout
```

**IMPORTANT**:
- Generate CA on an air-gapped or highly secure machine
- Never generate CA on production servers
- Use strong passphrase if encrypting private key

#### Step 1.2: Securely Store New CA

**HashiCorp Vault**:

```bash
# Upload to Vault
vault kv put secret/derusted/${ENV}/ca-${CA_VERSION} \
  key=@ca-${ENV}-${CA_VERSION}-key.pem \
  cert=@ca-${ENV}-${CA_VERSION}-cert.pem

# Verify upload
vault kv get secret/derusted/${ENV}/ca-${CA_VERSION}

# Set access policy (limit to proxy instances)
vault policy write derusted-ca-${ENV} - <<EOF
path "secret/data/derusted/${ENV}/ca-${CA_VERSION}" {
  capabilities = ["read"]
}
EOF
```

**AWS KMS**:

```bash
# Store CA key in AWS Secrets Manager
aws secretsmanager create-secret \
  --name derusted/${ENV}/ca-${CA_VERSION}/key \
  --secret-string file://ca-${ENV}-${CA_VERSION}-key.pem

# Store CA cert
aws secretsmanager create-secret \
  --name derusted/${ENV}/ca-${CA_VERSION}/cert \
  --secret-string file://ca-${ENV}-${CA_VERSION}-cert.pem

# Set resource policy (limit to proxy IAM role)
aws secretsmanager put-resource-policy \
  --secret-id derusted/${ENV}/ca-${CA_VERSION}/key \
  --resource-policy file://policy.json
```

#### Step 1.3: Calculate and Document Fingerprint

```bash
# SHA-256 fingerprint
openssl x509 -in ca-${ENV}-${CA_VERSION}-cert.pem -fingerprint -sha256 -noout

# Save to documentation
echo "CA ${ENV} ${CA_VERSION} Fingerprint: [output above]" >> ca-fingerprints.txt
```

#### Step 1.4: Prepare Client Distribution Package

Create trust installation scripts:

```bash
# Create distribution directory
mkdir -p ca-distribution/${ENV}/${CA_VERSION}

# Copy CA certificate
cp ca-${ENV}-${CA_VERSION}-cert.pem ca-distribution/${ENV}/${CA_VERSION}/

# Create installation scripts (see examples below)
```

**Windows Installation Script** (`install-ca-windows.ps1`):

```powershell
# install-ca-windows.ps1
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import("ca-production-v2-cert.pem")

$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    "Root",
    "CurrentUser"
)
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()

Write-Host "CA certificate installed successfully"
```

**macOS/Linux Installation Script** (`install-ca-unix.sh`):

```bash
#!/bin/bash
# install-ca-unix.sh

CA_CERT="ca-production-v2-cert.pem"

# macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    sudo security add-trusted-cert -d -r trustRoot \
        -k /Library/Keychains/System.keychain "$CA_CERT"
    echo "CA installed in macOS system keychain"

# Linux (Ubuntu/Debian)
elif [[ -f /etc/debian_version ]]; then
    sudo cp "$CA_CERT" /usr/local/share/ca-certificates/
    sudo update-ca-certificates
    echo "CA installed in system trust store"

# Linux (RHEL/CentOS)
elif [[ -f /etc/redhat-release ]]; then
    sudo cp "$CA_CERT" /etc/pki/ca-trust/source/anchors/
    sudo update-ca-trust
    echo "CA installed in system trust store"

else
    echo "Unsupported OS. Manual installation required."
    exit 1
fi
```

---

### Phase 2: Dual-Issue Period (Day 1-30)

During this phase, the proxy issues certificates signed by **BOTH** old and new CAs to allow gradual client migration.

#### Step 2.1: Configure Proxy for Dual-Issue

**Note**: Derusted v0.1.0 does not yet support dual-issue mode. This is a future enhancement.

**Current Workaround**: Use rolling updates with monitoring

```bash
# Update 50% of proxies to new CA
# Monitor for client connection issues
# If issues arise, roll back
```

#### Step 2.2: Distribute New CA to Clients

**Email Distribution**:
- Send email to all users with installation instructions
- Include CA certificate and installation scripts
- Provide support contact information

**MDM/GPO Distribution** (Enterprise):
- Push CA via Mobile Device Management (iOS/Android)
- Use Group Policy Objects (Windows)
- JAMF/Intune for managed devices

**Self-Service Portal**:
- Provide downloadable CA + scripts on internal portal
- Include step-by-step installation guide
- Video tutorials for non-technical users

#### Step 2.3: Monitor Adoption Rate

```bash
# Query client user-agents / connection patterns
# Track clients still using old CA
# Send reminders to users who haven't updated
```

**Metrics to Track**:
- % of clients with new CA installed
- Connection errors / cert warnings
- Support tickets related to CA

**Adoption Thresholds**:
- Day 7: Expect 30% adoption
- Day 14: Expect 60% adoption
- Day 21: Expect 80% adoption
- Day 30: Expect 95%+ adoption

---

### Phase 3: Cutover (Day 31)

#### Step 3.1: Switch Proxy to New CA Only

```bash
# Update proxy configuration to use new CA
# Environment variable or Vault path change

# Example: Update environment variable
export DERUSTED_CA_PATH="secret/derusted/production/ca-v2"

# Or: Update configuration file
# ca_cert_path = "/etc/derusted/ca-v2-cert.pem"
# ca_key_path = "/etc/derusted/ca-v2-key.pem"
```

#### Step 3.2: Rolling Restart

```bash
# Restart proxies in rolling fashion (zero-downtime)
# Use load balancer health checks

for instance in proxy-1 proxy-2 proxy-3; do
    # Drain connections
    lb-drain $instance

    # Restart with new CA
    systemctl restart derusted@$instance

    # Wait for health check
    wait-for-healthy $instance

    # Re-enable in load balancer
    lb-enable $instance

    # Wait before next instance
    sleep 60
done
```

#### Step 3.3: Verify New CA in Use

```bash
# Connect to proxy and inspect certificate
openssl s_client -connect proxy.example.com:443 -showcerts

# Verify issuer matches new CA
# Check fingerprint matches documented value
```

#### Step 3.4: Monitor for Issues

Watch for:
- Certificate warnings from clients
- Connection failures
- Support ticket spike

If issues arise:
- **Immediate Rollback**: Revert to old CA
- **Investigate**: Identify which clients are affected
- **Extend Dual-Issue**: Give more time for adoption

---

### Phase 4: Cleanup (Day 31-60)

#### Step 4.1: Remove Old CA from Vault/KMS

```bash
# After 30 days of stable operation
# Remove old CA from secret store

# Vault
vault kv delete secret/derusted/production/ca-v1

# AWS Secrets Manager
aws secretsmanager delete-secret \
  --secret-id derusted/production/ca-v1/key \
  --force-delete-without-recovery
```

#### Step 4.2: Client Cleanup

Send communication to clients:
- Old CA is now revoked
- Remove old CA from trust stores
- Verify new CA is installed

Provide cleanup scripts:

**Windows Cleanup**:
```powershell
# Find and remove old CA by fingerprint
$thumbprint = "OLD_CA_FINGERPRINT_HERE"
Get-ChildItem Cert:\CurrentUser\Root | Where-Object {$_.Thumbprint -eq $thumbprint} | Remove-Item
```

**macOS/Linux Cleanup**:
```bash
# macOS
sudo security delete-certificate -t -c "YourOrg MITM CA v1"

# Linux
sudo rm /usr/local/share/ca-certificates/ca-production-v1-cert.crt
sudo update-ca-certificates --fresh
```

#### Step 4.3: Secure Deletion of Old CA Key

```bash
# Securely delete old CA private key from generation machine
shred -vfz -n 10 ca-production-v1-key.pem

# Verify deletion
ls -la ca-production-v1-key.pem  # Should not exist
```

#### Step 4.4: Documentation Update

- Update CA fingerprint documentation
- Update operational runbooks
- Archive old CA details for auditing
- Update this playbook with lessons learned

---

## Scenario 2: Emergency Rotation (Compromise)

**Trigger**: CA private key compromised or suspected compromise

**Timeline**: Immediate action required
- Hour 0-1: Containment
- Hour 1-4: New CA deployment
- Day 1-7: Client migration
- Week 2-4: Investigation and cleanup

### Phase 1: Immediate Containment (<1 Hour)

#### Step 1.1: Confirm Compromise

**Indicators**:
- Unauthorized TLS certificates issued by your CA
- Vault/KMS audit log shows suspicious access
- Private key found in logs/crash dumps/Git
- User reports of suspicious certificates

#### Step 1.2: Emergency Communication

```bash
# Immediately notify:
- Incident response team
- Security team
- Engineering team
- Executive stakeholders

# Use incident management platform (PagerDuty, Opsgenie)
```

#### Step 1.3: Revoke Compromised CA

**Note**: Derusted v0.1.0 doesn't have built-in revocation. Use infrastructure-level blocking.

```bash
# Option 1: Disable all proxies using compromised CA
for instance in $(list-proxy-instances); do
    systemctl stop derusted@$instance
done

# Option 2: Update configuration to reject compromised CA
# Add to block list or update Vault path to invalid
```

#### Step 1.4: Generate Emergency CA

```bash
# IMMEDIATE generation (on secure machine)
export ENV=production
export CA_VERSION=emergency-$(date +%Y%m%d)

# Generate CA (same process as scheduled, but expedited)
openssl genrsa -out ca-${ENV}-${CA_VERSION}-key.pem 4096
openssl req -new -x509 -days 3650 \
  -key ca-${ENV}-${CA_VERSION}-key.pem \
  -out ca-${ENV}-${CA_VERSION}-cert.pem \
  -subj "/C=US/ST=California/L=San Francisco/O=YourOrg/OU=Security-Emergency/CN=YourOrg Emergency CA"

# Upload to Vault/KMS immediately
vault kv put secret/derusted/${ENV}/ca-emergency \
  key=@ca-${ENV}-${CA_VERSION}-key.pem \
  cert=@ca-${ENV}-${CA_VERSION}-cert.pem
```

---

### Phase 2: Emergency Deployment (Hour 1-4)

#### Step 2.1: Deploy Emergency CA to All Proxies

```bash
# Update ALL proxies immediately (parallel deployment)
for instance in $(list-proxy-instances); do
    (
        # Update configuration
        ssh $instance "sudo systemctl set-environment DERUSTED_CA_PATH=secret/derusted/production/ca-emergency"

        # Restart
        ssh $instance "sudo systemctl restart derusted"
    ) &
done

# Wait for all deployments
wait
```

#### Step 2.2: Emergency Client Distribution

**Immediate notification**:
- Email blast to all users (URGENT)
- Slack/Teams announcement
- In-app notification

**Distribution methods** (prioritize speed):
1. **Self-Service**: Post emergency CA on internal portal
2. **Email**: Attach CA + installation scripts
3. **MDM**: Push via device management (if available)

**Sample Emergency Email**:
```
Subject: URGENT - Security Update Required: New CA Certificate

We have detected a security issue requiring immediate action.

ACTION REQUIRED:
1. Download the new CA certificate: [link]
2. Install using the provided script: [instructions]
3. Restart your browser/applications

Until you complete these steps, you may see security warnings.

For immediate assistance: [support contact]
```

#### Step 2.3: Monitor Service Impact

```bash
# Watch for connection failures
# Monitor support tickets
# Track client adoption

# Dashboard should show:
- Proxy uptime: 100%
- Certificate errors: (monitor trend)
- Support tickets: (expect spike)
```

---

### Phase 3: Client Migration (Day 1-7)

#### Step 3.1: Aggressive Communication

- Daily email reminders
- In-app banners
- IT support outreach to non-compliant users

#### Step 3.2: Forced Updates (Enterprise)

```bash
# Use MDM/GPO to force CA installation
# Remote assistance for non-technical users
# Schedule installation during maintenance windows
```

#### Step 3.3: Gradual Service Restoration

- Priority 1: Critical users (exec team, sales)
- Priority 2: Power users (engineering, support)
- Priority 3: General users

---

### Phase 4: Investigation & Cleanup (Week 2-4)

#### Step 4.1: Root Cause Analysis

**Investigate**:
- How was CA compromised?
- What access logs show the compromise?
- Were any certificates maliciously issued?
- What systems were affected?

**Document findings** in incident report.

#### Step 4.2: Review All Issued Certificates

```bash
# Review certificate transparency logs
# Search for certificates issued by compromised CA
# Identify any suspicious certificates

# If malicious certs found:
- Contact affected domains
- Report to abuse contacts
- Consider legal action
```

#### Step 4.3: Permanent CA Replacement

```bash
# After emergency is over, generate production-grade CA
# Follow scheduled rotation process (Scenario 1)
# Replace emergency CA with proper CA
```

#### Step 4.4: Security Improvements

- Update secret management procedures
- Enhance monitoring and alerting
- Implement additional access controls
- Conduct security training
- Update this playbook

---

## Post-Rotation Verification

### Step 1: Verify Proxy Configuration

```bash
# Check that proxy is using correct CA
ps aux | grep derusted  # Check env vars

# Connect and inspect certificate
openssl s_client -connect proxy.example.com:443 -showcerts | \
  openssl x509 -noout -fingerprint -sha256

# Compare fingerprint to documented value
```

### Step 2: Test Client Connections

```bash
# From client machine
curl -v https://example.com --proxy http://proxy.example.com:8080

# Should show:
# - TLS handshake successful
# - Certificate issued by new CA
# - No warnings
```

### Step 3: Verify Trust Store

**Windows**:
```powershell
Get-ChildItem Cert:\CurrentUser\Root | Where-Object {$_.Issuer -like "*YourOrg*"}
```

**macOS**:
```bash
security find-certificate -a -c "YourOrg MITM CA" /Library/Keychains/System.keychain
```

**Linux**:
```bash
grep -r "YourOrg MITM CA" /etc/ssl/certs/ /usr/local/share/ca-certificates/
```

---

## Rollback Procedures

### When to Rollback

- Client adoption <50% after 14 days (scheduled)
- >10% connection failures (emergency)
- Critical business application failures
- Compliance/legal requirements

### Rollback Steps

```bash
# 1. Revert proxy configuration to old CA
export DERUSTED_CA_PATH="secret/derusted/production/ca-v1"

# 2. Rolling restart of proxies
for instance in $(list-proxy-instances); do
    ssh $instance "sudo systemctl restart derusted"
done

# 3. Notify clients (rollback communication)
# 4. Investigate root cause of failure
# 5. Plan retry with corrected approach
```

---

## Troubleshooting

### Problem: Client sees certificate warning

**Cause**: New CA not installed in client trust store

**Solution**:
1. Verify CA certificate file is correct
2. Check installation script ran successfully
3. Restart browser/application
4. Check system trust store

### Problem: Connection failures after rotation

**Cause**: Proxy not using new CA

**Solution**:
1. Check proxy logs for errors
2. Verify Vault/KMS access
3. Confirm environment variables set correctly
4. Restart proxy service

### Problem: Old CA still in use

**Cause**: Configuration not updated

**Solution**:
1. Check configuration files
2. Verify environment variables
3. Check Vault path is correct
4. Restart application

---

## Checklist: Scheduled Rotation

### Pre-Rotation
- [ ] Generate new CA on secure machine
- [ ] Upload CA to Vault/KMS
- [ ] Document fingerprint
- [ ] Prepare client distribution package
- [ ] Test installation scripts
- [ ] Communicate upcoming rotation

### Week 1-4 (Dual-Issue)
- [ ] Deploy new CA to proxies
- [ ] Distribute CA to clients
- [ ] Monitor adoption rate
- [ ] Send adoption reminders

### Day 31 (Cutover)
- [ ] Switch proxies to new CA only
- [ ] Rolling restart
- [ ] Verify new CA in use
- [ ] Monitor for issues

### Day 31-60 (Cleanup)
- [ ] Remove old CA from Vault/KMS
- [ ] Client cleanup communication
- [ ] Securely delete old CA key
- [ ] Update documentation

## Checklist: Emergency Rotation

### Hour 0-1 (Containment)
- [ ] Confirm compromise
- [ ] Notify incident response team
- [ ] Revoke/disable compromised CA
- [ ] Generate emergency CA
- [ ] Upload emergency CA to Vault/KMS

### Hour 1-4 (Deployment)
- [ ] Deploy emergency CA to all proxies
- [ ] Send urgent client notification
- [ ] Distribute emergency CA
- [ ] Monitor service impact

### Day 1-7 (Migration)
- [ ] Daily communication
- [ ] Forced updates (if possible)
- [ ] Prioritize critical users

### Week 2-4 (Investigation)
- [ ] Root cause analysis
- [ ] Review issued certificates
- [ ] Replace with production CA
- [ ] Security improvements
- [ ] Incident report

---

## Appendix: CA Generation Best Practices

### Key Size
- **Minimum**: 2048-bit RSA
- **Recommended**: 4096-bit RSA or 256-bit ECC (P-256)

### Validity Period
- **CA Certificate**: 10 years (3650 days)
- **Leaf Certificates**: 90 days (Derusted default)

### Subject DN
```
C=US                    # Country
ST=California           # State
L=San Francisco         # Locality
O=YourOrganization      # Organization
OU=Security             # Organizational Unit
CN=YourOrg MITM CA v2   # Common Name
```

### X.509 Extensions
- `basicConstraints = critical, CA:TRUE`
- `keyUsage = critical, keyCertSign, cRLSign`
- `subjectKeyIdentifier = hash`

---

## References

- **Threat Model**: `docs/THREAT_MODEL.md`
- **MITM Guide**: `docs/MITM_GUIDE.md`
- **Architecture**: `docs/ARCHITECTURE.md`
- **OpenSSL Documentation**: https://www.openssl.org/docs/

---

**Document Version**: 1.0
**Last Review**: November 25, 2025
**Next Review**: February 25, 2026 (Quarterly)
**Owner**: Derusted Security Team
