# Pinaka Rust Proxy - Deployment Guide

## Quick Start with Docker Compose

### 1. Prerequisites

- Docker and Docker Compose installed
- Valid TLS certificate and private key
- Minimum 128MB RAM, 0.5 CPU core

### 2. Setup

```bash
# Clone the repository
git clone https://github.com/kumarprobeops/pinaka-rust-proxy.git
cd pinaka-rust-proxy

# Copy environment template
cp .env.template .env

# Edit .env with your configuration
nano .env
```

### 3. Required Configuration

Edit `.env` and set at minimum:

```bash
# TLS Certificates (REQUIRED)
TLS_CERT_PATH=/etc/letsencrypt/live/your-domain.com/fullchain.pem
TLS_KEY_PATH=/etc/letsencrypt/live/your-domain.com/privkey.pem

# JWT Secret (REQUIRED - must be 32+ characters)
JWT_SECRET=your_very_long_secret_key_at_least_32_characters
```

### 4. Deploy

```bash
# Start the proxy
docker compose up -d

# View logs
docker compose logs -f rust-proxy

# Check status
docker compose ps
```

### 5. Verify Deployment

```bash
# Check logs for successful startup
docker compose logs rust-proxy | grep "Starting Rust"
docker compose logs rust-proxy | grep "Configuration loaded"
docker compose logs rust-proxy | grep "Listening"

# Test ALPN negotiation
openssl s_client -connect localhost:443 -alpn h2,http/1.1
# Should show: ALPN protocol: h2
```

## Production Deployment

### Using Pre-built Docker Image

```bash
# Pull latest image
docker pull kumarprobeops/pinaka-rust-proxy:latest

# Or use specific tag
docker pull kumarprobeops/pinaka-rust-proxy:v0.2.0

# Start with docker compose
docker compose up -d
```

### Building from Source

```bash
# Build Docker image
docker build -t pinaka-rust-proxy:local .

# Update docker-compose.yml to use local image
# image: pinaka-rust-proxy:local

# Deploy
docker compose up -d
```

### TLS Certificate Setup

#### Option 1: Let's Encrypt (Recommended)

```bash
# Install certbot
sudo apt-get install certbot

# Obtain certificate
sudo certbot certonly --standalone -d your-domain.com

# Certificates will be in:
# /etc/letsencrypt/live/your-domain.com/fullchain.pem
# /etc/letsencrypt/live/your-domain.com/privkey.pem

# Update .env
TLS_CERT_PATH=/etc/letsencrypt/live/your-domain.com/fullchain.pem
TLS_KEY_PATH=/etc/letsencrypt/live/your-domain.com/privkey.pem
```

#### Option 2: Self-Signed Certificate (Development Only)

```bash
# Create certs directory
mkdir -p certs

# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -days 365 \
  -subj "/CN=localhost"

# Update .env
TLS_CERT_PATH=./certs/cert.pem
TLS_KEY_PATH=./certs/key.pem

# Update docker-compose.yml volumes
volumes:
  - ./certs:/app/certs:ro
```

## Configuration Options

### Mixed Content Policy (v0.2.0+)

Control how the proxy handles HTTP requests from HTTPS pages:

```bash
# Allow all HTTP requests (default, no change)
MIXED_CONTENT_POLICY=allow

# Attempt to upgrade HTTP→HTTPS
MIXED_CONTENT_POLICY=upgrade
UPGRADE_FAILURE_ACTION=warn  # Or: block, fallback
UPGRADE_PROBE_TIMEOUT=1000   # Milliseconds

# Block all mixed content (strict)
MIXED_CONTENT_POLICY=block
```

**Use Cases:**
- `allow` - Default, no mixed content handling
- `upgrade` - Reduce browser "Not secure" warnings (10-20% coverage)
- `block` - Strict security policy (may break some sites)

**Limitations:**
- Only catches direct HTTP proxy requests (~10-20% of traffic)
- Cannot inspect CONNECT tunnel traffic (~80-90%)
- See CHANGELOG.md for details

### Rate Limiting

```bash
# Per-token rate limits
RATE_LIMIT_REQUESTS_PER_MINUTE=10000  # Adjust based on your needs
RATE_LIMIT_BURST_SIZE=500             # Temporary burst allowance
```

### Backend Integration (Optional)

```bash
# Connect to ProbeOps backend for request logging
BACKEND_URL=https://your-backend.com
PROBE_NODE_NAME=my-proxy-node
PROBE_NODE_REGION=us-east

# Logging configuration
LOG_BATCH_SIZE=100
LOG_BATCH_INTERVAL_SECS=5
```

## Monitoring

### Health Check

```bash
# Docker health check
docker compose ps

# Manual check
curl -k https://localhost:443
```

### Logs

```bash
# View all logs
docker compose logs rust-proxy

# Follow logs
docker compose logs -f rust-proxy

# Search for errors
docker compose logs rust-proxy | grep ERROR

# Check mixed content activity
docker compose logs rust-proxy | grep "Mixed content"
```

### Prometheus Metrics

The proxy exposes Prometheus metrics (if configured). Connect your Prometheus server to scrape metrics.

## Maintenance

### Certificate Renewal

```bash
# Renew Let's Encrypt certificates
sudo certbot renew

# Reload certificates (send SIGHUP to container)
docker compose exec rust-proxy kill -HUP 1

# Or restart container
docker compose restart rust-proxy
```

### Updates

```bash
# Pull latest image
docker compose pull rust-proxy

# Recreate container with new image
docker compose up -d --force-recreate rust-proxy

# View logs to verify
docker compose logs -f rust-proxy
```

### Backup

```bash
# Backup configuration
cp .env .env.backup

# Backup docker-compose.yml
cp docker-compose.yml docker-compose.yml.backup
```

## Troubleshooting

### Container won't start

```bash
# Check logs
docker compose logs rust-proxy

# Common issues:
# 1. JWT_SECRET too short (< 32 characters)
# 2. TLS certificate path incorrect
# 3. Port 443 already in use
```

### TLS handshake errors

```bash
# Verify certificate paths
ls -la $(grep TLS_CERT_PATH .env | cut -d= -f2)
ls -la $(grep TLS_KEY_PATH .env | cut -d= -f2)

# Check certificate validity
openssl x509 -in /path/to/cert.pem -text -noout

# Test TLS connection
openssl s_client -connect localhost:443
```

### High memory usage

```bash
# Check container stats
docker stats pinaka-rust-proxy

# Adjust resource limits in docker-compose.yml
# Typical usage: 1.72 MB RSS (very low)
```

### Rate limit errors

```bash
# Check rate limit configuration
docker compose logs rust-proxy | grep "rate limit"

# Adjust in .env if needed
RATE_LIMIT_REQUESTS_PER_MINUTE=20000  # Increase limit
```

## Performance Tuning

### For High Traffic

```bash
# Increase resource limits in docker-compose.yml
deploy:
  resources:
    limits:
      cpus: '4'
      memory: 1G

# Increase rate limits
RATE_LIMIT_REQUESTS_PER_MINUTE=50000
RATE_LIMIT_BURST_SIZE=2000
RATE_LIMIT_MAX_BUCKETS=50000
```

### For Low Latency

```bash
# Reduce timeouts
CONNECT_TIMEOUT_SECONDS=5
READ_TIMEOUT_SECONDS=15
WRITE_TIMEOUT_SECONDS=15

# Reduce DNS cache TTL
DNS_CACHE_TTL_SECONDS=30
```

## Security Best Practices

1. **Use strong JWT secrets** (64+ characters recommended)
2. **Enable JWT issuer/audience validation** in production
3. **Use Let's Encrypt certificates** (auto-renewal)
4. **Run as non-root user** (default in Docker image)
5. **Set appropriate rate limits** for your use case
6. **Monitor logs** for suspicious activity
7. **Keep Docker image updated** (security patches)

## Support

- **Documentation**: See README.md and CHANGELOG.md
- **Issues**: https://github.com/kumarprobeops/pinaka-rust-proxy/issues
- **Status**: See STATUS.md for feature completion

## License

See LICENSE file in the repository.
