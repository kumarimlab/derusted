use anyhow::Result;
use ipnetwork::IpNetwork;
use lru::LruCache;
use std::collections::HashSet;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, warn};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// Destination filter for SSRF protection
/// Blocks requests to private IPs, localhost, and cloud metadata endpoints
#[derive(Debug)]
pub struct DestinationFilter {
    resolver: Arc<TokioAsyncResolver>,
    dns_cache: Arc<Mutex<LruCache<String, CachedResolution>>>,
    blocked_ranges: Vec<IpNetwork>,
    blocked_hostnames: HashSet<String>,
    resolver_timeout: Duration,
    cache_ttl: Duration,
}

struct CachedResolution {
    ips: Vec<IpAddr>,
    resolved_at: Instant,
}

#[derive(Debug, thiserror::Error)]
pub enum DestinationError {
    #[error("Blocked hostname: {0}")]
    BlockedHostname(String),

    #[error("Blocked IP range: {0}")]
    BlockedIpRange(IpAddr),

    #[error("DNS resolution failed: {0}")]
    ResolutionFailed(String),

    #[error("DNS resolution timeout")]
    ResolutionTimeout,

    #[error("No IP addresses found for hostname: {0}")]
    NoAddressesFound(String),
}

impl DestinationFilter {
    /// Create a new destination filter with configuration
    pub fn new(
        cache_size: usize,
        cache_ttl_seconds: u64,
        resolver_timeout_seconds: u64,
    ) -> Result<Self> {
        // Build DNS resolver with custom timeouts
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(resolver_timeout_seconds);
        opts.attempts = 2; // Try twice

        // Use system resolver by default (respects /etc/resolv.conf, split-horizon DNS, etc.)
        // Falls back to Google DNS only if system config is unavailable
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|_| {
            warn!("Failed to load system DNS config, falling back to Google DNS");
            TokioAsyncResolver::tokio(ResolverConfig::google(), opts.clone())
        });

        Ok(Self {
            resolver: Arc::new(resolver),
            dns_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(cache_size).unwrap(),
            ))),
            blocked_ranges: load_blocked_ranges()?,
            blocked_hostnames: load_blocked_hostnames(),
            resolver_timeout: Duration::from_secs(resolver_timeout_seconds),
            cache_ttl: Duration::from_secs(cache_ttl_seconds),
        })
    }

    /// Check if a destination is allowed and return ALL vetted IPs
    /// Caller MUST use these IPs and NOT re-resolve the hostname
    pub async fn check_and_resolve(&self, host: &str) -> Result<Vec<IpAddr>, DestinationError> {
        debug!("[SSRF] Checking destination: {}", host);

        // 1. Check hostname blocklist first
        if self.is_hostname_blocked(host) {
            warn!("[SSRF] Blocked hostname: {}", host);
            return Err(DestinationError::BlockedHostname(host.to_string()));
        }

        // 2. Resolve hostname to IPs (with caching)
        let ips = self.resolve_with_cache(host).await?;

        if ips.is_empty() {
            return Err(DestinationError::NoAddressesFound(host.to_string()));
        }

        // 3. Check ALL resolved IPs against blocklist
        for ip in &ips {
            if self.is_ip_blocked(*ip) {
                warn!("[SSRF] Blocked IP {} for hostname {}", ip, host);
                return Err(DestinationError::BlockedIpRange(*ip));
            }
        }

        debug!("[SSRF] Allowed destination {} -> {:?}", host, ips);
        Ok(ips)
    }

    /// Resolve hostname with caching
    async fn resolve_with_cache(&self, host: &str) -> Result<Vec<IpAddr>, DestinationError> {
        let mut cache = self.dns_cache.lock().await;

        // Check cache first
        if let Some(cached) = cache.get(host) {
            if cached.resolved_at.elapsed() < self.cache_ttl {
                debug!("[DNS] Cache hit for {}: {:?}", host, cached.ips);
                return Ok(cached.ips.clone());
            }
        }

        // Cache miss or expired - resolve with timeout
        drop(cache); // Release lock during DNS lookup

        let lookup_result = timeout(self.resolver_timeout, self.resolver.lookup_ip(host)).await;

        let ips = match lookup_result {
            Ok(Ok(lookup)) => {
                let ips: Vec<IpAddr> = lookup.iter().collect();
                debug!("[DNS] Resolved {} -> {:?}", host, ips);
                ips
            }
            Ok(Err(e)) => {
                warn!("[DNS] Resolution failed for {}: {}", host, e);
                return Err(DestinationError::ResolutionFailed(e.to_string()));
            }
            Err(_) => {
                warn!("[DNS] Resolution timeout for {}", host);
                return Err(DestinationError::ResolutionTimeout);
            }
        };

        // Update cache
        let mut cache = self.dns_cache.lock().await;
        cache.put(
            host.to_string(),
            CachedResolution {
                ips: ips.clone(),
                resolved_at: Instant::now(),
            },
        );

        Ok(ips)
    }

    /// Check if hostname is blocked
    fn is_hostname_blocked(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();

        // Exact match in blocklist
        if self.blocked_hostnames.contains(&host_lower) {
            return true;
        }

        // localhost variants
        if host_lower == "localhost"
            || host_lower.ends_with(".localhost")
            || host_lower == "ip6-localhost"
            || host_lower == "ip6-loopback"
        {
            return true;
        }

        // Internal/private domain patterns
        if host_lower.ends_with(".local")      // mDNS
            || host_lower.ends_with(".internal") // Common private
            || host_lower.ends_with(".localdomain")
            || host_lower.ends_with(".home")
            || host_lower.ends_with(".lan")
        {
            return true;
        }

        false
    }

    /// Check if IP is in blocked ranges
    fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        for range in &self.blocked_ranges {
            if range.contains(ip) {
                return true;
            }
        }
        false
    }
}

/// Load blocked IP ranges (RFC1918, localhost, metadata, etc.)
fn load_blocked_ranges() -> Result<Vec<IpNetwork>> {
    const BLOCKED_CIDRS: &[&str] = &[
        // IPv4 Private Networks (RFC1918)
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        // IPv4 Localhost
        "127.0.0.0/8",
        // IPv4 Link-Local
        "169.254.0.0/16",
        // IPv4 Metadata Services
        "169.254.169.254/32", // AWS, Azure, GCP
        // IPv4 Broadcast/Special
        "0.0.0.0/8",          // Current network
        "255.255.255.255/32", // Broadcast
        "224.0.0.0/4",        // Multicast
        "240.0.0.0/4",        // Reserved
        // IPv6 Localhost
        "::1/128",
        // IPv6 Link-Local
        "fe80::/10",
        // IPv6 Unique Local Addresses (ULA)
        "fc00::/7",
        // IPv6 Metadata (AWS)
        "fd00:ec2::254/128",
        // IPv6 Documentation/Reserved
        "2001:db8::/32", // Documentation
        "ff00::/8",      // Multicast
    ];

    let mut ranges = Vec::new();
    for cidr in BLOCKED_CIDRS {
        ranges.push(cidr.parse()?);
    }

    Ok(ranges)
}

/// Load blocked hostnames (metadata endpoints)
fn load_blocked_hostnames() -> HashSet<String> {
    let mut set = HashSet::new();

    // Metadata service hostnames
    set.insert("metadata.google.internal".to_string());
    set.insert("metadata.azure.com".to_string());
    set.insert("instance-data.ec2.internal".to_string());

    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_block_localhost() {
        let filter = DestinationFilter::new(100, 60, 5).unwrap();

        let result = filter.check_and_resolve("localhost").await;
        assert!(matches!(result, Err(DestinationError::BlockedHostname(_))));
    }

    #[tokio::test]
    async fn test_block_localhost_variants() {
        let filter = DestinationFilter::new(100, 60, 5).unwrap();

        assert!(filter.check_and_resolve("ip6-localhost").await.is_err());
        assert!(filter.check_and_resolve("test.localhost").await.is_err());
    }

    #[tokio::test]
    async fn test_block_metadata_hostname() {
        let filter = DestinationFilter::new(100, 60, 5).unwrap();

        let result = filter.check_and_resolve("metadata.google.internal").await;
        assert!(matches!(result, Err(DestinationError::BlockedHostname(_))));
    }

    // This test requires outbound network access for DNS resolution to example.com
    // Enable with: cargo test --lib --features network-tests
    #[cfg(feature = "network-tests")]
    #[tokio::test]
    async fn test_allow_public_domain() {
        let filter = DestinationFilter::new(100, 60, 5).unwrap();

        let result = filter.check_and_resolve("example.com").await;
        assert!(result.is_ok());
        let ips = result.unwrap();
        assert!(!ips.is_empty());
    }

    // This test requires outbound network access for DNS resolution to example.com
    // Enable with: cargo test --lib --features network-tests
    #[cfg(feature = "network-tests")]
    #[tokio::test]
    async fn test_dns_caching() {
        let filter = DestinationFilter::new(100, 60, 5).unwrap();

        // First lookup
        let start = Instant::now();
        let ips1 = filter.check_and_resolve("example.com").await.unwrap();
        let first_duration = start.elapsed();

        // Second lookup (should be cached)
        let start = Instant::now();
        let ips2 = filter.check_and_resolve("example.com").await.unwrap();
        let second_duration = start.elapsed();

        // Same IPs
        assert_eq!(ips1, ips2);

        // Second lookup should be much faster (< 1ms vs > 10ms)
        assert!(second_duration < first_duration / 2);
    }

    #[test]
    fn test_is_ip_blocked_rfc1918() {
        let filter = DestinationFilter::new(100, 60, 5).unwrap();

        assert!(filter.is_ip_blocked("10.0.0.1".parse().unwrap()));
        assert!(filter.is_ip_blocked("172.16.0.1".parse().unwrap()));
        assert!(filter.is_ip_blocked("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_is_ip_blocked_localhost() {
        let filter = DestinationFilter::new(100, 60, 5).unwrap();

        assert!(filter.is_ip_blocked("127.0.0.1".parse().unwrap()));
        assert!(filter.is_ip_blocked("127.255.255.255".parse().unwrap()));
        assert!(filter.is_ip_blocked("::1".parse().unwrap()));
    }

    #[test]
    fn test_is_ip_blocked_metadata() {
        let filter = DestinationFilter::new(100, 60, 5).unwrap();

        assert!(filter.is_ip_blocked("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn test_is_ip_allowed_public() {
        let filter = DestinationFilter::new(100, 60, 5).unwrap();

        assert!(!filter.is_ip_blocked("8.8.8.8".parse().unwrap()));
        assert!(!filter.is_ip_blocked("1.1.1.1".parse().unwrap()));
        assert!(!filter.is_ip_blocked("93.184.216.34".parse().unwrap())); // example.com
    }

    #[test]
    fn test_hostname_blocked() {
        let filter = DestinationFilter::new(100, 60, 5).unwrap();

        assert!(filter.is_hostname_blocked("localhost"));
        assert!(filter.is_hostname_blocked("Localhost")); // case insensitive
        assert!(filter.is_hostname_blocked("test.localhost"));
        assert!(filter.is_hostname_blocked("metadata.google.internal"));
    }

    #[test]
    fn test_hostname_allowed() {
        let filter = DestinationFilter::new(100, 60, 5).unwrap();

        assert!(!filter.is_hostname_blocked("example.com"));
        assert!(!filter.is_hostname_blocked("google.com"));
    }
}
