use lru::LruCache;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::debug;

/// IP tracker for enforcing unique IP limits per JWT token
/// Prevents token sharing and abuse by limiting how many unique IPs can use a token
#[derive(Debug)]
pub struct IpTracker {
    cache: Arc<Mutex<LruCache<String, TokenIpState>>>,
    max_ips_per_token: usize,
    entry_ttl: Duration,
}

struct TokenIpState {
    ips: BTreeSet<IpAddr>,
    created_at: Instant,
}

#[derive(Debug, thiserror::Error)]
pub enum IpTrackerError {
    #[error(
        "IP limit exceeded: {current_count}/{limit} unique IPs used. Please refresh your token."
    )]
    LimitExceeded {
        token_id: String,
        current_count: usize,
        limit: usize,
    },
}

impl IpTracker {
    /// Create a new IP tracker with configuration
    pub fn new(max_ips_per_token: usize, cache_size: usize, entry_ttl_seconds: u64) -> Self {
        Self {
            cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(cache_size).unwrap(),
            ))),
            max_ips_per_token,
            entry_ttl: Duration::from_secs(entry_ttl_seconds),
        }
    }

    /// Check if IP is allowed for this token and track it
    /// Returns error if IP limit exceeded
    pub async fn check_and_track(
        &self,
        token_id: &str,
        client_ip: IpAddr,
    ) -> Result<(), IpTrackerError> {
        // Normalize dual-stack IPs (::ffff:192.0.2.1 -> 192.0.2.1)
        let normalized_ip = normalize_dual_stack_ip(client_ip);

        let mut cache = self.cache.lock().await;

        // Get or create token state
        let state = match cache.get_mut(token_id) {
            Some(state) => {
                // Check TTL expiration
                if state.created_at.elapsed() > self.entry_ttl {
                    debug!("[IP Tracker] TTL expired for token {}, resetting", token_id);
                    state.ips.clear();
                    state.created_at = Instant::now();
                }
                state
            }
            None => {
                // Create new entry
                cache.put(
                    token_id.to_string(),
                    TokenIpState {
                        ips: BTreeSet::new(),
                        created_at: Instant::now(),
                    },
                );
                cache.get_mut(token_id).unwrap()
            }
        };

        // Check if IP already tracked
        if state.ips.contains(&normalized_ip) {
            debug!(
                "[IP Tracker] IP {} already tracked for token {}",
                normalized_ip, token_id
            );
            return Ok(());
        }

        // Check IP limit
        if state.ips.len() >= self.max_ips_per_token {
            return Err(IpTrackerError::LimitExceeded {
                token_id: token_id.to_string(),
                current_count: state.ips.len(),
                limit: self.max_ips_per_token,
            });
        }

        // Add new IP
        state.ips.insert(normalized_ip);
        debug!(
            "[IP Tracker] Tracked new IP {} for token {} ({}/{} IPs)",
            normalized_ip,
            token_id,
            state.ips.len(),
            self.max_ips_per_token
        );

        Ok(())
    }

    /// Get current IP count for a token (for monitoring/debugging)
    pub async fn get_ip_count(&self, token_id: &str) -> usize {
        let cache = self.cache.lock().await;
        cache
            .peek(token_id)
            .map(|state| state.ips.len())
            .unwrap_or(0)
    }
}

/// Normalize IPv6-mapped IPv4 addresses to IPv4
/// e.g., ::ffff:192.0.2.1 -> 192.0.2.1
/// This prevents same client using IPv4 and IPv6 from counting as 2 IPs
fn normalize_dual_stack_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            // Check if it's an IPv4-mapped IPv6 address
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_track_new_ip() {
        let tracker = IpTracker::new(5, 100, 3600);

        let result = tracker
            .check_and_track("token1", "1.2.3.4".parse().unwrap())
            .await;
        assert!(result.is_ok());

        let count = tracker.get_ip_count("token1").await;
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_track_duplicate_ip() {
        let tracker = IpTracker::new(5, 100, 3600);

        tracker
            .check_and_track("token1", "1.2.3.4".parse().unwrap())
            .await
            .unwrap();
        tracker
            .check_and_track("token1", "1.2.3.4".parse().unwrap())
            .await
            .unwrap();

        let count = tracker.get_ip_count("token1").await;
        assert_eq!(count, 1); // Same IP should not be counted twice
    }

    #[tokio::test]
    async fn test_ip_limit_enforcement() {
        let tracker = IpTracker::new(3, 100, 3600);

        // Add 3 IPs (at limit)
        tracker
            .check_and_track("token1", "1.2.3.4".parse().unwrap())
            .await
            .unwrap();
        tracker
            .check_and_track("token1", "1.2.3.5".parse().unwrap())
            .await
            .unwrap();
        tracker
            .check_and_track("token1", "1.2.3.6".parse().unwrap())
            .await
            .unwrap();

        let count = tracker.get_ip_count("token1").await;
        assert_eq!(count, 3);

        // Try to add 4th IP (should fail)
        let result = tracker
            .check_and_track("token1", "1.2.3.7".parse().unwrap())
            .await;
        assert!(matches!(result, Err(IpTrackerError::LimitExceeded { .. })));

        if let Err(IpTrackerError::LimitExceeded {
            current_count,
            limit,
            ..
        }) = result
        {
            assert_eq!(current_count, 3);
            assert_eq!(limit, 3);
        }
    }

    #[tokio::test]
    async fn test_multiple_tokens() {
        let tracker = IpTracker::new(5, 100, 3600);

        tracker
            .check_and_track("token1", "1.2.3.4".parse().unwrap())
            .await
            .unwrap();
        tracker
            .check_and_track("token2", "1.2.3.4".parse().unwrap())
            .await
            .unwrap();

        let count1 = tracker.get_ip_count("token1").await;
        let count2 = tracker.get_ip_count("token2").await;

        assert_eq!(count1, 1);
        assert_eq!(count2, 1); // Same IP can be used by different tokens
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let tracker = IpTracker::new(5, 100, 1); // 1 second TTL

        tracker
            .check_and_track("token1", "1.2.3.4".parse().unwrap())
            .await
            .unwrap();
        tracker
            .check_and_track("token1", "1.2.3.5".parse().unwrap())
            .await
            .unwrap();

        let count = tracker.get_ip_count("token1").await;
        assert_eq!(count, 2);

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Add new IP - should reset the set
        tracker
            .check_and_track("token1", "1.2.3.6".parse().unwrap())
            .await
            .unwrap();

        let count = tracker.get_ip_count("token1").await;
        assert_eq!(count, 1); // Only the new IP should be tracked
    }

    #[test]
    fn test_normalize_ipv4() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let normalized = normalize_dual_stack_ip(ip);
        assert_eq!(normalized, ip);
    }

    #[test]
    fn test_normalize_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let normalized = normalize_dual_stack_ip(ip);
        assert_eq!(normalized, ip); // Regular IPv6 should not change
    }

    #[test]
    fn test_normalize_ipv4_mapped() {
        // ::ffff:192.0.2.1 should be normalized to 192.0.2.1
        let ip: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        let normalized = normalize_dual_stack_ip(ip);

        assert_eq!(normalized, "192.0.2.1".parse::<IpAddr>().unwrap());
    }
}
