// Rate Limiting Module
// Phase 2: Token bucket rate limiter with per-token limits

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, warn};

#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("Rate limit exceeded for token {0}")]
    LimitExceeded(String),

    #[error("Too many active tokens (max: {0})")]
    TooManyTokens(usize),
}

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Number of tokens currently available
    tokens: f64,

    /// Maximum number of tokens (burst size)
    capacity: f64,

    /// Tokens added per second
    refill_rate: f64,

    /// Last time bucket was refilled
    last_refill: Instant,

    /// When this bucket expires (for cleanup)
    expires_at: Instant,
}

impl TokenBucket {
    /// Create a new token bucket
    fn new(capacity: usize, requests_per_minute: usize, ttl: Duration) -> Self {
        let refill_rate = requests_per_minute as f64 / 60.0; // Convert per-minute to per-second

        Self {
            tokens: capacity as f64,
            capacity: capacity as f64,
            refill_rate,
            last_refill: Instant::now(),
            expires_at: Instant::now() + ttl,
        }
    }

    /// Refill tokens based on time elapsed
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        if elapsed > 0.0 {
            let tokens_to_add = elapsed * self.refill_rate;
            self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
            self.last_refill = now;
        }
    }

    /// Try to consume one token
    fn try_consume(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Check if bucket has expired
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    /// Reset expiry time (bucket is still in use)
    fn reset_expiry(&mut self, ttl: Duration) {
        self.expires_at = Instant::now() + ttl;
    }
}

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Maximum requests per minute per token
    pub requests_per_minute: usize,

    /// Maximum burst size (tokens in bucket)
    pub burst_size: usize,

    /// Time-to-live for inactive buckets (seconds)
    pub bucket_ttl_seconds: u64,

    /// Maximum number of token buckets to track
    pub max_buckets: usize,
}

/// Per-token rate limiter with LRU cache
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimiterConfig,
    buckets: Arc<Mutex<LruCache<String, TokenBucket>>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimiterConfig) -> Self {
        let capacity =
            NonZeroUsize::new(config.max_buckets).expect("max_buckets must be greater than 0");

        Self {
            config,
            buckets: Arc::new(Mutex::new(LruCache::new(capacity))),
        }
    }

    /// Check if request is allowed for given token
    pub async fn check_limit(&self, token_id: &str) -> Result<(), RateLimitError> {
        let mut buckets = self.buckets.lock().await;

        // Get or create bucket for this token
        let bucket = buckets.get_mut(token_id);

        match bucket {
            Some(bucket) => {
                // Check if bucket expired (inactive for too long)
                if bucket.is_expired() {
                    debug!("Token bucket expired for {}, creating new one", token_id);

                    // Create new bucket
                    let new_bucket = TokenBucket::new(
                        self.config.burst_size,
                        self.config.requests_per_minute,
                        Duration::from_secs(self.config.bucket_ttl_seconds),
                    );

                    buckets.put(token_id.to_string(), new_bucket);

                    // Try to consume from new bucket
                    if let Some(bucket) = buckets.get_mut(token_id) {
                        if bucket.try_consume() {
                            Ok(())
                        } else {
                            Err(RateLimitError::LimitExceeded(token_id.to_string()))
                        }
                    } else {
                        // This shouldn't happen, but handle gracefully
                        Err(RateLimitError::LimitExceeded(token_id.to_string()))
                    }
                } else {
                    // Bucket is active, reset expiry and try to consume
                    bucket.reset_expiry(Duration::from_secs(self.config.bucket_ttl_seconds));

                    if bucket.try_consume() {
                        debug!(
                            "Rate limit check passed for {} ({:.2} tokens remaining)",
                            token_id, bucket.tokens
                        );
                        Ok(())
                    } else {
                        warn!(
                            "Rate limit exceeded for {} (capacity: {}, refill: {}/min)",
                            token_id, self.config.burst_size, self.config.requests_per_minute
                        );
                        Err(RateLimitError::LimitExceeded(token_id.to_string()))
                    }
                }
            }
            None => {
                // First request from this token
                debug!("Creating new token bucket for {}", token_id);

                // Check if we've hit max buckets limit
                if buckets.len() >= self.config.max_buckets {
                    // Before rejecting, try to clean up expired buckets to free space
                    let mut expired_tokens = Vec::new();
                    for (tid, bucket) in buckets.iter() {
                        if bucket.is_expired() {
                            expired_tokens.push(tid.clone());
                        }
                    }

                    // Remove expired buckets
                    for tid in &expired_tokens {
                        buckets.pop(tid);
                    }

                    if !expired_tokens.is_empty() {
                        debug!(
                            "Cleaned up {} expired buckets to free space",
                            expired_tokens.len()
                        );
                    }

                    // Recheck capacity after cleanup
                    if buckets.len() >= self.config.max_buckets {
                        warn!(
                            "Max token buckets reached ({}) even after cleanup. Rejecting new token.",
                            self.config.max_buckets
                        );
                        return Err(RateLimitError::TooManyTokens(self.config.max_buckets));
                    }
                }

                // Create new bucket
                let mut bucket = TokenBucket::new(
                    self.config.burst_size,
                    self.config.requests_per_minute,
                    Duration::from_secs(self.config.bucket_ttl_seconds),
                );

                // Try to consume token
                if bucket.try_consume() {
                    buckets.put(token_id.to_string(), bucket);
                    Ok(())
                } else {
                    // This shouldn't happen for a new bucket, but handle gracefully
                    Err(RateLimitError::LimitExceeded(token_id.to_string()))
                }
            }
        }
    }

    /// Get current stats for monitoring
    pub async fn get_stats(&self) -> RateLimiterStats {
        let buckets = self.buckets.lock().await;

        RateLimiterStats {
            active_tokens: buckets.len(),
            max_tokens: self.config.max_buckets,
            requests_per_minute: self.config.requests_per_minute,
            burst_size: self.config.burst_size,
        }
    }

    /// Clean up expired buckets (call periodically)
    pub async fn cleanup_expired(&self) {
        let mut buckets = self.buckets.lock().await;
        let mut expired_tokens = Vec::new();

        // Find expired buckets
        for (token_id, bucket) in buckets.iter() {
            if bucket.is_expired() {
                expired_tokens.push(token_id.clone());
            }
        }

        // Remove expired buckets
        for token_id in &expired_tokens {
            buckets.pop(token_id);
        }

        if !expired_tokens.is_empty() {
            debug!("Cleaned up {} expired token buckets", expired_tokens.len());
        }
    }

    /// Start background cleanup task
    /// This spawns a tokio task that periodically cleans up expired buckets
    pub fn start_cleanup_task(limiter: SharedRateLimiter, interval_secs: u64) {
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                limiter.cleanup_expired().await;
            }
        });
    }
}

/// Rate limiter statistics
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub active_tokens: usize,
    pub max_tokens: usize,
    pub requests_per_minute: usize,
    pub burst_size: usize,
}

/// Thread-safe rate limiter (can be shared across async tasks)
pub type SharedRateLimiter = Arc<RateLimiter>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_creation() {
        let bucket = TokenBucket::new(100, 1000, Duration::from_secs(300));
        assert_eq!(bucket.tokens, 100.0);
        assert_eq!(bucket.capacity, 100.0);
        assert!((bucket.refill_rate - 1000.0 / 60.0).abs() < 0.001);
    }

    #[test]
    fn test_token_bucket_consume() {
        let mut bucket = TokenBucket::new(2, 60, Duration::from_secs(300));

        // Should allow first request
        assert!(bucket.try_consume());
        assert!((bucket.tokens - 1.0).abs() < 0.001);

        // Should allow second request
        assert!(bucket.try_consume());
        assert!(bucket.tokens < 0.1);

        // Should deny third request (burst exhausted)
        assert!(!bucket.try_consume());
    }

    #[tokio::test]
    async fn test_rate_limiter_basic() {
        let config = RateLimiterConfig {
            requests_per_minute: 60,
            burst_size: 5,
            bucket_ttl_seconds: 300,
            max_buckets: 100,
        };

        let limiter = RateLimiter::new(config);

        // First 5 requests should succeed (burst)
        for i in 0..5 {
            let result = limiter.check_limit("test_token").await;
            assert!(result.is_ok(), "Request {} should succeed", i);
        }

        // 6th request should fail (burst exhausted)
        let result = limiter.check_limit("test_token").await;
        assert!(result.is_err(), "Request 6 should fail");
    }

    #[tokio::test]
    async fn test_rate_limiter_multiple_tokens() {
        let config = RateLimiterConfig {
            requests_per_minute: 60,
            burst_size: 2,
            bucket_ttl_seconds: 300,
            max_buckets: 100,
        };

        let limiter = RateLimiter::new(config);

        // Token 1: 2 requests (should succeed)
        assert!(limiter.check_limit("token1").await.is_ok());
        assert!(limiter.check_limit("token1").await.is_ok());

        // Token 2: 2 requests (should succeed)
        assert!(limiter.check_limit("token2").await.is_ok());
        assert!(limiter.check_limit("token2").await.is_ok());

        // Token 1: 3rd request (should fail)
        assert!(limiter.check_limit("token1").await.is_err());

        // Token 2: 3rd request (should fail)
        assert!(limiter.check_limit("token2").await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_stats() {
        let config = RateLimiterConfig {
            requests_per_minute: 60,
            burst_size: 5,
            bucket_ttl_seconds: 300,
            max_buckets: 100,
        };

        let limiter = RateLimiter::new(config);

        // Initially no active tokens
        let stats = limiter.get_stats().await;
        assert_eq!(stats.active_tokens, 0);

        // After request, should have 1 active token
        let _ = limiter.check_limit("test_token").await;
        let stats = limiter.get_stats().await;
        assert_eq!(stats.active_tokens, 1);
    }

    #[tokio::test]
    async fn test_too_many_tokens_error() {
        let config = RateLimiterConfig {
            requests_per_minute: 60,
            burst_size: 5,
            bucket_ttl_seconds: 300,
            max_buckets: 3, // Very low limit to test
        };

        let limiter = RateLimiter::new(config);

        // Add 3 tokens (should succeed)
        assert!(limiter.check_limit("token1").await.is_ok());
        assert!(limiter.check_limit("token2").await.is_ok());
        assert!(limiter.check_limit("token3").await.is_ok());

        // 4th token should fail with TooManyTokens
        let result = limiter.check_limit("token4").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            RateLimitError::TooManyTokens(max) => {
                assert_eq!(max, 3);
            }
            other => panic!("Expected TooManyTokens, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_bucket_ttl_expiry() {
        let config = RateLimiterConfig {
            requests_per_minute: 6000, // High rate to allow refill
            burst_size: 5,
            bucket_ttl_seconds: 1, // Very short TTL for testing
            max_buckets: 100,
        };

        let limiter = RateLimiter::new(config);

        // Make first request
        assert!(limiter.check_limit("test_token").await.is_ok());

        // Wait for bucket to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Next request should create a new bucket (full capacity)
        // If we can make 5 more requests, it's a new bucket
        for i in 0..5 {
            let result = limiter.check_limit("test_token").await;
            assert!(
                result.is_ok(),
                "Request {} should succeed after TTL expiry",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_cleanup_expired_buckets() {
        let config = RateLimiterConfig {
            requests_per_minute: 60,
            burst_size: 5,
            bucket_ttl_seconds: 1, // Short TTL for testing
            max_buckets: 100,
        };

        let limiter = RateLimiter::new(config);

        // Create 3 buckets
        assert!(limiter.check_limit("token1").await.is_ok());
        assert!(limiter.check_limit("token2").await.is_ok());
        assert!(limiter.check_limit("token3").await.is_ok());

        // Verify 3 active tokens
        let stats = limiter.get_stats().await;
        assert_eq!(stats.active_tokens, 3);

        // Wait for buckets to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Clean up expired buckets
        limiter.cleanup_expired().await;

        // Should have no active tokens after cleanup
        let stats = limiter.get_stats().await;
        assert_eq!(stats.active_tokens, 0);
    }

    #[tokio::test]
    async fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(2, 120, Duration::from_secs(300));

        // Consume all tokens
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(!bucket.try_consume()); // Should fail

        // Wait for refill (120 req/min = 2 req/sec)
        tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;

        // Should be able to consume again after refill
        assert!(bucket.try_consume());
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let config = RateLimiterConfig {
            requests_per_minute: 600,
            burst_size: 100,
            bucket_ttl_seconds: 300,
            max_buckets: 100,
        };

        let limiter = Arc::new(RateLimiter::new(config));
        let mut handles = vec![];

        // Spawn 10 concurrent tasks, each making 10 requests
        for task_id in 0..10 {
            let limiter_clone = Arc::clone(&limiter);
            let handle = tokio::spawn(async move {
                let token_id = format!("token_{}", task_id);
                let mut success_count = 0;
                for _ in 0..10 {
                    if limiter_clone.check_limit(&token_id).await.is_ok() {
                        success_count += 1;
                    }
                }
                success_count
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        let mut total_success = 0;
        for handle in handles {
            total_success += handle.await.unwrap();
        }

        // Should allow all 100 requests (within burst capacity)
        assert_eq!(total_success, 100);

        // Verify 10 active tokens
        let stats = limiter.get_stats().await;
        assert_eq!(stats.active_tokens, 10);
    }

    #[tokio::test]
    async fn test_background_cleanup_task() {
        let config = RateLimiterConfig {
            requests_per_minute: 60,
            burst_size: 5,
            bucket_ttl_seconds: 1, // Short TTL
            max_buckets: 100,
        };

        let limiter = Arc::new(RateLimiter::new(config));

        // Create buckets
        assert!(limiter.check_limit("token1").await.is_ok());
        assert!(limiter.check_limit("token2").await.is_ok());

        // Start cleanup task (runs every 2 seconds)
        RateLimiter::start_cleanup_task(Arc::clone(&limiter), 2);

        // Wait for buckets to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Wait for cleanup task to run
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Buckets should be cleaned up automatically
        let stats = limiter.get_stats().await;
        assert_eq!(stats.active_tokens, 0);
    }

    #[tokio::test]
    async fn test_cleanup_expired_before_too_many_tokens() {
        // Phase 2.2: Test that expired buckets are purged before rejecting with TooManyTokens
        let config = RateLimiterConfig {
            requests_per_minute: 60,
            burst_size: 5,
            bucket_ttl_seconds: 1, // Very short TTL for testing
            max_buckets: 3,        // Low limit to trigger capacity check
        };

        let limiter = RateLimiter::new(config);

        // Fill up to max capacity
        assert!(limiter.check_limit("token1").await.is_ok());
        assert!(limiter.check_limit("token2").await.is_ok());
        assert!(limiter.check_limit("token3").await.is_ok());

        // Verify we're at capacity
        let stats = limiter.get_stats().await;
        assert_eq!(stats.active_tokens, 3);

        // Wait for buckets to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // New token should succeed because expired buckets are cleaned up automatically
        // Before Phase 2.2 fix, this would return TooManyTokens
        let result = limiter.check_limit("token4").await;
        assert!(
            result.is_ok(),
            "New token should succeed after expired buckets are purged"
        );

        // Verify old expired buckets were removed and new one was added
        let stats = limiter.get_stats().await;
        assert_eq!(
            stats.active_tokens, 1,
            "Should have only the new token after cleanup"
        );
    }
}
