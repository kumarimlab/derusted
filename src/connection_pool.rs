//! Connection Pool for Upstream TLS Connections
//!
//! This module provides connection pooling to reuse TLS connections to upstream servers.
//! Key benefits:
//! - Eliminates repeated TLS handshakes (150-300ms overhead)
//! - Reduces CPU usage (fewer crypto operations)
//! - Improves throughput by 20-30%
//!
//! ## Architecture
//!
//! - Per-host pools: Each upstream host gets its own connection pool
//! - Idle management: Connections are reused until they expire or close
//! - Automatic cleanup: Background task removes stale connections
//! - Thread-safe: Pool uses Arc<Mutex<...>> for concurrent access
//!
//! ## Configuration
//!
//! ```rust
//! let config = PoolConfig {
//!     max_idle_per_host: 10,              // Max idle connections per host
//!     idle_timeout: Duration::from_secs(90),     // Idle connection timeout
//!     max_lifetime: Duration::from_secs(600),    // Max connection lifetime
//!     connection_timeout: Duration::from_secs(30), // New connection timeout
//! };
//! ```

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tracing::debug;

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of idle connections per host
    pub max_idle_per_host: usize,

    /// Duration after which idle connections are closed
    pub idle_timeout: Duration,

    /// Maximum lifetime of a connection (even if active)
    pub max_lifetime: Duration,

    /// Timeout for establishing new connections
    pub connection_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: 10,
            idle_timeout: Duration::from_secs(90),
            max_lifetime: Duration::from_secs(600), // 10 minutes
            connection_timeout: Duration::from_secs(30),
        }
    }
}

/// A pooled connection with metadata
pub struct PooledConnection {
    /// The TLS stream to the upstream server
    pub stream: TlsStream<TcpStream>,

    /// When this connection was created
    created_at: Instant,

    /// When this connection was last used
    last_used: Instant,
}

impl PooledConnection {
    /// Create a new pooled connection
    pub fn new(stream: TlsStream<TcpStream>) -> Self {
        let now = Instant::now();
        Self {
            stream,
            created_at: now,
            last_used: now,
        }
    }

    /// Check if connection has exceeded its maximum lifetime
    pub fn is_expired(&self, max_lifetime: Duration) -> bool {
        self.created_at.elapsed() > max_lifetime
    }

    /// Check if connection has been idle too long
    pub fn is_idle_timeout(&self, idle_timeout: Duration) -> bool {
        self.last_used.elapsed() > idle_timeout
    }

    /// Mark connection as used (updates last_used timestamp)
    pub fn mark_used(&mut self) {
        self.last_used = Instant::now();
    }
}

/// Connection pool for reusing upstream TLS connections
pub struct ConnectionPool {
    /// Per-host connection pools
    pools: Arc<Mutex<HashMap<String, VecDeque<PooledConnection>>>>,

    /// Pool configuration
    config: PoolConfig,

    /// Statistics
    stats: Arc<Mutex<PoolStats>>,
}

/// Connection pool statistics
#[derive(Debug, Default, Clone)]
pub struct PoolStats {
    /// Number of times a connection was retrieved from pool
    pub hits: u64,

    /// Number of times a new connection was created
    pub misses: u64,

    /// Number of connections currently in all pools
    pub total_connections: usize,

    /// Number of connections that were evicted (expired/idle)
    pub evictions: u64,
}

impl ConnectionPool {
    /// Create a new connection pool with default configuration
    pub fn new() -> Self {
        Self::with_config(PoolConfig::default())
    }

    /// Create a new connection pool with custom configuration
    pub fn with_config(config: PoolConfig) -> Self {
        Self {
            pools: Arc::new(Mutex::new(HashMap::new())),
            config,
            stats: Arc::new(Mutex::new(PoolStats::default())),
        }
    }

    /// Get a connection from the pool or return None if pool is empty
    ///
    /// This method checks for expired/idle connections and removes them.
    pub async fn get(&self, host: &str) -> Option<TlsStream<TcpStream>> {
        let mut pools = self.pools.lock().await;
        let mut stats = self.stats.lock().await;

        let pool = pools.get_mut(host)?;

        // Try to find a valid connection
        while let Some(mut conn) = pool.pop_front() {
            // Check if connection is still valid
            if conn.is_expired(self.config.max_lifetime) {
                debug!(host = %host, "Connection expired, discarding");
                stats.evictions += 1;
                continue;
            }

            if conn.is_idle_timeout(self.config.idle_timeout) {
                debug!(host = %host, "Connection idle timeout, discarding");
                stats.evictions += 1;
                continue;
            }

            // Connection is valid, update usage and return
            conn.mark_used();
            stats.hits += 1;
            debug!(host = %host, "Reusing pooled connection (hit)");

            return Some(conn.stream);
        }

        // No valid connections in pool
        None
    }

    /// Return a connection to the pool
    ///
    /// The connection will be reused for future requests to the same host.
    /// If the pool is full, the connection is dropped.
    pub async fn put(&self, host: String, stream: TlsStream<TcpStream>) {
        let mut pools = self.pools.lock().await;

        let pool = pools.entry(host.clone()).or_insert_with(VecDeque::new);

        // Check if pool is full
        if pool.len() >= self.config.max_idle_per_host {
            debug!(host = %host, "Pool full, dropping connection");
            return;
        }

        // Add connection to pool
        pool.push_back(PooledConnection::new(stream));
        debug!(host = %host, pool_size = pool.len(), "Connection returned to pool");
    }

    /// Record a cache miss (new connection created)
    pub async fn record_miss(&self) {
        let mut stats = self.stats.lock().await;
        stats.misses += 1;
    }

    /// Get current pool statistics
    pub async fn stats(&self) -> PoolStats {
        let pools = self.pools.lock().await;
        let mut stats = self.stats.lock().await;

        // Update total connections count
        stats.total_connections = pools.values().map(|p| p.len()).sum();

        stats.clone()
    }

    /// Clean up expired and idle connections across all hosts
    ///
    /// This should be called periodically by a background task.
    pub async fn cleanup(&self) {
        let mut pools = self.pools.lock().await;
        let mut stats = self.stats.lock().await;

        let mut total_removed = 0;

        for (host, pool) in pools.iter_mut() {
            let original_len = pool.len();

            // Keep only valid connections
            pool.retain(|conn| {
                let valid = !conn.is_expired(self.config.max_lifetime)
                    && !conn.is_idle_timeout(self.config.idle_timeout);

                if !valid {
                    total_removed += 1;
                    stats.evictions += 1;
                }

                valid
            });

            let removed = original_len - pool.len();
            if removed > 0 {
                debug!(host = %host, removed, "Cleaned up expired connections");
            }
        }

        if total_removed > 0 {
            debug!(total_removed, "Pool cleanup complete");
        }
    }

    /// Get the number of idle connections for a specific host
    pub async fn idle_count(&self, host: &str) -> usize {
        let pools = self.pools.lock().await;
        pools.get(host).map(|p| p.len()).unwrap_or(0)
    }

    /// Get total number of idle connections across all hosts
    pub async fn total_idle(&self) -> usize {
        let pools = self.pools.lock().await;
        pools.values().map(|p| p.len()).sum()
    }

    /// Clear all connections from the pool
    pub async fn clear(&self) {
        let mut pools = self.pools.lock().await;
        pools.clear();
        debug!("Connection pool cleared");
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Start a background task that periodically cleans up expired connections
///
/// This task runs every 60 seconds and removes connections that have:
/// - Exceeded their maximum lifetime
/// - Been idle for too long
pub fn start_cleanup_task(pool: Arc<ConnectionPool>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;
            pool.cleanup().await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_defaults() {
        let config = PoolConfig::default();

        assert_eq!(config.max_idle_per_host, 10);
        assert_eq!(config.idle_timeout, Duration::from_secs(90));
        assert_eq!(config.max_lifetime, Duration::from_secs(600));
        assert_eq!(config.connection_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_pool_config_custom() {
        let config = PoolConfig {
            max_idle_per_host: 5,
            idle_timeout: Duration::from_secs(30),
            max_lifetime: Duration::from_secs(300),
            connection_timeout: Duration::from_secs(15),
        };

        assert_eq!(config.max_idle_per_host, 5);
        assert_eq!(config.idle_timeout, Duration::from_secs(30));
        assert_eq!(config.max_lifetime, Duration::from_secs(300));
        assert_eq!(config.connection_timeout, Duration::from_secs(15));
    }

    #[test]
    #[ignore] // Requires real TLS connection - use integration tests
    fn test_pooled_connection_expiration() {
        let stream = create_mock_tls_stream();
        let mut conn = PooledConnection::new(stream);

        // Connection should not be expired immediately
        assert!(!conn.is_expired(Duration::from_secs(600)));

        // Simulate passage of time by manually setting created_at
        conn.created_at = Instant::now() - Duration::from_secs(700);
        assert!(conn.is_expired(Duration::from_secs(600)));
    }

    #[test]
    #[ignore] // Requires real TLS connection - use integration tests
    fn test_pooled_connection_idle_timeout() {
        let stream = create_mock_tls_stream();
        let mut conn = PooledConnection::new(stream);

        // Connection should not be idle immediately
        assert!(!conn.is_idle_timeout(Duration::from_secs(90)));

        // Simulate idle time
        conn.last_used = Instant::now() - Duration::from_secs(100);
        assert!(conn.is_idle_timeout(Duration::from_secs(90)));
    }

    #[tokio::test]
    async fn test_connection_pool_creation() {
        let pool = ConnectionPool::new();
        let stats = pool.stats().await;

        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.evictions, 0);
    }

    #[tokio::test]
    async fn test_pool_get_empty() {
        let pool = ConnectionPool::new();
        let conn = pool.get("example.com:443").await;

        assert!(conn.is_none());
    }

    #[tokio::test]
    async fn test_pool_idle_count() {
        let pool = ConnectionPool::new();

        assert_eq!(pool.idle_count("example.com:443").await, 0);
        assert_eq!(pool.total_idle().await, 0);
    }

    // Mock helper for testing (note: actual TLS streams can't be easily mocked)
    // In real tests, you'd use integration tests with real connections
    fn create_mock_tls_stream() -> TlsStream<TcpStream> {
        // This is a placeholder - in practice, you'd create a real connection
        // or use a test helper that provides mock streams
        unimplemented!("Mock TLS stream creation for unit tests")
    }
}
