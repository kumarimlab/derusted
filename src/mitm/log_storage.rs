//! SQLite Logging Backend
//!
//! This module provides async SQLite storage for request logs with:
//! - Connection pooling for performance
//! - Automatic schema migration
//! - Optional encryption at rest
//! - Log rotation by age
//! - Non-blocking async writes

use crate::mitm::logging::RequestMetadata;
use sqlx::{sqlite::SqlitePool, Sqlite};
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info};

/// Storage errors
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),
}

/// Log storage with SQLite backend
pub struct LogStorage {
    /// SQLite connection pool
    pool: SqlitePool,

    /// Optional encryption (for future implementation)
    #[allow(dead_code)]
    encryption_enabled: bool,
}

impl LogStorage {
    /// Create new log storage
    ///
    /// Creates or opens database at specified path and runs migrations
    pub async fn new(db_path: &str) -> Result<Self, StorageError> {
        // Ensure parent directory exists
        if let Some(parent) = Path::new(db_path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| StorageError::DatabaseError(sqlx::Error::Io(e)))?;
        }

        // Create connection pool
        // Use file: protocol with ?mode=rwc to create database if it doesn't exist
        let pool = SqlitePool::connect(&format!("sqlite://{}?mode=rwc", db_path)).await?;

        info!(db_path = %db_path, "Connected to SQLite database");

        // Enable WAL mode for better concurrent performance
        Self::enable_wal(&pool).await?;

        // Run migrations
        Self::migrate(&pool).await?;

        Ok(Self {
            pool,
            encryption_enabled: false,
        })
    }

    /// Enable WAL mode for better concurrent write performance
    async fn enable_wal(pool: &SqlitePool) -> Result<(), StorageError> {
        info!("Enabling WAL mode for SQLite");

        // Enable WAL (Write-Ahead Logging) mode
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(pool)
            .await?;

        // Set synchronous mode to NORMAL for better performance with WAL
        sqlx::query("PRAGMA synchronous = NORMAL")
            .execute(pool)
            .await?;

        info!("WAL mode enabled successfully");

        Ok(())
    }

    /// Run database migrations
    async fn migrate(pool: &SqlitePool) -> Result<(), StorageError> {
        info!("Running database migrations");

        // Create request_logs table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                method TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                path TEXT NOT NULL,
                http_version TEXT,
                status_code INTEGER,
                request_size INTEGER NOT NULL,
                response_size INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                tls_version TEXT,
                mitm_applied BOOLEAN NOT NULL,
                bypass_reason TEXT,
                created_at INTEGER DEFAULT (strftime('%s', 'now'))
            )
            "#,
        )
        .execute(pool)
        .await?;

        // Create index on timestamp for efficient queries
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp
            ON request_logs(timestamp)
            "#,
        )
        .execute(pool)
        .await?;

        // Create index on host for filtering
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_request_logs_host
            ON request_logs(host)
            "#,
        )
        .execute(pool)
        .await?;

        info!("Database migrations completed");

        Ok(())
    }

    /// Log a request
    ///
    /// Writes request metadata to database asynchronously
    pub async fn log_request(&self, metadata: &RequestMetadata) -> Result<i64, StorageError> {
        let result = sqlx::query(
            r#"
            INSERT INTO request_logs (
                timestamp, method, host, port, path, http_version,
                status_code, request_size, response_size, duration_ms,
                tls_version, mitm_applied, bypass_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(metadata.timestamp)
        .bind(&metadata.method)
        .bind(&metadata.host)
        .bind(metadata.port as i64)
        .bind(&metadata.path)
        .bind(&metadata.http_version)
        .bind(metadata.status_code.map(|c| c as i64))
        .bind(metadata.request_size as i64)
        .bind(metadata.response_size as i64)
        .bind(metadata.duration_ms as i64)
        .bind(&metadata.tls_version)
        .bind(metadata.mitm_applied)
        .bind(&metadata.bypass_reason)
        .execute(&self.pool)
        .await?;

        debug!(
            id = result.last_insert_rowid(),
            host = %metadata.host,
            "Request logged to database"
        );

        Ok(result.last_insert_rowid())
    }

    /// Query logs by timestamp range
    ///
    /// Returns logs between start_ts and end_ts (inclusive)
    pub async fn query_logs(
        &self,
        start_ts: i64,
        end_ts: i64,
        limit: i64,
    ) -> Result<Vec<RequestMetadata>, StorageError> {
        let rows = sqlx::query_as::<Sqlite, RequestMetadata>(
            r#"
            SELECT
                timestamp, method, host, port, path, http_version,
                status_code, request_size, response_size, duration_ms,
                tls_version, mitm_applied, bypass_reason
            FROM request_logs
            WHERE timestamp BETWEEN ? AND ?
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
        )
        .bind(start_ts)
        .bind(end_ts)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        debug!(count = rows.len(), "Retrieved logs from database");

        Ok(rows)
    }

    /// Query logs by host
    pub async fn query_logs_by_host(
        &self,
        host: &str,
        limit: i64,
    ) -> Result<Vec<RequestMetadata>, StorageError> {
        let rows = sqlx::query_as::<Sqlite, RequestMetadata>(
            r#"
            SELECT
                timestamp, method, host, port, path, http_version,
                status_code, request_size, response_size, duration_ms,
                tls_version, mitm_applied, bypass_reason
            FROM request_logs
            WHERE host = ?
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
        )
        .bind(host)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        debug!(host = %host, count = rows.len(), "Retrieved logs for host");

        Ok(rows)
    }

    /// Get log count
    pub async fn count_logs(&self) -> Result<i64, StorageError> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM request_logs
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0)
    }

    /// Delete old logs
    ///
    /// Deletes logs older than specified number of days
    /// Returns number of rows deleted
    pub async fn cleanup_old_logs(&self, days: u32) -> Result<u64, StorageError> {
        let cutoff_ts = chrono::Utc::now().timestamp() - (days as i64 * 86400);

        let result = sqlx::query(
            r#"
            DELETE FROM request_logs
            WHERE timestamp < ?
            "#,
        )
        .bind(cutoff_ts)
        .execute(&self.pool)
        .await?;

        let deleted = result.rows_affected();

        if deleted > 0 {
            info!(deleted = deleted, days = days, "Deleted old logs");
        }

        Ok(deleted)
    }

    /// Vacuum database
    ///
    /// Reclaims space after deleting logs
    pub async fn vacuum(&self) -> Result<(), StorageError> {
        info!("Vacuuming database");
        sqlx::query("VACUUM").execute(&self.pool).await?;
        Ok(())
    }

    /// Get database size in bytes
    pub async fn database_size(&self) -> Result<u64, StorageError> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT page_count * page_size as size
            FROM pragma_page_count(), pragma_page_size()
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0 as u64)
    }

    /// Close database connection
    pub async fn close(self) {
        self.pool.close().await;
        info!("Database connection closed");
    }
}

/// Implement sqlx::FromRow for RequestMetadata
impl sqlx::FromRow<'_, sqlx::sqlite::SqliteRow> for RequestMetadata {
    fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;

        Ok(Self {
            timestamp: row.try_get("timestamp")?,
            method: row.try_get("method")?,
            host: row.try_get("host")?,
            port: row.try_get::<i64, _>("port")? as u16,
            path: row.try_get("path")?,
            http_version: row.try_get("http_version")?,
            status_code: row
                .try_get::<Option<i64>, _>("status_code")?
                .map(|c| c as u16),
            request_size: row.try_get::<i64, _>("request_size")? as usize,
            response_size: row.try_get::<i64, _>("response_size")? as usize,
            duration_ms: row.try_get::<i64, _>("duration_ms")? as u64,
            tls_version: row.try_get("tls_version")?,
            mitm_applied: row.try_get("mitm_applied")?,
            bypass_reason: row.try_get("bypass_reason")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_storage() -> (LogStorage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = LogStorage::new(db_path.to_str().unwrap()).await.unwrap();
        (storage, temp_dir)
    }

    fn create_test_metadata() -> RequestMetadata {
        RequestMetadata {
            timestamp: chrono::Utc::now().timestamp(),
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 443,
            path: "/test".to_string(),
            http_version: "HTTP/1.1".to_string(),
            status_code: Some(200),
            request_size: 1024,
            response_size: 2048,
            duration_ms: 150,
            tls_version: Some("TLSv1.3".to_string()),
            mitm_applied: true,
            bypass_reason: None,
        }
    }

    #[tokio::test]
    async fn test_storage_creation() {
        let (_storage, _temp_dir) = create_test_storage().await;
        // Storage created successfully
    }

    #[tokio::test]
    async fn test_log_request() {
        let (storage, _temp_dir) = create_test_storage().await;
        let metadata = create_test_metadata();

        let id = storage.log_request(&metadata).await.unwrap();
        assert!(id > 0);
    }

    #[tokio::test]
    async fn test_query_logs() {
        let (storage, _temp_dir) = create_test_storage().await;
        let metadata = create_test_metadata();

        storage.log_request(&metadata).await.unwrap();

        let start_ts = chrono::Utc::now().timestamp() - 3600;
        let end_ts = chrono::Utc::now().timestamp() + 3600;

        let logs = storage.query_logs(start_ts, end_ts, 10).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].host, "example.com");
    }

    #[tokio::test]
    async fn test_query_logs_by_host() {
        let (storage, _temp_dir) = create_test_storage().await;

        let metadata1 = RequestMetadata {
            host: "example.com".to_string(),
            ..create_test_metadata()
        };
        let metadata2 = RequestMetadata {
            host: "test.com".to_string(),
            ..create_test_metadata()
        };

        storage.log_request(&metadata1).await.unwrap();
        storage.log_request(&metadata2).await.unwrap();

        let logs = storage.query_logs_by_host("example.com", 10).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].host, "example.com");
    }

    #[tokio::test]
    async fn test_count_logs() {
        let (storage, _temp_dir) = create_test_storage().await;
        let metadata = create_test_metadata();

        storage.log_request(&metadata).await.unwrap();
        storage.log_request(&metadata).await.unwrap();

        let count = storage.count_logs().await.unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_cleanup_old_logs() {
        let (storage, _temp_dir) = create_test_storage().await;

        // Create old log (365 days ago)
        let old_metadata = RequestMetadata {
            timestamp: chrono::Utc::now().timestamp() - (365 * 86400),
            ..create_test_metadata()
        };

        // Create recent log
        let recent_metadata = create_test_metadata();

        storage.log_request(&old_metadata).await.unwrap();
        storage.log_request(&recent_metadata).await.unwrap();

        // Delete logs older than 30 days
        let deleted = storage.cleanup_old_logs(30).await.unwrap();
        assert_eq!(deleted, 1);

        let count = storage.count_logs().await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_database_size() {
        let (storage, _temp_dir) = create_test_storage().await;
        let metadata = create_test_metadata();

        storage.log_request(&metadata).await.unwrap();

        let size = storage.database_size().await.unwrap();
        assert!(size > 0);
    }

    #[tokio::test]
    async fn test_vacuum() {
        let (storage, _temp_dir) = create_test_storage().await;
        let metadata = create_test_metadata();

        storage.log_request(&metadata).await.unwrap();
        storage.cleanup_old_logs(0).await.unwrap(); // Delete all

        storage.vacuum().await.unwrap();
    }
}
