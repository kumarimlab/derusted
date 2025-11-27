use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// Individual log entry matching backend's BatchLogEntry schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub token_id: String,
    pub user_id: i32,
    pub timestamp: String, // ISO8601 format
    pub method: String,
    pub target_url: String,
    pub status_code: Option<i32>,
    pub response_size: i64,
    pub duration_ms: Option<i64>,
    pub success: bool,
    pub rate_limited: bool,
    pub error_message: Option<String>,
}

/// Batch log submission request matching backend's BatchLogSubmitRequest schema
#[derive(Debug, Serialize)]
struct BatchLogSubmitRequest {
    logs: Vec<LogEntry>,
    probe_node_name: String,
    region: String,
}

/// Batch log submission response from backend
#[derive(Debug, Deserialize)]
struct BatchLogSubmitResponse {
    submitted: i32,
    failed: i32,
    errors: Option<Vec<String>>,
}

/// Request logger that batches logs and sends to backend API
#[derive(Debug)]
pub struct RequestLogger {
    backend_url: String,
    probe_node_name: String,
    probe_node_region: String,
    batch_size: usize,
    batch_interval: Duration,
    pending_logs: Arc<Mutex<Vec<LogEntry>>>,
    http_client: reqwest::Client,
}

impl RequestLogger {
    /// Create a new request logger
    pub fn new(
        backend_url: String,
        probe_node_name: String,
        probe_node_region: String,
        batch_size: usize,
        batch_interval_secs: u64,
    ) -> Self {
        Self {
            backend_url,
            probe_node_name,
            probe_node_region,
            batch_size,
            batch_interval: Duration::from_secs(batch_interval_secs),
            pending_logs: Arc::new(Mutex::new(Vec::new())),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client for logger"),
        }
    }

    /// Start background task that periodically flushes logs
    pub fn start_background_flush(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut tick = interval(self.batch_interval);
            loop {
                tick.tick().await;
                if let Err(e) = self.flush_logs().await {
                    error!("Background log flush failed: {}", e);
                }
            }
        });
    }

    /// Add a log entry to the batch
    pub async fn log_request(
        &self,
        token_id: String,
        user_id: i32,
        method: String,
        target_url: String,
        status_code: Option<i32>,
        response_size: i64,
        duration_ms: Option<i64>,
        success: bool,
        rate_limited: bool,
        error_message: Option<String>,
    ) {
        let entry = LogEntry {
            token_id,
            user_id,
            timestamp: Utc::now().to_rfc3339(),
            method,
            target_url,
            status_code,
            response_size,
            duration_ms,
            success,
            rate_limited,
            error_message,
        };

        let mut logs = self.pending_logs.lock().await;
        logs.push(entry);

        // Flush if batch is full
        if logs.len() >= self.batch_size {
            let batch = logs.drain(..).collect::<Vec<_>>();
            drop(logs); // Release lock before making HTTP request

            debug!("Batch full ({} logs), flushing to backend", batch.len());
            if let Err(e) = self.submit_batch(batch).await {
                error!("Failed to flush full batch: {}", e);
            }
        }
    }

    /// Flush pending logs to backend (called by background task or when batch is full)
    async fn flush_logs(&self) -> Result<()> {
        let mut logs = self.pending_logs.lock().await;

        if logs.is_empty() {
            return Ok(());
        }

        let batch = logs.drain(..).collect::<Vec<_>>();
        drop(logs); // Release lock before making HTTP request

        debug!("Periodic flush: {} pending logs", batch.len());
        self.submit_batch(batch).await
    }

    /// Submit a batch of logs to the backend API
    async fn submit_batch(&self, logs: Vec<LogEntry>) -> Result<()> {
        if logs.is_empty() {
            return Ok(());
        }

        let endpoint = format!("{}/api/forward-proxy/logs/batch", self.backend_url);
        let log_count = logs.len();

        let request_body = BatchLogSubmitRequest {
            logs,
            probe_node_name: self.probe_node_name.clone(),
            region: self.probe_node_region.clone(),
        };

        debug!(
            "Submitting {} logs to {} (probe={}, region={})",
            log_count, endpoint, self.probe_node_name, self.probe_node_region
        );

        match self
            .http_client
            .post(&endpoint)
            .json(&request_body)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();

                if status.is_success() {
                    match response.json::<BatchLogSubmitResponse>().await {
                        Ok(result) => {
                            info!(
                                "✓ Submitted {} logs - backend accepted {}, failed {}",
                                log_count, result.submitted, result.failed
                            );

                            if result.failed > 0 {
                                if let Some(errors) = result.errors {
                                    warn!(
                                        "Backend reported {} errors: {:?}",
                                        result.failed, errors
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Log submission succeeded but failed to parse response: {}",
                                e
                            );
                        }
                    }
                } else {
                    let error_body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "(could not read error body)".to_string());
                    error!(
                        "Backend rejected log batch: HTTP {} - {}",
                        status, error_body
                    );
                }
            }
            Err(e) => {
                error!("Failed to send logs to backend: {}", e);
                // Don't fail the proxy request - logging is best-effort
            }
        }

        Ok(())
    }
}

pub type SharedRequestLogger = Arc<RequestLogger>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_serialization() {
        let entry = LogEntry {
            token_id: "test_token_123".to_string(),
            user_id: 42,
            timestamp: "2025-11-21T10:00:00Z".to_string(),
            method: "CONNECT".to_string(),
            target_url: "example.com:443".to_string(),
            status_code: Some(200),
            response_size: 1024,
            duration_ms: Some(150),
            success: true,
            rate_limited: false,
            error_message: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("test_token_123"));
        assert!(json.contains("\"user_id\":42"));
        assert!(json.contains("\"success\":true"));
    }

    #[test]
    fn test_batch_request_serialization() {
        let entry = LogEntry {
            token_id: "test_token".to_string(),
            user_id: 1,
            timestamp: Utc::now().to_rfc3339(),
            method: "CONNECT".to_string(),
            target_url: "example.com:443".to_string(),
            status_code: Some(200),
            response_size: 512,
            duration_ms: Some(100),
            success: true,
            rate_limited: false,
            error_message: None,
        };

        let batch_request = BatchLogSubmitRequest {
            logs: vec![entry],
            probe_node_name: "probe-node-2".to_string(),
            region: "us-east".to_string(),
        };

        let json = serde_json::to_string(&batch_request).unwrap();
        assert!(json.contains("probe-node-2"));
        assert!(json.contains("us-east"));
        assert!(json.contains("\"logs\":"));
    }
}
