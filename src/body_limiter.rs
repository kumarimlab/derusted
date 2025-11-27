// Body Size Limiter - Streaming body reader with size enforcement
// Phase 4: Prevent memory exhaustion from large request bodies

use bytes::{Bytes, BytesMut};
use http::StatusCode;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error)]
pub enum BodyLimitError {
    #[error("Request body too large: {current} bytes exceeds limit of {limit} bytes")]
    TooLarge { current: usize, limit: usize },

    #[error("Failed to read request body: {0}")]
    ReadError(String),
}

/// Stream request body with size limit enforcement
/// Returns 413 as soon as the limit is exceeded (no full buffering)
pub async fn read_body_with_limit(
    mut body: Incoming,
    max_size: usize,
) -> Result<Bytes, BodyLimitError> {
    let mut collected = BytesMut::new();
    let mut total_size = 0;

    // Stream body frame by frame
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| BodyLimitError::ReadError(e.to_string()))?;

        // Check if this is a data frame
        if let Ok(data) = frame.into_data() {
            total_size += data.len();

            // Check size limit BEFORE adding to buffer
            if total_size > max_size {
                warn!(
                    "[Body Limiter] Request body exceeded limit: {} bytes (limit: {})",
                    total_size, max_size
                );
                return Err(BodyLimitError::TooLarge {
                    current: total_size,
                    limit: max_size,
                });
            }

            collected.extend_from_slice(&data);
        }
    }

    Ok(collected.freeze())
}

/// Helper to convert BodyLimitError to HTTP response status
impl BodyLimitError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            BodyLimitError::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            BodyLimitError::ReadError(_) => StatusCode::BAD_REQUEST,
        }
    }

    pub fn to_response_message(&self) -> String {
        match self {
            BodyLimitError::TooLarge { current, limit } => {
                format!(
                    "Request body too large: {} bytes (limit: {})",
                    current, limit
                )
            }
            BodyLimitError::ReadError(_) => "Failed to read request body".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    
    use bytes::Bytes;
    use http_body_util::Full;

    #[tokio::test]
    async fn test_body_under_limit() {
        let body_data = Bytes::from("Hello, World!");
        let body = Full::new(body_data.clone());

        // Convert Full<Bytes> to Incoming would require more complex setup
        // This is a simplified test structure
    }

    #[tokio::test]
    async fn test_body_over_limit() {
        // Test that oversized bodies are rejected before full read
        // Would need Incoming body mock
    }
}
