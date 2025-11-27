//! Week 4 Performance Benchmarks
//!
//! Benchmarks for HTTP parsing, PII redaction, and SQLite logging overhead

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use derusted::mitm::{
    http_parser::{parse_http1_request, parse_http1_response},
    log_storage::LogStorage,
    logging::{PiiRedactor, RequestMetadata},
};
use tempfile::TempDir;

/// Helper to create test metadata
fn create_test_metadata() -> RequestMetadata {
    RequestMetadata {
        timestamp: chrono::Utc::now().timestamp(),
        method: "GET".to_string(),
        host: "example.com".to_string(),
        port: 443,
        path: "/api/test".to_string(),
        http_version: "HTTP/1.1".to_string(),
        status_code: Some(200),
        request_size: 1024,
        response_size: 2048,
        duration_ms: 150,
        tls_version: Some("TLS 1.3".to_string()),
        mitm_applied: true,
        bypass_reason: None,
    }
}

/// Benchmark HTTP request parsing
fn bench_http_request_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_request_parsing");

    // Small request (1KB)
    let small_request = b"GET /api/users?id=123 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/json\r\nAuthorization: Bearer token123\r\n\r\n";

    group.bench_function("small_request_1kb", |b| {
        b.iter(|| parse_http1_request(black_box(small_request)).unwrap())
    });

    // Medium request with body (4KB)
    let body_content = "x".repeat(3900);
    let medium_request = format!(
        "POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body_content.len(),
        body_content
    );

    group.bench_function("medium_request_4kb", |b| {
        b.iter(|| parse_http1_request(black_box(medium_request.as_bytes())).unwrap())
    });

    // Large request (8KB - typical buffer size)
    let large_body = "y".repeat(7900);
    let large_request = format!(
        "POST /api/upload HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n{}",
        large_body.len(),
        large_body
    );

    group.bench_function("large_request_8kb", |b| {
        b.iter(|| parse_http1_request(black_box(large_request.as_bytes())).unwrap())
    });

    group.finish();
}

/// Benchmark HTTP response parsing
fn bench_http_response_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_response_parsing");

    // Small response (1KB)
    let small_response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n{\"status\":\"success\",\"data\":{\"id\":123,\"name\":\"test\"}}";

    group.bench_function("small_response_1kb", |b| {
        b.iter(|| parse_http1_response(black_box(small_response)).unwrap())
    });

    // Medium response (4KB)
    let response_body = r#"{"data":["#.to_string() + &"x".repeat(3900) + "]}";
    let medium_response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        response_body.len(),
        response_body
    );

    group.bench_function("medium_response_4kb", |b| {
        b.iter(|| parse_http1_response(black_box(medium_response.as_bytes())).unwrap())
    });

    // Binary response (image-like)
    let mut binary_response =
        b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 1000\r\n\r\n".to_vec();
    binary_response.extend_from_slice(&vec![0xFF; 1000]);

    group.bench_function("binary_response_1kb", |b| {
        b.iter(|| parse_http1_response(black_box(&binary_response)).unwrap())
    });

    group.finish();
}

/// Benchmark PII redaction
fn bench_pii_redaction(c: &mut Criterion) {
    let mut group = c.benchmark_group("pii_redaction");

    // Path without PII (common case)
    let clean_path = "/api/users/123/profile?page=1&sort=name";

    group.bench_function("no_pii", |b| {
        b.iter(|| PiiRedactor::redact(black_box(clean_path)))
    });

    // Path with single PII (credit card)
    let path_with_cc = "/payment?card=4532-1234-5678-9010&amount=100";

    group.bench_function("single_pii_credit_card", |b| {
        b.iter(|| PiiRedactor::redact(black_box(path_with_cc)))
    });

    // Path with multiple PII
    let path_multi_pii =
        "/checkout?card=4532-1234-5678-9010&email=user@test.com&phone=555-123-4567&ssn=123-45-6789";

    group.bench_function("multiple_pii", |b| {
        b.iter(|| PiiRedactor::redact(black_box(path_multi_pii)))
    });

    // Long path with PII
    let long_path = format!(
        "/api/transaction?id=123&card=4532-1234-5678-9010&email=user@example.com&{}",
        "a=b&".repeat(100)
    );

    group.bench_function("long_path_with_pii", |b| {
        b.iter(|| PiiRedactor::redact(black_box(&long_path)))
    });

    group.finish();
}

/// Benchmark sampling decision
fn bench_sampling(c: &mut Criterion) {
    let mut group = c.benchmark_group("sampling");

    group.bench_function("should_sample_check", |b| {
        b.iter(|| {
            PiiRedactor::should_sample(black_box(0.01)) // 1% sampling
        })
    });

    group.finish();
}

/// Benchmark SQLite logging
fn bench_sqlite_logging(c: &mut Criterion) {
    let mut group = c.benchmark_group("sqlite_logging");

    // Create runtime for async operations
    let rt = tokio::runtime::Runtime::new().unwrap();

    // In-memory database for benchmarking
    let storage = rt.block_on(async { LogStorage::new(":memory:").await.unwrap() });

    let metadata = create_test_metadata();

    group.bench_function("log_request_memory_db", |b| {
        b.to_async(&rt)
            .iter(|| async { storage.log_request(black_box(&metadata)).await.unwrap() })
    });

    // Disk-based database
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("bench.db");
    let disk_storage =
        rt.block_on(async { LogStorage::new(db_path.to_str().unwrap()).await.unwrap() });

    group.bench_function("log_request_disk_db", |b| {
        b.to_async(&rt).iter(|| async {
            disk_storage
                .log_request(black_box(&metadata))
                .await
                .unwrap()
        })
    });

    group.finish();
}

/// Benchmark log queries
fn bench_sqlite_queries(c: &mut Criterion) {
    let mut group = c.benchmark_group("sqlite_queries");

    let rt = tokio::runtime::Runtime::new().unwrap();

    // Create database with test data
    let storage = rt.block_on(async {
        let storage = LogStorage::new(":memory:").await.unwrap();

        // Insert 1000 test logs
        for i in 0..1000 {
            let metadata = RequestMetadata {
                timestamp: chrono::Utc::now().timestamp() - (i * 60),
                method: "GET".to_string(),
                host: format!("host{}.example.com", i % 10),
                port: 443,
                path: format!("/api/endpoint{}", i),
                http_version: "HTTP/1.1".to_string(),
                status_code: Some(200),
                request_size: 1024,
                response_size: 2048,
                duration_ms: 150,
                tls_version: Some("TLS 1.3".to_string()),
                mitm_applied: true,
                bypass_reason: None,
            };
            storage.log_request(&metadata).await.unwrap();
        }

        storage
    });

    group.bench_function("query_logs_by_time", |b| {
        b.to_async(&rt).iter(|| async {
            let start_ts = chrono::Utc::now().timestamp() - 3600;
            let end_ts = chrono::Utc::now().timestamp();
            storage
                .query_logs(black_box(start_ts), black_box(end_ts), black_box(100))
                .await
                .unwrap()
        })
    });

    group.bench_function("query_logs_by_host", |b| {
        b.to_async(&rt).iter(|| async {
            storage
                .query_logs_by_host(black_box("host5.example.com"), black_box(100))
                .await
                .unwrap()
        })
    });

    group.bench_function("count_logs", |b| {
        b.to_async(&rt)
            .iter(|| async { storage.count_logs().await.unwrap() })
    });

    group.finish();
}

/// Benchmark end-to-end parsing + redaction + metadata creation
fn bench_end_to_end_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end");

    let request_data =
        b"GET /payment?card=4532-1234-5678-9010 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let response_data =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}";

    group.bench_function("parse_request_response_redact", |b| {
        b.iter(|| {
            // Parse request
            let req = parse_http1_request(black_box(request_data)).unwrap();

            // Parse response
            let resp = parse_http1_response(black_box(response_data)).unwrap();

            // Create metadata
            let mut metadata = RequestMetadata {
                timestamp: chrono::Utc::now().timestamp(),
                method: req.method.clone(),
                host: "example.com".to_string(),
                port: 443,
                path: req.path.clone(),
                http_version: req.version.clone(),
                status_code: Some(resp.status_code),
                request_size: request_data.len(),
                response_size: response_data.len(),
                duration_ms: 100,
                tls_version: Some("TLS 1.3".to_string()),
                mitm_applied: true,
                bypass_reason: None,
            };

            // Apply PII redaction
            metadata.path = PiiRedactor::redact(&metadata.path);

            black_box(metadata)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_http_request_parsing,
    bench_http_response_parsing,
    bench_pii_redaction,
    bench_sampling,
    bench_sqlite_logging,
    bench_sqlite_queries,
    bench_end_to_end_overhead
);

criterion_main!(benches);
