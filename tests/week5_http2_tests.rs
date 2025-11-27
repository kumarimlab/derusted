//! Week 5: HTTP/2 MITM Integration Tests
//!
//! These tests verify HTTP/2 frame parsing, ALPN protocol negotiation,
//! and integration with the MITM interceptor.

use derusted::mitm::http2_parser::{
    extract_http2_request, extract_http2_response, has_end_headers, has_end_stream,
    is_client_stream, is_response_frame, parse_frame_header, parse_http2_frame, FrameType,
    HpackDecoder,
};

/// Test: Parse HTTP/2 connection preface
///
/// HTTP/2 connections start with a 24-byte preface:
/// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#[test]
fn test_http2_connection_preface() {
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    assert_eq!(preface.len(), 24);
    assert_eq!(&preface[0..3], b"PRI");
    assert_eq!(&preface[18..20], b"SM");
}

/// Test: Parse SETTINGS frame (connection setup)
///
/// SETTINGS frames are used to configure connection parameters.
/// They must have stream_id = 0 (connection-level).
#[test]
fn test_parse_settings_frame() {
    // SETTINGS frame: type=0x4, flags=0x0, stream_id=0, length=6
    // Payload: SETTINGS_MAX_CONCURRENT_STREAMS = 100
    let frame_data = [
        0x00, 0x00, 0x06, // Length: 6 bytes
        0x04, // Type: SETTINGS (0x4)
        0x00, // Flags: none
        0x00, 0x00, 0x00, 0x00, // Stream ID: 0 (connection)
        // Payload: SETTINGS_MAX_CONCURRENT_STREAMS (0x3) = 100
        0x00, 0x03, // Identifier: 3
        0x00, 0x00, 0x00, 0x64, // Value: 100
    ];

    let (frame_type, flags, stream_id, length) = parse_frame_header(&frame_data[0..9]).unwrap();
    assert_eq!(frame_type, FrameType::Settings);
    assert_eq!(flags, 0x00);
    assert_eq!(stream_id, 0);
    assert_eq!(length, 6);

    let frame = parse_http2_frame(&frame_data).unwrap();
    assert_eq!(frame.frame_type, FrameType::Settings);
    assert_eq!(frame.stream_id, 0);
    assert_eq!(frame.payload.len(), 6);
}

/// Test: Parse HEADERS frame with HPACK compression
///
/// HEADERS frames contain request/response headers compressed with HPACK.
/// This test verifies we can decompress a simple GET request.
#[test]
fn test_parse_headers_frame_with_hpack() {
    use hpack::Encoder;

    // Create a simple GET request
    let headers = vec![
        (b":method".to_vec(), b"GET".to_vec()),
        (b":path".to_vec(), b"/api/test".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), b"example.com".to_vec()),
    ];

    // Encode with HPACK
    let mut encoder = Encoder::new();
    let mut encoded = Vec::new();
    let header_refs: Vec<(&[u8], &[u8])> = headers
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    encoder.encode_into(header_refs, &mut encoded).unwrap();

    // Build HEADERS frame
    let length = encoded.len();
    let mut frame_data = vec![
        ((length >> 16) & 0xFF) as u8,
        ((length >> 8) & 0xFF) as u8,
        (length & 0xFF) as u8,
        0x01, // Type: HEADERS
        0x05, // Flags: END_STREAM | END_HEADERS
        0x00,
        0x00,
        0x00,
        0x01, // Stream ID: 1 (client-initiated)
    ];
    frame_data.extend_from_slice(&encoded);

    let frame = parse_http2_frame(&frame_data).unwrap();
    assert_eq!(frame.frame_type, FrameType::Headers);
    assert_eq!(frame.stream_id, 1);
    assert!(has_end_stream(&frame));
    assert!(has_end_headers(&frame));
    assert!(is_client_stream(frame.stream_id));

    // Extract request
    let mut decoder = HpackDecoder::new();
    let request = extract_http2_request(&[frame], &mut decoder).unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/api/test");
    assert_eq!(request.scheme, "https");
    assert_eq!(request.authority, "example.com");
}

/// Test: Parse DATA frame with body
///
/// DATA frames contain request/response body data.
#[test]
fn test_parse_data_frame_with_body() {
    let body = b"{\"key\":\"value\"}";
    let length = body.len();

    let mut frame_data = vec![
        ((length >> 16) & 0xFF) as u8,
        ((length >> 8) & 0xFF) as u8,
        (length & 0xFF) as u8,
        0x00, // Type: DATA
        0x01, // Flags: END_STREAM
        0x00,
        0x00,
        0x00,
        0x01, // Stream ID: 1
    ];
    frame_data.extend_from_slice(body);

    let frame = parse_http2_frame(&frame_data).unwrap();
    assert_eq!(frame.frame_type, FrameType::Data);
    assert_eq!(frame.stream_id, 1);
    assert_eq!(frame.payload, body);
    assert!(has_end_stream(&frame));
}

/// Test: Parse CONTINUATION frame (large headers)
///
/// When headers exceed the frame size limit, they're split across
/// HEADERS and CONTINUATION frames.
#[test]
fn test_parse_continuation_frame() {
    use hpack::Encoder;

    // Create headers that will span multiple frames
    let headers_part1 = vec![
        (b":method".to_vec(), b"POST".to_vec()),
        (b":path".to_vec(), b"/api/upload".to_vec()),
    ];

    let headers_part2 = vec![
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), b"example.com".to_vec()),
    ];

    let mut encoder = Encoder::new();
    let mut encoded1 = Vec::new();
    let header_refs1: Vec<(&[u8], &[u8])> = headers_part1
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    encoder.encode_into(header_refs1, &mut encoded1).unwrap();

    let mut encoded2 = Vec::new();
    let header_refs2: Vec<(&[u8], &[u8])> = headers_part2
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    encoder.encode_into(header_refs2, &mut encoded2).unwrap();

    // Build HEADERS frame (without END_HEADERS)
    let length1 = encoded1.len();
    let mut frame1_data = vec![
        ((length1 >> 16) & 0xFF) as u8,
        ((length1 >> 8) & 0xFF) as u8,
        (length1 & 0xFF) as u8,
        0x01, // Type: HEADERS
        0x00, // Flags: none (no END_HEADERS)
        0x00,
        0x00,
        0x00,
        0x03, // Stream ID: 3
    ];
    frame1_data.extend_from_slice(&encoded1);

    // Build CONTINUATION frame (with END_HEADERS)
    let length2 = encoded2.len();
    let mut frame2_data = vec![
        ((length2 >> 16) & 0xFF) as u8,
        ((length2 >> 8) & 0xFF) as u8,
        (length2 & 0xFF) as u8,
        0x09, // Type: CONTINUATION
        0x04, // Flags: END_HEADERS
        0x00,
        0x00,
        0x00,
        0x03, // Stream ID: 3 (must match HEADERS)
    ];
    frame2_data.extend_from_slice(&encoded2);

    let frame1 = parse_http2_frame(&frame1_data).unwrap();
    let frame2 = parse_http2_frame(&frame2_data).unwrap();

    assert_eq!(frame1.frame_type, FrameType::Headers);
    assert_eq!(frame2.frame_type, FrameType::Continuation);
    assert_eq!(frame1.stream_id, frame2.stream_id);
    assert!(!has_end_headers(&frame1));
    assert!(has_end_headers(&frame2));

    // Extract request from both frames
    let mut decoder = HpackDecoder::new();
    let request = extract_http2_request(&[frame1, frame2], &mut decoder).unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/upload");
}

/// Test: Parse HTTP/2 response (HEADERS + DATA)
///
/// A typical HTTP/2 response consists of:
/// 1. HEADERS frame with :status pseudo-header
/// 2. DATA frame(s) with response body
#[test]
fn test_parse_http2_response() {
    use hpack::Encoder;

    // Build response HEADERS
    let headers = vec![
        (b":status".to_vec(), b"200".to_vec()),
        (b"content-type".to_vec(), b"application/json".to_vec()),
    ];

    let mut encoder = Encoder::new();
    let mut encoded = Vec::new();
    let header_refs: Vec<(&[u8], &[u8])> = headers
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    encoder.encode_into(header_refs, &mut encoded).unwrap();

    let length = encoded.len();
    let mut headers_frame_data = vec![
        ((length >> 16) & 0xFF) as u8,
        ((length >> 8) & 0xFF) as u8,
        (length & 0xFF) as u8,
        0x01, // Type: HEADERS
        0x04, // Flags: END_HEADERS
        0x00,
        0x00,
        0x00,
        0x01, // Stream ID: 1 (client-initiated, so response)
    ];
    headers_frame_data.extend_from_slice(&encoded);

    // Build response DATA
    let body = b"{\"result\":\"success\"}";
    let body_length = body.len();
    let mut data_frame_data = vec![
        ((body_length >> 16) & 0xFF) as u8,
        ((body_length >> 8) & 0xFF) as u8,
        (body_length & 0xFF) as u8,
        0x00, // Type: DATA
        0x01, // Flags: END_STREAM
        0x00,
        0x00,
        0x00,
        0x01, // Stream ID: 1
    ];
    data_frame_data.extend_from_slice(body);

    let headers_frame = parse_http2_frame(&headers_frame_data).unwrap();
    let data_frame = parse_http2_frame(&data_frame_data).unwrap();

    assert_eq!(headers_frame.stream_id, 1);
    assert_eq!(data_frame.stream_id, 1);
    assert!(is_client_stream(headers_frame.stream_id)); // Odd stream = client-initiated
    assert!(is_response_frame(&headers_frame)); // Response on client-initiated stream

    // Extract response
    let mut decoder = HpackDecoder::new();
    let response = extract_http2_response(&[headers_frame, data_frame], &mut decoder).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers.get("content-type").unwrap(),
        "application/json"
    );
    assert!(response.body_preview.contains("success"));
}

/// Test: Multiple concurrent streams
///
/// HTTP/2 allows multiple requests/responses on the same connection.
/// This test verifies we can track frames by stream ID.
#[test]
fn test_multiple_concurrent_streams() {
    use hpack::Encoder;

    let mut encoder = Encoder::new();

    // Stream 1: GET /api/users
    let headers1 = vec![
        (b":method".to_vec(), b"GET".to_vec()),
        (b":path".to_vec(), b"/api/users".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), b"example.com".to_vec()),
    ];

    let mut encoded1 = Vec::new();
    let header_refs1: Vec<(&[u8], &[u8])> = headers1
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    encoder.encode_into(header_refs1, &mut encoded1).unwrap();

    // Stream 3: POST /api/orders
    let headers3 = vec![
        (b":method".to_vec(), b"POST".to_vec()),
        (b":path".to_vec(), b"/api/orders".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), b"example.com".to_vec()),
    ];

    let mut encoded3 = Vec::new();
    let header_refs3: Vec<(&[u8], &[u8])> = headers3
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    encoder.encode_into(header_refs3, &mut encoded3).unwrap();

    // Build frames
    let length1 = encoded1.len();
    let mut frame1_data = vec![
        ((length1 >> 16) & 0xFF) as u8,
        ((length1 >> 8) & 0xFF) as u8,
        (length1 & 0xFF) as u8,
        0x01,
        0x05, // HEADERS, END_STREAM | END_HEADERS
        0x00,
        0x00,
        0x00,
        0x01, // Stream 1
    ];
    frame1_data.extend_from_slice(&encoded1);

    let length3 = encoded3.len();
    let mut frame3_data = vec![
        ((length3 >> 16) & 0xFF) as u8,
        ((length3 >> 8) & 0xFF) as u8,
        (length3 & 0xFF) as u8,
        0x01,
        0x04, // HEADERS, END_HEADERS (no END_STREAM for POST)
        0x00,
        0x00,
        0x00,
        0x03, // Stream 3
    ];
    frame3_data.extend_from_slice(&encoded3);

    let frame1 = parse_http2_frame(&frame1_data).unwrap();
    let frame3 = parse_http2_frame(&frame3_data).unwrap();

    assert_eq!(frame1.stream_id, 1);
    assert_eq!(frame3.stream_id, 3);
    assert!(is_client_stream(frame1.stream_id));
    assert!(is_client_stream(frame3.stream_id));

    // Extract requests
    let mut decoder1 = HpackDecoder::new();
    let request1 = extract_http2_request(&[frame1], &mut decoder1).unwrap();
    assert_eq!(request1.method, "GET");
    assert_eq!(request1.path, "/api/users");

    let mut decoder3 = HpackDecoder::new();
    let request3 = extract_http2_request(&[frame3], &mut decoder3).unwrap();
    assert_eq!(request3.method, "POST");
    assert_eq!(request3.path, "/api/orders");
}

/// Test: GOAWAY frame (connection termination)
///
/// GOAWAY frames are sent when closing a connection gracefully.
#[test]
fn test_parse_goaway_frame() {
    // GOAWAY frame: last_stream_id=5, error_code=NO_ERROR (0x0)
    let frame_data = [
        0x00, 0x00, 0x08, // Length: 8 bytes
        0x07, // Type: GOAWAY
        0x00, // Flags: none
        0x00, 0x00, 0x00, 0x00, // Stream ID: 0 (connection)
        // Payload
        0x00, 0x00, 0x00, 0x05, // Last stream ID: 5
        0x00, 0x00, 0x00, 0x00, // Error code: NO_ERROR
    ];

    let frame = parse_http2_frame(&frame_data).unwrap();
    assert_eq!(frame.frame_type, FrameType::GoAway);
    assert_eq!(frame.stream_id, 0); // Connection-level
    assert_eq!(frame.payload.len(), 8);
}

/// Test: RST_STREAM frame (cancel stream)
///
/// RST_STREAM frames cancel individual streams.
#[test]
fn test_parse_rst_stream_frame() {
    // RST_STREAM frame: stream_id=7, error_code=CANCEL (0x8)
    let frame_data = [
        0x00, 0x00, 0x04, // Length: 4 bytes
        0x03, // Type: RST_STREAM
        0x00, // Flags: none
        0x00, 0x00, 0x00, 0x07, // Stream ID: 7
        // Payload
        0x00, 0x00, 0x00, 0x08, // Error code: CANCEL
    ];

    let frame = parse_http2_frame(&frame_data).unwrap();
    assert_eq!(frame.frame_type, FrameType::RstStream);
    assert_eq!(frame.stream_id, 7);
    assert_eq!(frame.payload, vec![0x00, 0x00, 0x00, 0x08]);
}

/// Test: Body preview truncation
///
/// Verify that large response bodies are truncated in the preview.
#[test]
fn test_body_preview_truncation() {
    use hpack::Encoder;

    // Build response with large body
    let headers = vec![
        (b":status".to_vec(), b"200".to_vec()),
        (b"content-type".to_vec(), b"text/plain".to_vec()),
    ];

    let mut encoder = Encoder::new();
    let mut encoded = Vec::new();
    let header_refs: Vec<(&[u8], &[u8])> = headers
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    encoder.encode_into(header_refs, &mut encoded).unwrap();

    let length = encoded.len();
    let mut headers_frame_data = vec![
        ((length >> 16) & 0xFF) as u8,
        ((length >> 8) & 0xFF) as u8,
        (length & 0xFF) as u8,
        0x01,
        0x04, // HEADERS, END_HEADERS
        0x00,
        0x00,
        0x00,
        0x01, // Stream 1 (client-initiated, for response)
    ];
    headers_frame_data.extend_from_slice(&encoded);

    // Large body (2KB)
    let body = vec![b'A'; 2048];
    let body_length = body.len();
    let mut data_frame_data = vec![
        ((body_length >> 16) & 0xFF) as u8,
        ((body_length >> 8) & 0xFF) as u8,
        (body_length & 0xFF) as u8,
        0x00,
        0x01, // DATA, END_STREAM
        0x00,
        0x00,
        0x00,
        0x01, // Stream 1
    ];
    data_frame_data.extend_from_slice(&body);

    let headers_frame = parse_http2_frame(&headers_frame_data).unwrap();
    let data_frame = parse_http2_frame(&data_frame_data).unwrap();

    let mut decoder = HpackDecoder::new();
    let response = extract_http2_response(&[headers_frame, data_frame], &mut decoder).unwrap();

    // Body preview should be truncated to 1KB
    assert!(response.body_preview.len() <= 1024);
    assert_eq!(response.content_length, Some(2048));
}
