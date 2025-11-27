//! HTTP/2 Frame Parser for MITM Inspection
//!
//! This module provides lightweight HTTP/2 frame parsing for logging and inspection
//! purposes. It does NOT implement the full HTTP/2 protocol stack - instead, it
//! passively observes frames as they flow through the proxy.
//!
//! Key Features:
//! - Parse HTTP/2 frame headers (9 bytes)
//! - Extract HEADERS frames and decompress with HPACK
//! - Extract DATA frames for body preview
//! - Handle CONTINUATION frames for large headers
//! - Track stream lifecycle (START → END_STREAM)

pub use hpack::Decoder as HpackDecoder;
use std::collections::HashMap;
use thiserror::Error;
use tracing::debug;

/// HTTP/2 frame types (RFC 9113 Section 6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
}

impl FrameType {
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x0 => Some(FrameType::Data),
            0x1 => Some(FrameType::Headers),
            0x2 => Some(FrameType::Priority),
            0x3 => Some(FrameType::RstStream),
            0x4 => Some(FrameType::Settings),
            0x5 => Some(FrameType::PushPromise),
            0x6 => Some(FrameType::Ping),
            0x7 => Some(FrameType::GoAway),
            0x8 => Some(FrameType::WindowUpdate),
            0x9 => Some(FrameType::Continuation),
            _ => None,
        }
    }
}

/// HTTP/2 frame flags (RFC 9113 Section 6)
pub mod flags {
    pub const END_STREAM: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

/// Parsed HTTP/2 frame
#[derive(Debug, Clone)]
pub struct Http2Frame {
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: u32,
    pub payload_length: usize,
    pub payload: Vec<u8>,
}

/// HTTP/2 request metadata (extracted from HEADERS + DATA frames)
#[derive(Debug, Clone)]
pub struct Http2Request {
    pub method: String,    // :method pseudo-header
    pub path: String,      // :path pseudo-header
    pub authority: String, // :authority pseudo-header (optional)
    pub scheme: String,    // :scheme pseudo-header
    pub headers: HashMap<String, String>,
    pub body_preview: String,
    pub content_length: Option<usize>,
}

/// HTTP/2 response metadata
#[derive(Debug, Clone)]
pub struct Http2Response {
    pub status: u16, // :status pseudo-header
    pub headers: HashMap<String, String>,
    pub body_preview: String,
    pub content_length: Option<usize>,
}

/// Parse errors
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Incomplete frame (need {0} more bytes)")]
    Incomplete(usize),

    #[error("Invalid frame type: {0}")]
    InvalidFrameType(u8),

    #[error("Invalid stream ID: {0}")]
    InvalidStreamId(u32),

    #[error("HPACK decompression failed: {0}")]
    HpackError(String),

    #[error("Missing pseudo-header: {0}")]
    MissingPseudoHeader(String),

    #[error("Invalid UTF-8 in header")]
    InvalidUtf8,
}

/// Parse HTTP/2 frame header (first 9 bytes)
///
/// Frame Format (RFC 9113 Section 4.1):
/// ```text
/// +-----------------------------------------------+
/// |                 Length (24)                   |
/// +---------------+---------------+---------------+
/// |   Type (8)    |   Flags (8)   |
/// +-+-------------+---------------+-------------------------------+
/// |R|                 Stream Identifier (31)                      |
/// +=+=============================================================+
/// |                   Frame Payload (0...)                      ...
/// +---------------------------------------------------------------+
/// ```
pub fn parse_frame_header(data: &[u8]) -> Result<(FrameType, u8, u32, usize), ParseError> {
    if data.len() < 9 {
        return Err(ParseError::Incomplete(9 - data.len()));
    }

    // Length (24 bits, big-endian)
    let length = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);

    // Type (8 bits)
    let frame_type = FrameType::from_u8(data[3]).ok_or(ParseError::InvalidFrameType(data[3]))?;

    // Flags (8 bits)
    let flags = data[4];

    // Stream ID (31 bits, big-endian, ignore reserved bit)
    let stream_id = ((data[5] as u32 & 0x7F) << 24)
        | ((data[6] as u32) << 16)
        | ((data[7] as u32) << 8)
        | (data[8] as u32);

    Ok((frame_type, flags, stream_id, length))
}

/// Parse complete HTTP/2 frame (header + payload)
pub fn parse_http2_frame(data: &[u8]) -> Result<Http2Frame, ParseError> {
    let (frame_type, flags, stream_id, payload_length) = parse_frame_header(data)?;

    if data.len() < 9 + payload_length {
        return Err(ParseError::Incomplete((9 + payload_length) - data.len()));
    }

    let payload = data[9..9 + payload_length].to_vec();

    Ok(Http2Frame {
        frame_type,
        flags,
        stream_id,
        payload_length,
        payload,
    })
}

/// Extract HTTP/2 request from HEADERS frame(s)
///
/// HEADERS frames contain HPACK-compressed header block.
/// May span multiple CONTINUATION frames if END_HEADERS flag not set.
pub fn extract_http2_request(
    frames: &[Http2Frame],
    decoder: &mut HpackDecoder,
) -> Result<Http2Request, ParseError> {
    // Collect all HEADERS and CONTINUATION frames
    let mut header_block = Vec::new();
    for frame in frames {
        if matches!(
            frame.frame_type,
            FrameType::Headers | FrameType::Continuation
        ) {
            header_block.extend_from_slice(&frame.payload);
        }
    }

    // Decompress with HPACK
    let decompressed = decoder
        .decode(&header_block)
        .map_err(|e| ParseError::HpackError(format!("{:?}", e)))?;

    // Extract pseudo-headers and regular headers
    let mut method = None;
    let mut path = None;
    let mut authority = None;
    let mut scheme = None;
    let mut headers = HashMap::new();

    for (name, value) in decompressed {
        let name_str = String::from_utf8(name).map_err(|_| ParseError::InvalidUtf8)?;
        let value_str = String::from_utf8(value).map_err(|_| ParseError::InvalidUtf8)?;

        match name_str.as_str() {
            ":method" => method = Some(value_str),
            ":path" => path = Some(value_str),
            ":authority" => authority = Some(value_str),
            ":scheme" => scheme = Some(value_str),
            _ if !name_str.starts_with(':') => {
                headers.insert(name_str.to_lowercase(), value_str);
            }
            _ => {
                debug!(name = %name_str, "Unknown pseudo-header");
            }
        }
    }

    // Extract body preview from DATA frames
    let mut body_preview = String::new();
    let mut total_data_length = 0usize;

    for frame in frames {
        if frame.frame_type == FrameType::Data {
            total_data_length += frame.payload.len();

            // Preview first 1KB only
            if body_preview.len() < 1024 {
                let preview_bytes =
                    &frame.payload[..frame.payload.len().min(1024 - body_preview.len())];
                if let Ok(text) = String::from_utf8(preview_bytes.to_vec()) {
                    body_preview.push_str(&text);
                } else {
                    body_preview.push_str(&format!("[Binary data: {} bytes]", frame.payload.len()));
                    break;
                }
            }
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .or(if total_data_length > 0 {
            Some(total_data_length)
        } else {
            None
        });

    Ok(Http2Request {
        method: method.ok_or(ParseError::MissingPseudoHeader(":method".to_string()))?,
        path: path.ok_or(ParseError::MissingPseudoHeader(":path".to_string()))?,
        authority: authority.unwrap_or_default(),
        scheme: scheme.ok_or(ParseError::MissingPseudoHeader(":scheme".to_string()))?,
        headers,
        body_preview,
        content_length,
    })
}

/// Extract HTTP/2 response from HEADERS frame(s)
pub fn extract_http2_response(
    frames: &[Http2Frame],
    decoder: &mut HpackDecoder,
) -> Result<Http2Response, ParseError> {
    // Collect all HEADERS and CONTINUATION frames
    let mut header_block = Vec::new();
    for frame in frames {
        if matches!(
            frame.frame_type,
            FrameType::Headers | FrameType::Continuation
        ) {
            header_block.extend_from_slice(&frame.payload);
        }
    }

    // Decompress with HPACK
    let decompressed = decoder
        .decode(&header_block)
        .map_err(|e| ParseError::HpackError(format!("{:?}", e)))?;

    // Extract pseudo-headers and regular headers
    let mut status = None;
    let mut headers = HashMap::new();

    for (name, value) in decompressed {
        let name_str = String::from_utf8(name).map_err(|_| ParseError::InvalidUtf8)?;
        let value_str = String::from_utf8(value).map_err(|_| ParseError::InvalidUtf8)?;

        match name_str.as_str() {
            ":status" => status = Some(value_str.parse::<u16>().unwrap_or(0)),
            _ if !name_str.starts_with(':') => {
                headers.insert(name_str.to_lowercase(), value_str);
            }
            _ => {
                debug!(name = %name_str, "Unknown pseudo-header in response");
            }
        }
    }

    // Extract body preview from DATA frames
    let mut body_preview = String::new();
    let mut total_data_length = 0usize;

    for frame in frames {
        if frame.frame_type == FrameType::Data {
            total_data_length += frame.payload.len();

            // Preview first 1KB only
            if body_preview.len() < 1024 {
                let preview_bytes =
                    &frame.payload[..frame.payload.len().min(1024 - body_preview.len())];
                if let Ok(text) = String::from_utf8(preview_bytes.to_vec()) {
                    body_preview.push_str(&text);
                } else {
                    body_preview.push_str(&format!("[Binary data: {} bytes]", frame.payload.len()));
                    break;
                }
            }
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .or(if total_data_length > 0 {
            Some(total_data_length)
        } else {
            None
        });

    Ok(Http2Response {
        status: status.ok_or(ParseError::MissingPseudoHeader(":status".to_string()))?,
        headers,
        body_preview,
        content_length,
    })
}

/// Helper: Check if frame has END_STREAM flag
pub fn has_end_stream(frame: &Http2Frame) -> bool {
    frame.flags & flags::END_STREAM != 0
}

/// Helper: Check if frame has END_HEADERS flag
pub fn has_end_headers(frame: &Http2Frame) -> bool {
    frame.flags & flags::END_HEADERS != 0
}

/// Helper: Check if frame belongs to a request stream
/// (client-initiated streams have odd stream IDs)
pub fn is_client_stream(stream_id: u32) -> bool {
    stream_id % 2 == 1
}

/// Helper: Check if frame belongs to a response stream
/// (same as client stream - responses use same stream ID)
pub fn is_response_frame(frame: &Http2Frame) -> bool {
    // Response frames: HEADERS/CONTINUATION/DATA on client-initiated stream
    matches!(
        frame.frame_type,
        FrameType::Headers | FrameType::Data | FrameType::Continuation
    ) && is_client_stream(frame.stream_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test: Parse frame header from raw bytes
    #[test]
    fn test_parse_frame_header() {
        // HEADERS frame: length=100, type=0x1, flags=0x4 (END_HEADERS), stream=1
        let frame_data = [
            0x00, 0x00, 0x64, // Length = 100
            0x01, // Type = HEADERS
            0x04, // Flags = END_HEADERS
            0x00, 0x00, 0x00, 0x01, // Stream ID = 1
        ];

        let result = parse_frame_header(&frame_data);
        assert!(result.is_ok());

        let (frame_type, flags, stream_id, length) = result.unwrap();
        assert_eq!(frame_type, FrameType::Headers);
        assert_eq!(flags, 0x04);
        assert_eq!(stream_id, 1);
        assert_eq!(length, 100);
    }

    /// Test: Incomplete frame header (less than 9 bytes)
    #[test]
    fn test_incomplete_frame_header() {
        let incomplete = [0x00, 0x00, 0x64, 0x01, 0x04];

        let result = parse_frame_header(&incomplete);
        assert!(result.is_err());

        match result {
            Err(ParseError::Incomplete(n)) => assert_eq!(n, 4),
            _ => panic!("Expected Incomplete error"),
        }
    }

    /// Test: DATA frame parsing
    #[test]
    fn test_parse_data_frame() {
        let payload = b"Hello, World!";
        let mut frame_data = vec![
            0x00, 0x00, 0x0D, // Length = 13
            0x00, // Type = DATA
            0x01, // Flags = END_STREAM
            0x00, 0x00, 0x00, 0x01, // Stream ID = 1
        ];
        frame_data.extend_from_slice(payload);

        let result = parse_http2_frame(&frame_data);
        assert!(result.is_ok());

        let frame = result.unwrap();
        assert_eq!(frame.frame_type, FrameType::Data);
        assert_eq!(frame.flags, 0x01);
        assert_eq!(frame.stream_id, 1);
        assert_eq!(frame.payload, payload);
        assert!(has_end_stream(&frame));
    }

    /// Test: SETTINGS frame
    #[test]
    fn test_parse_settings_frame() {
        // SETTINGS frame with no payload
        let frame_data = [
            0x00, 0x00, 0x00, // Length = 0
            0x04, // Type = SETTINGS
            0x00, // Flags = none
            0x00, 0x00, 0x00, 0x00, // Stream ID = 0 (connection-level)
        ];

        let result = parse_http2_frame(&frame_data);
        assert!(result.is_ok());

        let frame = result.unwrap();
        assert_eq!(frame.frame_type, FrameType::Settings);
        assert_eq!(frame.stream_id, 0); // SETTINGS always on stream 0
    }

    /// Test: HPACK request decompression
    #[test]
    fn test_extract_http2_request_simple() {
        let mut decoder = HpackDecoder::new();

        // Manually construct HPACK-encoded headers for GET /api/test
        // Note: In real implementation, headers would be HPACK-encoded
        // For testing, we'll use the decoder API

        // Simple test: encode and decode headers
        let headers_to_encode = vec![
            (b":method".to_vec(), b"GET".to_vec()),
            (b":path".to_vec(), b"/api/test".to_vec()),
            (b":scheme".to_vec(), b"https".to_vec()),
            (b":authority".to_vec(), b"example.com".to_vec()),
            (b"content-type".to_vec(), b"application/json".to_vec()),
        ];

        // Encode with HPACK encoder
        let mut encoder = hpack::Encoder::new();
        let encoded = encoder.encode(headers_to_encode.iter().map(|(n, v)| (&n[..], &v[..])));

        // Create HEADERS frame with encoded payload
        let mut frame_data = vec![
            0x00, 0x00, 0x00, // Length (placeholder)
            0x01, // Type = HEADERS
            0x05, // Flags = END_STREAM | END_HEADERS
            0x00, 0x00, 0x00, 0x01, // Stream ID = 1
        ];

        // Update length
        let payload_len = encoded.len();
        frame_data[0] = ((payload_len >> 16) & 0xFF) as u8;
        frame_data[1] = ((payload_len >> 8) & 0xFF) as u8;
        frame_data[2] = (payload_len & 0xFF) as u8;

        frame_data.extend_from_slice(&encoded);

        let frame = parse_http2_frame(&frame_data).unwrap();

        let request = extract_http2_request(&[frame], &mut decoder).unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/api/test");
        assert_eq!(request.scheme, "https");
        assert_eq!(request.authority, "example.com");
        assert_eq!(
            request.headers.get("content-type").unwrap(),
            "application/json"
        );
    }

    /// Test: Stream ID detection (client vs server)
    #[test]
    fn test_stream_id_detection() {
        assert!(is_client_stream(1)); // Odd = client-initiated
        assert!(is_client_stream(3));
        assert!(is_client_stream(5));
        assert!(!is_client_stream(2)); // Even = server-initiated (PUSH_PROMISE)
        assert!(!is_client_stream(4));
    }

    /// Test: Frame flags
    #[test]
    fn test_frame_flags() {
        let frame_end_stream = Http2Frame {
            frame_type: FrameType::Data,
            flags: flags::END_STREAM,
            stream_id: 1,
            payload_length: 0,
            payload: vec![],
        };

        assert!(has_end_stream(&frame_end_stream));
        assert!(!has_end_headers(&frame_end_stream));

        let frame_end_headers = Http2Frame {
            frame_type: FrameType::Headers,
            flags: flags::END_HEADERS,
            stream_id: 1,
            payload_length: 0,
            payload: vec![],
        };

        assert!(!has_end_stream(&frame_end_headers));
        assert!(has_end_headers(&frame_end_headers));
    }

    /// Test: Invalid frame type
    #[test]
    fn test_invalid_frame_type() {
        let invalid_frame = [
            0x00, 0x00, 0x00, // Length = 0
            0xFF, // Type = invalid
            0x00, // Flags
            0x00, 0x00, 0x00, 0x01, // Stream ID = 1
        ];

        let result = parse_frame_header(&invalid_frame);
        assert!(result.is_err());

        match result {
            Err(ParseError::InvalidFrameType(0xFF)) => {}
            _ => panic!("Expected InvalidFrameType error"),
        }
    }
}
