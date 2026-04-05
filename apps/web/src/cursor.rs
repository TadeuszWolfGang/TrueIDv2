//! Shared helpers for opaque cursor encoding and decoding.

use axum::http::StatusCode;

use crate::error::{self, ApiError};

/// Builds a uniform validation error for malformed cursors.
///
/// Parameters: `request_id` - request correlation ID, `message` - client-facing error text.
/// Returns: consistent API error with `INVALID_INPUT`.
pub(crate) fn invalid_cursor(request_id: &str, message: &str) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, error::INVALID_INPUT, message)
        .with_request_id(request_id)
}

/// Hex-encodes cursor payload into a query-safe opaque token.
///
/// Parameters: `payload` - raw cursor payload to encode.
/// Returns: ASCII-safe opaque token suitable for query parameters.
pub(crate) fn encode_cursor_payload(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
    for byte in payload.bytes() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Decodes an opaque hex cursor payload into UTF-8 string content.
///
/// Parameters: `raw` - raw token from client, `request_id` - request correlation ID,
/// `message` - client-facing validation message.
/// Returns: decoded UTF-8 payload or a consistent validation error.
pub(crate) fn decode_cursor_payload(
    raw: &str,
    request_id: &str,
    message: &str,
) -> Result<String, ApiError> {
    if raw.is_empty() || raw.len() % 2 != 0 || !raw.is_ascii() {
        return Err(invalid_cursor(request_id, message));
    }

    let mut bytes = Vec::with_capacity(raw.len() / 2);
    for chunk in raw.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(chunk).map_err(|_| invalid_cursor(request_id, message))?;
        let byte = u8::from_str_radix(pair, 16).map_err(|_| invalid_cursor(request_id, message))?;
        bytes.push(byte);
    }

    String::from_utf8(bytes).map_err(|_| invalid_cursor(request_id, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_and_decode_round_trip() {
        let raw = "2026-04-05T10:00:00Z\n42";
        let encoded = encode_cursor_payload(raw);
        let decoded = decode_cursor_payload(&encoded, "req-1", "invalid")
            .unwrap_or_else(|_| panic!("cursor should decode"));
        assert_eq!(decoded, raw);
    }

    #[test]
    fn decode_rejects_odd_length() {
        let err = decode_cursor_payload("abc", "req-1", "invalid").expect_err("must fail");
        assert_eq!(err.code, error::INVALID_INPUT);
    }

    #[test]
    fn decode_rejects_non_ascii() {
        let err = decode_cursor_payload("0\u{80}000", "req-1", "invalid").expect_err("must fail");
        assert_eq!(err.code, error::INVALID_INPUT);
    }

    #[test]
    fn decode_rejects_invalid_hex() {
        let err = decode_cursor_payload("zz", "req-1", "invalid").expect_err("must fail");
        assert_eq!(err.code, error::INVALID_INPUT);
    }
}
