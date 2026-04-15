use crate::error::{JwtError, Result};

/// Decodes standard base64 (RFC 4648 §4). Trailing `=` padding is optional.
pub(crate) fn base64_decode(input: &[u8]) -> Result<Vec<u8>> {
    const INVALID: u8 = 0xFF;

    #[rustfmt::skip]
    const TABLE: [u8; 256] = {
        let mut t = [INVALID; 256];
        let mut i = 0u8;
        while i < 26 { t[(b'A' + i) as usize] = i; i += 1; }
        i = 0;
        while i < 26 { t[(b'a' + i) as usize] = 26 + i; i += 1; }
        i = 0;
        while i < 10 { t[(b'0' + i) as usize] = 52 + i; i += 1; }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };

    let data = match input.iter().rposition(|&b| b != b'=') {
        Some(pos) => &input[..=pos],
        None => return Ok(Vec::new()),
    };

    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let chunks = data.chunks_exact(4);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let (a, b, c, d) = (
            TABLE[chunk[0] as usize],
            TABLE[chunk[1] as usize],
            TABLE[chunk[2] as usize],
            TABLE[chunk[3] as usize],
        );
        if a == INVALID || b == INVALID || c == INVALID || d == INVALID {
            return Err(JwtError::InvalidPem("invalid base64 character".into()));
        }
        let triple = (a as u32) << 18 | (b as u32) << 12 | (c as u32) << 6 | d as u32;
        out.push((triple >> 16) as u8);
        out.push((triple >> 8) as u8);
        out.push(triple as u8);
    }

    match remainder.len() {
        2 => {
            let (a, b) = (TABLE[remainder[0] as usize], TABLE[remainder[1] as usize]);
            if a == INVALID || b == INVALID {
                return Err(JwtError::InvalidPem("invalid base64 character".into()));
            }
            out.push((a << 2) | (b >> 4));
        }
        3 => {
            let (a, b, c) = (
                TABLE[remainder[0] as usize],
                TABLE[remainder[1] as usize],
                TABLE[remainder[2] as usize],
            );
            if a == INVALID || b == INVALID || c == INVALID {
                return Err(JwtError::InvalidPem("invalid base64 character".into()));
            }
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
        }
        0 => {}
        _ => return Err(JwtError::InvalidPem("invalid base64 length".into())),
    }

    Ok(out)
}

/// Encodes as URL-safe base64 without padding (RFC 4648 §5), the form
/// required by JWT header, payload, and signature segments.
pub(crate) fn base64url_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        result.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            result.push(TABLE[((triple >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            result.push(TABLE[(triple & 0x3f) as usize] as char);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decode_basic() {
        assert_eq!(base64_decode(b"SGVsbG8=").unwrap(), b"Hello");
        assert_eq!(base64_decode(b"SGVsbG8").unwrap(), b"Hello");
        assert_eq!(base64_decode(b"").unwrap(), b"");
        assert_eq!(base64_decode(b"YQ==").unwrap(), b"a");
        assert_eq!(base64_decode(b"YWI=").unwrap(), b"ab");
        assert_eq!(base64_decode(b"YWJj").unwrap(), b"abc");
    }

    #[test]
    fn base64url_encode_basic() {
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(base64url_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64url_uses_url_safe_chars() {
        let data = [0xfb, 0xff, 0xfe];
        let encoded = base64url_encode(&data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(encoded.contains('-') || encoded.contains('_'));
    }
}
