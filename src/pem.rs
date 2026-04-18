use crate::base64::base64_decode;
use crate::error::{JwtError, Result};

/// Fixed prefix bytes of a PKCS#8 `PrivateKeyInfo` for RSA keys:
/// `INTEGER 0` (version) followed by the `AlgorithmIdentifier` SEQUENCE
/// `{ OID rsaEncryption (1.2.840.113549.1.1.1), NULL }`.
#[rustfmt::skip]
const PKCS8_RSA_PREFIX: [u8; 18] = [
    // version = INTEGER 0
    0x02, 0x01, 0x00,
    // AlgorithmIdentifier = SEQUENCE (length 13)
    0x30, 0x0D,
    // OID 1.2.840.113549.1.1.1 (rsaEncryption)
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    // parameters = NULL
    0x05, 0x00,
];

enum PemKind {
    Pkcs8,
    Pkcs1,
    Sec1,
}

/// Extracts the DER body from a private-key PEM.
///
/// - `BEGIN PRIVATE KEY` (PKCS#8): returned as-is.
/// - `BEGIN RSA PRIVATE KEY` (PKCS#1): transparently re-wrapped into a
///   PKCS#8 `PrivateKeyInfo` so the result is accepted by Web Crypto.
/// - `BEGIN EC PRIVATE KEY` (SEC1): rejected; convert to PKCS#8 first.
pub(crate) fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(pem)
        .map_err(|e| JwtError::InvalidPem(format!("invalid UTF-8: {e}")))?;

    let mut kind: Option<PemKind> = None;
    let mut body = String::new();
    let mut found_end = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") {
            kind = Some(if trimmed.contains("RSA PRIVATE KEY") {
                PemKind::Pkcs1
            } else if trimmed.contains("EC PRIVATE KEY") {
                PemKind::Sec1
            } else {
                PemKind::Pkcs8
            });
            continue;
        }
        if trimmed.starts_with("-----END") {
            found_end = true;
            break;
        }
        if kind.is_some() {
            body.push_str(trimmed);
        }
    }

    let Some(kind) = kind else {
        return Err(JwtError::InvalidPem(
            "missing PEM header/footer markers".into(),
        ));
    };
    if !found_end {
        return Err(JwtError::InvalidPem(
            "missing PEM header/footer markers".into(),
        ));
    }

    let der = base64_decode(body.as_bytes())?;

    match kind {
        PemKind::Pkcs8 => Ok(der),
        PemKind::Pkcs1 => Ok(wrap_pkcs1_as_pkcs8(&der)),
        PemKind::Sec1 => Err(JwtError::InvalidPem(
            "SEC1 (EC PRIVATE KEY) format is not supported; \
             convert to PKCS#8 (PRIVATE KEY) format"
                .into(),
        )),
    }
}

/// Serializes an ASN.1 DER definite-form length.
///
/// Lengths below 128 use the single-byte short form; larger values use the
/// long form (`0x80 | N` followed by `N` big-endian bytes). The value `0x80`
/// on its own is reserved for indefinite length and never emitted.
fn encode_der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else if len <= 0xFF_FFFF {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    } else {
        vec![
            0x84,
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    }
}

/// Re-wraps a PKCS#1 `RSAPrivateKey` DER blob as a PKCS#8 `PrivateKeyInfo`.
///
/// The input is treated as an opaque byte string — no ASN.1 parsing is
/// performed. The `rsaEncryption` OID is used in the AlgorithmIdentifier,
/// matching openssl's `pkcs8 -topk8` output and accepted by Web Crypto for
/// `RSASSA-PKCS1-v1_5` import.
fn wrap_pkcs1_as_pkcs8(pkcs1_der: &[u8]) -> Vec<u8> {
    let octet_len_bytes = encode_der_length(pkcs1_der.len());
    let octet_total = 1 + octet_len_bytes.len() + pkcs1_der.len();

    let inner_len = PKCS8_RSA_PREFIX.len() + octet_total;
    let outer_len_bytes = encode_der_length(inner_len);

    let total = 1 + outer_len_bytes.len() + inner_len;
    let mut out = Vec::with_capacity(total);

    out.push(0x30);
    out.extend_from_slice(&outer_len_bytes);
    out.extend_from_slice(&PKCS8_RSA_PREFIX);
    out.push(0x04);
    out.extend_from_slice(&octet_len_bytes);
    out.extend_from_slice(pkcs1_der);

    debug_assert_eq!(out.len(), total);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_to_der_valid_pkcs8() {
        let pem = b"-----BEGIN PRIVATE KEY-----\nSGVsbG8gV29ybGQ=\n-----END PRIVATE KEY-----\n";
        let der = pem_to_der(pem).unwrap();
        assert_eq!(der, b"Hello World");
    }

    #[test]
    fn pem_to_der_rejects_sec1() {
        let pem = b"-----BEGIN EC PRIVATE KEY-----\nAA==\n-----END EC PRIVATE KEY-----\n";
        let err = pem_to_der(pem).unwrap_err();
        assert!(err.to_string().contains("SEC1"));
    }

    #[test]
    fn pem_to_der_missing_markers() {
        let err = pem_to_der(b"not a pem").unwrap_err();
        assert!(err.to_string().contains("missing PEM"));
    }

    #[test]
    fn encode_der_length_short_127() {
        assert_eq!(encode_der_length(127), vec![0x7F]);
    }

    #[test]
    fn encode_der_length_one_byte_boundary_128() {
        assert_eq!(encode_der_length(128), vec![0x81, 0x80]);
    }

    #[test]
    fn encode_der_length_one_byte_255() {
        assert_eq!(encode_der_length(255), vec![0x81, 0xFF]);
    }

    #[test]
    fn encode_der_length_two_byte_256() {
        assert_eq!(encode_der_length(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn encode_der_length_two_byte_max_65535() {
        assert_eq!(encode_der_length(65535), vec![0x82, 0xFF, 0xFF]);
    }

    #[test]
    fn encode_der_length_three_byte_65536() {
        assert_eq!(encode_der_length(65536), vec![0x83, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn wrap_pkcs1_as_pkcs8_prefix_bytes() {
        let pkcs1 = vec![0xAA; 300];
        let wrapped = wrap_pkcs1_as_pkcs8(&pkcs1);

        // Outer SEQUENCE tag
        assert_eq!(wrapped[0], 0x30);
        // Outer length is long-form (0x82 XX XX) because inner_len > 255
        assert_eq!(wrapped[1], 0x82);

        // After outer length (3 bytes: 0x82 hi lo), the 18-byte prefix
        // (version + AlgorithmIdentifier) must appear verbatim.
        let prefix_start = 1 + 3;
        assert_eq!(
            &wrapped[prefix_start..prefix_start + 18],
            &PKCS8_RSA_PREFIX[..],
        );

        // Then OCTET STRING tag + long-form length (0x82 XX XX for 300)
        let octet_start = prefix_start + 18;
        assert_eq!(wrapped[octet_start], 0x04);
        assert_eq!(wrapped[octet_start + 1], 0x82);
        assert_eq!(wrapped[octet_start + 2], 0x01);
        assert_eq!(wrapped[octet_start + 3], 0x2C);
    }

    #[test]
    fn wrap_pkcs1_as_pkcs8_preserves_body() {
        let pkcs1: Vec<u8> = (0..=255u8).collect();
        let wrapped = wrap_pkcs1_as_pkcs8(&pkcs1);
        let tail = &wrapped[wrapped.len() - pkcs1.len()..];
        assert_eq!(tail, pkcs1.as_slice());
    }

    #[test]
    fn wrap_pkcs1_as_pkcs8_total_length_consistent() {
        for size in [1usize, 127, 128, 255, 256, 1190, 2349] {
            let pkcs1 = vec![0x5A; size];
            let wrapped = wrap_pkcs1_as_pkcs8(&pkcs1);

            // Outer length field must match the remaining bytes after the
            // `[tag=0x30][length bytes]` prefix.
            assert_eq!(wrapped[0], 0x30);
            let outer_len_bytes = encode_der_length(
                PKCS8_RSA_PREFIX.len() + 1 + encode_der_length(size).len() + size,
            );
            let header_len = 1 + outer_len_bytes.len();
            assert_eq!(wrapped.len() - header_len, {
                let first = outer_len_bytes[0];
                if first < 0x80 {
                    first as usize
                } else {
                    let n = (first & 0x7F) as usize;
                    outer_len_bytes[1..=n]
                        .iter()
                        .fold(0usize, |acc, &b| (acc << 8) | b as usize)
                }
            });
        }
    }

    #[test]
    fn pem_to_der_accepts_pkcs1() {
        // 10-byte dummy "PKCS#1" body (real parsing happens downstream in
        // Web Crypto; here we only care about the wrapper shape).
        let pem =
            b"-----BEGIN RSA PRIVATE KEY-----\nAAECAwQFBgcICQ==\n-----END RSA PRIVATE KEY-----\n";
        let der = pem_to_der(pem).unwrap();

        assert_eq!(der[0], 0x30);
        // Inner prefix (version + AlgorithmIdentifier) must start after the
        // outer [tag, short-length] pair (total 30 bytes is well under 128).
        let prefix_start = 2;
        assert_eq!(&der[prefix_start..prefix_start + 18], &PKCS8_RSA_PREFIX[..],);

        // OCTET STRING containing the 10-byte body follows.
        assert_eq!(der[prefix_start + 18], 0x04);
        assert_eq!(der[prefix_start + 19], 10);
        assert_eq!(
            &der[prefix_start + 20..],
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
        );
    }
}
