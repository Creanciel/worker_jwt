use crate::base64::base64_decode;
use crate::error::{JwtError, Result};

/// Extracts the DER body from a PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`).
///
/// Legacy PKCS#1 (`RSA PRIVATE KEY`) and SEC1 (`EC PRIVATE KEY`) PEMs are
/// rejected explicitly to surface a clear error message instead of a
/// downstream Web Crypto import failure.
pub(crate) fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(pem)
        .map_err(|e| JwtError::InvalidPem(format!("invalid UTF-8: {e}")))?;

    let mut body = String::new();
    let mut found_begin = false;
    let mut found_end = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") {
            if trimmed.contains("RSA PRIVATE KEY") {
                return Err(JwtError::InvalidPem(
                    "PKCS#1 (RSA PRIVATE KEY) format is not supported; \
                     convert to PKCS#8 (PRIVATE KEY) format"
                        .into(),
                ));
            }
            if trimmed.contains("EC PRIVATE KEY") {
                return Err(JwtError::InvalidPem(
                    "SEC1 (EC PRIVATE KEY) format is not supported; \
                     convert to PKCS#8 (PRIVATE KEY) format"
                        .into(),
                ));
            }
            found_begin = true;
            continue;
        }
        if trimmed.starts_with("-----END") {
            found_end = true;
            break;
        }
        if found_begin {
            body.push_str(trimmed);
        }
    }

    if !found_begin || !found_end {
        return Err(JwtError::InvalidPem(
            "missing PEM header/footer markers".into(),
        ));
    }

    base64_decode(body.as_bytes())
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
    fn pem_to_der_rejects_pkcs1() {
        let pem = b"-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n";
        let err = pem_to_der(pem).unwrap_err();
        assert!(err.to_string().contains("PKCS#1"));
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
}
