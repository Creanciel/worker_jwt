use std::fmt;

/// Errors that can occur while building or signing a JWT.
#[derive(Debug)]
pub enum JwtError {
    /// The provided PEM was malformed, used an unsupported format (PKCS#1
    /// / SEC1), or contained invalid base64.
    InvalidPem(String),
    /// Claims could not be serialized to JSON.
    SerializationError(String),
    /// The underlying Web Crypto call failed — for example, the key could
    /// not be imported or signing was rejected by the runtime.
    CryptoError(wasm_web_crypto::WebCryptoError),
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPem(msg) => write!(f, "invalid PEM: {msg}"),
            Self::SerializationError(msg) => write!(f, "serialization error: {msg}"),
            Self::CryptoError(err) => write!(f, "crypto error: {err}"),
        }
    }
}

impl std::error::Error for JwtError {}

impl From<wasm_web_crypto::WebCryptoError> for JwtError {
    fn from(err: wasm_web_crypto::WebCryptoError) -> Self {
        Self::CryptoError(err)
    }
}

impl From<serde_json::Error> for JwtError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

/// Shorthand for `std::result::Result<T, JwtError>`.
pub type Result<T> = std::result::Result<T, JwtError>;
