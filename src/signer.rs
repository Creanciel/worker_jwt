use crate::base64::base64url_encode;
use crate::claims::Claims;
use crate::error::Result;
use crate::pem;
use wasm_web_crypto::{
    Algorithm as WasmAlgorithm, CryptoKey, Hash, KeyFormat, KeyUsage, NamedCurve, SubtleCrypto,
};

/// JWT signing algorithm.
///
/// The variant determines both the JWT `alg` header value and the expected
/// format of the key data passed to [`JwtSigner::new`].
#[derive(Debug, Clone, Copy)]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256 (`RS256`).
    ///
    /// Key data: PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`). Typical RSA
    /// modulus size is 2048 bits. Used by GitHub App, Google Cloud service
    /// accounts, and most server-to-server JWT flows.
    Rs256,
    /// ECDSA on curve P-256 with SHA-256 (`ES256`).
    ///
    /// Key data: PKCS#8 PEM. Used by Apple (Sign in with Apple, APNs
    /// Provider API) and other services that prefer compact signatures.
    Es256,
    /// HMAC with SHA-256 (`HS256`).
    ///
    /// Key data: raw shared-secret bytes. Used for symmetric authentication
    /// schemes such as custom gateways and Supabase.
    Hs256,
}

impl Algorithm {
    fn as_jwt_str(&self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
            Self::Hs256 => "HS256",
        }
    }

    fn wasm_algorithm(&self) -> WasmAlgorithm {
        match self {
            Self::Rs256 => WasmAlgorithm::RsassaPkcs1v15 { hash: Hash::Sha256 },
            Self::Es256 => WasmAlgorithm::Ecdsa {
                hash: Hash::Sha256,
                named_curve: NamedCurve::P256,
            },
            Self::Hs256 => WasmAlgorithm::Hmac {
                hash: Hash::Sha256,
                length: None,
            },
        }
    }

    fn key_format(&self) -> KeyFormat {
        match self {
            Self::Rs256 | Self::Es256 => KeyFormat::Pkcs8,
            Self::Hs256 => KeyFormat::Raw,
        }
    }
}

/// A JWT signer backed by a Web Crypto [`CryptoKey`].
///
/// `JwtSigner` owns an imported key and the [`SubtleCrypto`] handle used to
/// sign with it. Create one with [`JwtSigner::new`] and call [`sign`] as
/// many times as needed — importing the key is the expensive part, signing
/// is cheap.
///
/// [`sign`]: JwtSigner::sign
///
/// # Example
///
/// ```no_run
/// use worker_jwt::{Algorithm, Claims, JwtSigner};
///
/// # async fn run(pem: &[u8]) -> worker_jwt::Result<()> {
/// let signer = JwtSigner::new(Algorithm::Rs256, pem).await?;
///
/// let claims = Claims::builder()
///     .issuer("example-app")
///     .expires_at(1_750_000_000)
///     .build();
///
/// let token = signer.sign(&claims).await?;
/// # Ok(())
/// # }
/// ```
pub struct JwtSigner {
    algorithm: Algorithm,
    key: CryptoKey,
    subtle: SubtleCrypto,
}

impl JwtSigner {
    /// Imports `key_data` into a Web Crypto `CryptoKey` and returns a signer.
    ///
    /// The expected format of `key_data` depends on the algorithm:
    ///
    /// - [`Algorithm::Rs256`]: PKCS#8 PEM
    ///   (`-----BEGIN PRIVATE KEY-----`) or PKCS#1 PEM
    ///   (`-----BEGIN RSA PRIVATE KEY-----`). GitHub App private keys ship
    ///   as PKCS#1 and are accepted without conversion.
    /// - [`Algorithm::Es256`]: PKCS#8 PEM only. Convert SEC1 PEMs
    ///   (`-----BEGIN EC PRIVATE KEY-----`) with
    ///   `openssl pkcs8 -topk8 -nocrypt -in in.pem -out out.pem` first.
    /// - [`Algorithm::Hs256`]: raw shared-secret bytes.
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::InvalidPem`] if PEM parsing fails, or
    /// [`JwtError::CryptoError`] if Web Crypto rejects the key material
    /// (wrong algorithm, corrupted DER, unsupported curve, etc.).
    ///
    /// [`JwtError::InvalidPem`]: crate::JwtError::InvalidPem
    /// [`JwtError::CryptoError`]: crate::JwtError::CryptoError
    pub async fn new(algorithm: Algorithm, key_data: &[u8]) -> Result<Self> {
        let der = match algorithm {
            Algorithm::Rs256 | Algorithm::Es256 => pem::pem_to_der(key_data)?,
            Algorithm::Hs256 => key_data.to_vec(),
        };

        let subtle = SubtleCrypto::new()?;
        let key = subtle
            .import_key(
                algorithm.key_format(),
                &der,
                &algorithm.wasm_algorithm(),
                false,
                &[KeyUsage::Sign],
            )
            .await?;

        Ok(Self {
            algorithm,
            key,
            subtle,
        })
    }

    /// Signs `claims` and returns the encoded JWT `header.payload.signature`.
    ///
    /// The header is fixed to `{"alg":"<algorithm>","typ":"JWT"}`. The
    /// payload is produced by serializing `claims` to JSON (skipping
    /// `None` fields and flattening
    /// [`extra`](crate::Claims::extra)). Both parts are base64url-encoded
    /// without padding as required by RFC 7519.
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::SerializationError`] if the claims cannot be
    /// serialized, or [`JwtError::CryptoError`] if the underlying Web
    /// Crypto `sign` call fails.
    ///
    /// [`JwtError::SerializationError`]: crate::JwtError::SerializationError
    /// [`JwtError::CryptoError`]: crate::JwtError::CryptoError
    pub async fn sign(&self, claims: &Claims) -> Result<String> {
        let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, self.algorithm.as_jwt_str());

        let payload = serde_json::to_vec(claims)?;

        let signing_input = format!(
            "{}.{}",
            base64url_encode(header.as_bytes()),
            base64url_encode(&payload),
        );

        let signature = self
            .subtle
            .sign(
                &self.algorithm.wasm_algorithm(),
                &self.key,
                signing_input.as_bytes(),
            )
            .await?;

        Ok(format!(
            "{}.{}",
            signing_input,
            base64url_encode(signature.to_bytes()),
        ))
    }
}
