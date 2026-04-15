//! Google service account authentication preset.

use crate::claims::Claims;
use crate::error::Result;
use crate::signer::{Algorithm, JwtSigner};

const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// Builder for a Google service account JWT.
///
/// Google server-to-server OAuth2 uses an `RS256` JWT signed by the
/// service account's private key. The resulting token is exchanged at
/// `POST https://oauth2.googleapis.com/token` for a bearer
/// `access_token` that can then call any Google API authorized by the
/// requested scope.
///
/// This preset fills in the claims Google requires:
///
/// | Claim | Value |
/// |---|---|
/// | `alg`   | `RS256` |
/// | `iss`   | the service account email |
/// | `aud`   | `https://oauth2.googleapis.com/token` |
/// | `scope` | the scope passed to [`scope`](Self::scope), if any |
/// | `iat`   | now |
/// | `exp`   | now + 3600 s (Google caps lifetime at 1 hour) |
///
/// # Example
///
/// ```no_run
/// use worker_jwt::google::GoogleServiceAccountJwt;
///
/// # async fn run(pem: &[u8]) -> worker_jwt::Result<()> {
/// let jwt = GoogleServiceAccountJwt::new(
///         "my-sa@my-project.iam.gserviceaccount.com",
///         pem,
///     )
///     .scope("https://www.googleapis.com/auth/spreadsheets")
///     .generate()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// The `private_key` field inside the service account JSON downloaded
/// from Google Cloud is already PKCS#8 PEM — pass it through unchanged.
pub struct GoogleServiceAccountJwt {
    email: String,
    pem_bytes: Vec<u8>,
    scope: Option<String>,
}

impl GoogleServiceAccountJwt {
    /// Creates a new builder for the given service account email and
    /// PKCS#8 PEM key.
    pub fn new(email: impl Into<String>, pem_bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            email: email.into(),
            pem_bytes: pem_bytes.into(),
            scope: None,
        }
    }

    /// Sets the OAuth2 scope claim. Multiple scopes may be passed as a
    /// space-separated string.
    ///
    /// Omitting this is valid only for narrow flows such as domain-wide
    /// delegation with `sub` set; the usual server-to-server path expects
    /// a scope.
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Generates a freshly signed JWT.
    ///
    /// Each call reads the current time and produces a new token valid
    /// for one hour. Safe to call repeatedly.
    pub async fn generate(&self) -> Result<String> {
        let now = now_unix_secs();
        let mut claims = Claims {
            iss: Some(self.email.clone()),
            aud: Some(TOKEN_ENDPOINT.into()),
            iat: Some(now),
            exp: Some(now + 3600),
            ..Default::default()
        };
        if let Some(scope) = &self.scope {
            claims
                .extra
                .insert("scope".into(), serde_json::Value::String(scope.clone()));
        }
        let signer = JwtSigner::new(Algorithm::Rs256, &self.pem_bytes).await?;
        signer.sign(&claims).await
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn now_unix_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}
