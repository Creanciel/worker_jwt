//! GitHub App authentication preset.

use crate::claims::Claims;
use crate::error::Result;
use crate::signer::{Algorithm, JwtSigner};

/// Builder for a GitHub App authentication JWT.
///
/// GitHub App authentication uses an `RS256` JWT signed by the App's
/// private key. The resulting token is exchanged at
/// `POST /app/installations/:id/access_tokens` for a short-lived
/// installation token that can then call the GitHub REST or GraphQL API.
///
/// This preset fills in the claims that GitHub requires:
///
/// | Claim | Value |
/// |---|---|
/// | `alg` | `RS256` |
/// | `iss` | the App ID |
/// | `iat` | now − 60 s (clock-skew tolerance) |
/// | `exp` | now + 600 s (GitHub caps lifetime at 10 minutes) |
///
/// Only the App ID and PEM private key are required from the caller.
///
/// # Example
///
/// ```no_run
/// use worker_jwt::github::GitHubAppJwt;
///
/// # async fn run(pem: &[u8]) -> worker_jwt::Result<()> {
/// let jwt = GitHubAppJwt::new("123456", pem).generate().await?;
/// // POST to /app/installations/:id/access_tokens with `Authorization: Bearer {jwt}`
/// # Ok(())
/// # }
/// ```
pub struct GitHubAppJwt {
    app_id: String,
    pem_bytes: Vec<u8>,
}

impl GitHubAppJwt {
    /// Creates a new builder for the given App ID and PKCS#8 PEM key.
    ///
    /// `app_id` is the numeric App ID shown on the GitHub App settings
    /// page. `pem_bytes` is the contents of the `.pem` file downloaded
    /// when the private key was generated.
    pub fn new(app_id: impl Into<String>, pem_bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            app_id: app_id.into(),
            pem_bytes: pem_bytes.into(),
        }
    }

    /// Generates a freshly signed JWT.
    ///
    /// Each call reads the current time and produces a new token; the
    /// returned string is valid for 10 minutes. Safe to call repeatedly.
    pub async fn generate(&self) -> Result<String> {
        let now = now_unix_secs();
        let claims = Claims {
            iss: Some(self.app_id.clone()),
            iat: Some(now.saturating_sub(60)),
            exp: Some(now + 600),
            ..Default::default()
        };
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
