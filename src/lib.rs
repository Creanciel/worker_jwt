//! JWT generation for wasm runtimes such as Cloudflare Workers.
//!
//! `worker_jwt` is a thin layer over [`wasm_web_crypto`] that turns a PEM
//! private key (or a shared secret for HMAC) and a set of claims into a
//! signed JWT. It delegates all cryptography to the Web Crypto API provided
//! by the host runtime, so it can be used from any environment where Web
//! Crypto is available — Cloudflare Workers, Deno, browsers, and Node.js
//! (v20+) alike.
//!
//! # Supported algorithms
//!
//! | Algorithm | JWT name | Typical use |
//! |---|---|---|
//! | RSASSA-PKCS1-v1_5 + SHA-256 | `RS256` | GitHub App, Google Cloud |
//! | ECDSA P-256 + SHA-256       | `ES256` | Apple (Sign in with Apple, APNs) |
//! | HMAC + SHA-256              | `HS256` | Custom auth, Supabase |
//!
//! # Scope
//!
//! This crate only **produces** JWTs. Verification is intentionally out of
//! scope — token verification belongs on the API server, not on the Worker
//! that calls outbound APIs. Fetching installation/access tokens over HTTP
//! is also out of scope and left to the caller.
//!
//! # Quick start
//!
//! ```no_run
//! use worker_jwt::{Algorithm, Claims, JwtSigner};
//!
//! # async fn run(pem_bytes: &[u8]) -> worker_jwt::Result<()> {
//! let signer = JwtSigner::new(Algorithm::Rs256, pem_bytes).await?;
//!
//! let claims = Claims::builder()
//!     .issuer("my-service")
//!     .subject("user-42")
//!     .expires_at(1_750_000_000)
//!     .build();
//!
//! let jwt: String = signer.sign(&claims).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Cargo features
//!
//! - `github` — preset for GitHub App authentication. See [`github::GitHubAppJwt`].
//! - `google` — preset for Google service account authentication.
//!   See [`google::GoogleServiceAccountJwt`].
//! - `full` — enables both presets.

mod base64;
mod claims;
mod error;
mod pem;
mod signer;

#[cfg(feature = "github")]
pub mod github;
#[cfg(feature = "google")]
pub mod google;

pub use claims::{Claims, ClaimsBuilder};
pub use error::{JwtError, Result};
pub use signer::{Algorithm, JwtSigner};
