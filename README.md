# worker_jwt

JWT generation for wasm runtimes (Cloudflare Workers, Deno, browsers, Node.js 20+) backed by the Web Crypto API.

`worker_jwt` is a thin layer over [crate: wasm_web_crypto](https://crates.io/crates/wasm_web_crypto) that turns a PEM private key (or a shared secret for HMAC) plus a set of claims into a signed JWT string. All cryptography is delegated to the host runtime's Web Crypto implementation — no pure-Rust crypto is bundled.

## Supported algorithms

| Algorithm | JWT name | Typical use |
|----|----|----|
| RSASSA-PKCS1-v1_5 + SHA-256 | `RS256` | GitHub App, Google Cloud |
| ECDSA P-256 + SHA-256 | `ES256` | Apple (Sign in with Apple, APNs) |
| HMAC + SHA-256 | `HS256` | Custom auth, Supabase |

## Quick start

### Core API

```rust
use worker_jwt::{Algorithm, Claims, JwtSigner};

let signer = JwtSigner::new(Algorithm::Rs256, pem_bytes).await?;

let claims = Claims::builder()
    .issuer("my-service")
    .subject("user-42")
    .expires_at(1_750_000_000)
    .extra("scope", "read write")
    .build();

let jwt: String = signer.sign(&claims).await?;
```

Key format expected by `JwtSigner::new`:

- `Rs256` / `Es256` — PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`).
  Convert legacy PKCS#1 / SEC1 PEMs with:
  `openssl pkcs8 -topk8 -nocrypt -in in.pem -out out.pem`
- `Hs256` — raw shared-secret bytes.

Importing the key is the expensive step; one `JwtSigner` can `sign` any number of times.

### GitHub App (feature = `github`)

```sh
cargo add worker_jwt --features github
```

```rust
use worker_jwt::github::GitHubAppJwt;

let jwt = GitHubAppJwt::new("123456", pem_bytes).generate().await?;
// POST /app/installations/:id/access_tokens with `Authorization: Bearer {jwt}`
```

Claims are filled automatically: `alg=RS256`, `iss=app_id`, `iat=now − 60s`, `exp=now + 600s` (GitHub caps lifetime at 10 minutes).

### Google service account (feature = `google`)

```sh
cargo add worker_jwt --features google
```

```rust
use worker_jwt::google::GoogleServiceAccountJwt;

let jwt = GoogleServiceAccountJwt::new(
        "my-sa@my-project.iam.gserviceaccount.com",
        pem_bytes,
    )
    .scope("https://www.googleapis.com/auth/spreadsheets")
    .generate()
    .await?;
// POST https://oauth2.googleapis.com/token to exchange for an access_token
```

Claims are filled automatically: `alg=RS256`, `iss=<email>`, `aud=https://oauth2.googleapis.com/token`, `iat=now`, `exp=now + 3600s`. The `private_key` field in the service account JSON is already PKCS#8 PEM — pass it through unchanged.

### Apple (Sign in with Apple, APNs)

No preset is provided — use the core API with `ES256`:

```rust
use worker_jwt::{Algorithm, Claims, JwtSigner};

let signer = JwtSigner::new(Algorithm::Es256, p8_bytes).await?;
let claims = Claims::builder()
    .issuer(team_id)
    .subject(client_id)
    .audience("https://appleid.apple.com")
    .issued_at(now)
    .expires_at(now + 3600)
    .build();
let jwt = signer.sign(&claims).await?;
```

## Scope

This crate intentionally stays small:

- **Only signing.** Verification belongs on the API server, not on the Worker that calls outbound APIs.
- **No HTTP.** Exchanging the JWT for an installation/access token is the caller's job.
- **No JWK / JWKS.** Bring your own PEM.
