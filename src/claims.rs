use serde::Serialize;
use std::collections::HashMap;

/// JWT claims (the payload section of a JWT).
///
/// Each of the registered fields (`iss`, `sub`, `aud`, `exp`, `iat`) is
/// optional and omitted from the serialized payload when `None`. Anything
/// else — custom claims such as `scope`, `email`, or application-specific
/// keys — goes into [`extra`](Self::extra), which is flattened into the
/// top-level JSON object on serialization.
///
/// # Example
///
/// ```
/// use worker_jwt::Claims;
///
/// let claims = Claims::builder()
///     .issuer("my-service")
///     .subject("user-42")
///     .expires_at(1_750_000_000)
///     .extra("scope", "read write")
///     .build();
/// ```
#[derive(Debug, Clone, Default, Serialize)]
pub struct Claims {
    /// `iss` — issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// `sub` — subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// `aud` — audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// `exp` — expiration time, seconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// `iat` — issued-at time, seconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// Custom claims. Serialized flattened alongside the registered fields.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl Claims {
    /// Returns a new [`ClaimsBuilder`].
    pub fn builder() -> ClaimsBuilder {
        ClaimsBuilder::default()
    }
}

/// Fluent builder for [`Claims`].
///
/// Use [`Claims::builder`] to start, chain setters, then call
/// [`build`](Self::build) to produce the [`Claims`] value. All setters are
/// optional — anything left unset is omitted from the signed payload.
#[derive(Debug, Default)]
pub struct ClaimsBuilder {
    claims: Claims,
}

impl ClaimsBuilder {
    #[deprecated(note = "use `issuer` instead")]
    pub fn iss(self, value: &str) -> Self {
        self.issuer(value)
    }

    /// Sets the `iss` (issuer) claim.
    pub fn issuer(mut self, value: &str) -> Self {
        self.claims.iss = Some(value.into());
        self
    }

    #[deprecated(note = "use `subject` instead")]
    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, value: &str) -> Self {
        self.subject(value)
    }

    /// Sets the `sub` (subject) claim.
    pub fn subject(mut self, value: &str) -> Self {
        self.claims.sub = Some(value.into());
        self
    }

    #[deprecated(note = "use `audience` instead")]
    pub fn aud(self, value: &str) -> Self {
        self.audience(value)
    }

    /// Sets the `aud` (audience) claim.
    pub fn audience(mut self, value: &str) -> Self {
        self.claims.aud = Some(value.into());
        self
    }

    #[deprecated(note = "use `expires_at` instead")]
    pub fn exp(self, value: u64) -> Self {
        self.expires_at(value)
    }

    /// Sets the `exp` (expiration) claim, in seconds since the Unix epoch.
    pub fn expires_at(mut self, value: u64) -> Self {
        self.claims.exp = Some(value);
        self
    }

    #[deprecated(note = "use `issued_at` instead")]
    pub fn iat(self, value: u64) -> Self {
        self.issued_at(value)
    }

    /// Sets the `iat` (issued-at) claim, in seconds since the Unix epoch.
    pub fn issued_at(mut self, value: u64) -> Self {
        self.claims.iat = Some(value);
        self
    }

    /// Inserts a custom claim. Overwrites any existing value with the same key.
    ///
    /// `value` accepts anything that converts into a [`serde_json::Value`],
    /// which covers strings, numbers, booleans, arrays, and full JSON
    /// objects.
    pub fn extra(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.claims.extra.insert(key.into(), value.into());
        self
    }

    /// Consumes the builder and returns the final [`Claims`].
    pub fn build(self) -> Claims {
        self.claims
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_omits_none_fields() {
        let claims = Claims {
            iss: Some("test".into()),
            exp: Some(1234567890),
            ..Default::default()
        };
        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(json["iss"], "test");
        assert_eq!(json["exp"], 1234567890);
        assert!(json.get("sub").is_none());
        assert!(json.get("aud").is_none());
        assert!(json.get("iat").is_none());
    }

    #[test]
    fn serialize_flattens_extra() {
        let mut claims = Claims::default();
        claims.extra.insert(
            "scope".into(),
            serde_json::Value::String("read write".into()),
        );
        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(json["scope"], "read write");
    }
}
