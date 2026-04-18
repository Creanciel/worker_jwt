# Changelog

## [0.2.0]

- Accept PKCS#1 RSA PEM (`-----BEGIN RSA PRIVATE KEY-----`) for `Algorithm::Rs256`.
  GitHub App private keys now work without `openssl pkcs8 -topk8` conversion.

## [0.1.0]

- Initial release.
