#![forbid(unsafe_code)]
//! Authenticate by jwt: verifies a token's signature (HS256, RS256, ES256), expiry, issuer,
//! audience.
//!
//! Declared and not yet written: `architecture.toml` carries the maturity. When it
//! is, it implements `Authenticator` (ADR-0050).
