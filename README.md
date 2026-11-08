# xmip-core-authenticate-jwt

Authenticate by jwt: verifies a token's signature (HS256, RS256, ES256), expiry, issuer and audience. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

The keys are the capability's `authenticate::jose` — a shared secret, an RSA
or a P-256 public key, chosen by the `kid` a token names or, where it names
none, every key of its algorithm — the ones `oidc` holds too. The issuer and
the audience are required when the verifier is made. A token must carry an
`exp`; it is refused without one, on or after it and before its `nbf`, with
the configured leeway. The issuer, audience and expiry checks are the
capability's `authenticate::claims`, which `oidc`, `oauth2` and `saml` make
too.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
