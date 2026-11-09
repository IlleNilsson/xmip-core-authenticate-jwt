# xmip-core-authenticate-jwt

Authenticate by jwt: verifies a token's signature (HS256, RS256, ES256), expiry, issuer and audience. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

The keys are the capability's `authenticate::jose` — a shared secret, an RSA
or a P-256 public key, chosen by the `kid` a token names or, where it names
none, every key of its algorithm — the ones `oidc` holds too. A token whose
`alg` is `none`, or another than the named key serves, is refused. A token
must carry an `exp`; it is refused without one, on or after it and before
its `nbf`, with the configured leeway; its `iss` must be the issuer and its
`aud` must name the audience. The issuer, audience and expiry checks are the
capability's `authenticate::claims`, which `oidc`, `oauth2` and `saml` make
too.

Its settings are declared in `settings.rs` through `xcore::settings`:

| Setting | Default | Meaning |
| --- | --- | --- |
| `issuer` | required | The issuer a token's `iss` must be, exactly. |
| `audience` | required | The audience a token's `aud` must name. |
| `leeway` | `60s` | How far a clock may be off before a token's `exp` and `nbf` bite. |

A configuration without the issuer or the audience, or with either empty, is
refused when it is read, naming the setting. The keys are the node's secrets
and public keys and are given apart from these.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
