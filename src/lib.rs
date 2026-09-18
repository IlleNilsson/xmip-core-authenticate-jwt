#![forbid(unsafe_code)]

//! Authenticate by jwt: verifies a token's signature (HS256, RS256, ES256),
//! expiry, issuer and audience.
//!
//! The first gate read the token's `sub` and presented it as the claim, with
//! the token itself riding as the `jwt.token` proof. This gate checks that
//! the token was signed by a key the node holds — a shared secret, an RSA or
//! a P-256 public key, chosen by the `kid` the header names — that it sits
//! inside its `nbf`/`exp` window with the configured leeway, that `iss` and
//! `aud` are the ones the node expects, and that the subject is the value
//! that was claimed. Offline throughout (ADR-0045): the keys are
//! configuration, never fetched. The same token inside a payload is `jws`
//! and another gate's.

pub mod key;

pub use key::{Algorithm, Key};

use authenticate::{AuthenticateError, Authenticator, Presented};
use context::Verified;
use identify::jwt::Compact;
use std::time::{SystemTime, UNIX_EPOCH};
use xcore::{Mechanism, mechanism};

/// The proof the identify sibling attaches the compact token under.
pub const TOKEN: &str = "jwt.token";

type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Seconds since the Unix epoch, now.
#[must_use]
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The jwt authenticator: the keys the node holds and what it expects of a
/// token's claims.
pub struct Verifier {
    keys: Vec<Key>,
    issuer: Option<String>,
    audience: Option<String>,
    leeway: i64,
    clock: Clock,
}

impl Verifier {
    /// Verifies against these keys, with sixty seconds of leeway on the time
    /// claims and no expectation of issuer or audience.
    #[must_use]
    pub fn new(keys: Vec<Key>) -> Self {
        Self {
            keys,
            issuer: None,
            audience: None,
            leeway: 60,
            clock: Box::new(now),
        }
    }

    /// Refuse a token whose `iss` is not this.
    #[must_use]
    pub fn expecting_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Refuse a token whose `aud` does not name this.
    #[must_use]
    pub fn expecting_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// How far a clock may be off before `exp` and `nbf` bite.
    #[must_use]
    pub const fn with_leeway(mut self, seconds: i64) -> Self {
        self.leeway = seconds;
        self
    }

    /// Where the time comes from; the tests pin it.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    fn key_for(&self, compact: &Compact, algorithm: Algorithm) -> Result<&Key, AuthenticateError> {
        match compact.key_id() {
            Some(id) => self
                .keys
                .iter()
                .find(|key| key.id() == Some(id.as_str()))
                .ok_or_else(|| {
                    AuthenticateError::new(format!("the node holds no key named '{id}'"))
                }),
            None => self
                .keys
                .iter()
                .find(|key| key.algorithm() == algorithm)
                .ok_or_else(|| {
                    AuthenticateError::new(format!(
                        "the node holds no {} key and the token names none",
                        algorithm.name()
                    ))
                }),
        }
    }

    fn check_claims(&self, compact: &Compact, subject: &str) -> Result<(), AuthenticateError> {
        let now = (self.clock)();

        if let Some(expiry) = compact.numeric_claim("exp")
            && now > expiry.saturating_add(self.leeway)
        {
            return Err(AuthenticateError::new(format!(
                "the token expired at {expiry} and it is {now}"
            )));
        }
        if let Some(not_before) = compact.numeric_claim("nbf")
            && now.saturating_add(self.leeway) < not_before
        {
            return Err(AuthenticateError::new(format!(
                "the token is not valid before {not_before} and it is {now}"
            )));
        }
        if let Some(issuer) = &self.issuer
            && compact.claim("iss").as_deref() != Some(issuer.as_str())
        {
            return Err(AuthenticateError::new(format!(
                "the token's issuer is not '{issuer}'"
            )));
        }
        if let Some(audience) = &self.audience
            && !compact
                .strings_claim("aud")
                .iter()
                .any(|aud| aud == audience)
        {
            return Err(AuthenticateError::new(format!(
                "the token's audience does not name '{audience}'"
            )));
        }
        if compact.claim("sub").as_deref() != Some(subject) {
            return Err(AuthenticateError::new(
                "the token's subject is not the claimed value",
            ));
        }

        Ok(())
    }
}

impl Authenticator for Verifier {
    fn mechanism(&self) -> Mechanism {
        mechanism::jwt()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        let name = presented.mechanism.name();
        if name != self.mechanism().name() {
            return Err(AuthenticateError::new(format!(
                "'{name}' was presented and this authenticator verifies jwt"
            )));
        }
        let token = presented
            .proof(TOKEN)
            .ok_or_else(|| AuthenticateError::new(format!("no {TOKEN} proof was presented")))?;
        let compact =
            Compact::parse(token).map_err(|failure| AuthenticateError::new(failure.message))?;

        let named = compact.algorithm().unwrap_or_default();
        let algorithm = Algorithm::named(&named).ok_or_else(|| {
            AuthenticateError::new(format!(
                "the token's algorithm '{named}' is not one this node verifies"
            ))
        })?;
        let key = self.key_for(&compact, algorithm)?;
        key.verify(
            algorithm,
            compact.signing_input.as_bytes(),
            &compact.signature,
        )?;
        self.check_claims(&compact, &presented.value)?;

        Ok(Verified::Proven)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use hmac::{Hmac, Mac};
    use rsa::signature::{SignatureEncoding, Signer};
    use sha2::Sha256;

    const NOW: i64 = 1_800_000_000;

    fn mint(header: &str, claims: &str, sign: impl Fn(&[u8]) -> Vec<u8>) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let signature = sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn hs256(secret: &[u8]) -> impl Fn(&[u8]) -> Vec<u8> {
        let secret = secret.to_vec();
        move |input| {
            let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("a secret");
            mac.update(input);
            mac.finalize().into_bytes().to_vec()
        }
    }

    fn claims(expiry: i64) -> String {
        format!(
            r#"{{"sub":"partner-x","iss":"https://issuer.example","aud":["xmip"],"exp":{expiry}}}"#
        )
    }

    fn verifier() -> Verifier {
        Verifier::new(vec![Key::secret(Some("k1"), b"a-shared-secret")])
            .expecting_issuer("https://issuer.example")
            .expecting_audience("xmip")
            .with_clock(|| NOW)
    }

    fn presented(token: &str) -> Presented {
        Presented::passed(mechanism::jwt(), "partner-x").with_proof(TOKEN, token)
    }

    #[test]
    fn a_token_signed_with_the_shared_secret_verifies_to_proven() {
        let token = mint(
            r#"{"alg":"HS256","kid":"k1"}"#,
            &claims(NOW + 300),
            hs256(b"a-shared-secret"),
        );

        let verified = verifier().verify(&presented(&token)).expect("proven");

        assert_eq!(verified, Verified::Proven);
    }

    #[test]
    fn a_token_signed_with_another_secret_is_refused_for_its_signature() {
        let token = mint(
            r#"{"alg":"HS256","kid":"k1"}"#,
            &claims(NOW + 300),
            hs256(b"another-secret"),
        );

        let failure = verifier().verify(&presented(&token)).expect_err("refused");

        assert!(failure.message.contains("signature does not verify"));
    }

    #[test]
    fn an_expired_token_is_refused_by_its_expiry() {
        let token = mint(
            r#"{"alg":"HS256","kid":"k1"}"#,
            &claims(NOW - 300),
            hs256(b"a-shared-secret"),
        );

        let failure = verifier().verify(&presented(&token)).expect_err("refused");

        assert!(failure.message.contains("expired"));
    }

    #[test]
    fn a_token_for_another_audience_is_refused() {
        let token = mint(
            r#"{"alg":"HS256","kid":"k1"}"#,
            &format!(
                r#"{{"sub":"partner-x","iss":"https://issuer.example","aud":"other","exp":{}}}"#,
                NOW + 300
            ),
            hs256(b"a-shared-secret"),
        );

        let failure = verifier().verify(&presented(&token)).expect_err("refused");

        assert!(failure.message.contains("audience"));
    }

    #[test]
    fn a_token_whose_subject_is_not_the_claimed_value_is_refused() {
        let token = mint(
            r#"{"alg":"HS256","kid":"k1"}"#,
            &claims(NOW + 300),
            hs256(b"a-shared-secret"),
        );
        let claim = Presented::passed(mechanism::jwt(), "someone-else").with_proof(TOKEN, token);

        let failure = verifier().verify(&claim).expect_err("refused");

        assert!(failure.message.contains("subject"));
    }

    #[test]
    fn a_claim_of_another_mechanism_is_not_this_authenticators() {
        let claim = Presented::passed(mechanism::oidc(), "partner-x").with_proof(TOKEN, "x.y.z");

        let failure = verifier().verify(&claim).expect_err("refused");

        assert!(failure.message.contains("'oidc' was presented"));
    }

    #[test]
    fn a_claim_without_the_token_proof_names_what_is_missing() {
        let failure = verifier()
            .verify(&Presented::passed(mechanism::jwt(), "partner-x"))
            .expect_err("refused");

        assert!(failure.message.contains("jwt.token"));
    }

    #[test]
    fn an_unsigned_token_is_refused_by_its_algorithm() {
        let token = mint(r#"{"alg":"none"}"#, &claims(NOW + 300), |_| Vec::new());

        let failure = verifier().verify(&presented(&token)).expect_err("refused");

        assert!(failure.message.contains("'none'"));
    }

    #[test]
    fn an_rs256_token_verifies_with_the_rsa_public_key() {
        let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("a key");
        let public = rsa::RsaPublicKey::from(&private);
        let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(private);
        let token = mint(r#"{"alg":"RS256"}"#, &claims(NOW + 300), |input| {
            signer.sign(input).to_vec()
        });
        let pem = rsa::pkcs8::EncodePublicKey::to_public_key_pem(
            &public,
            rsa::pkcs8::LineEnding::default(),
        )
        .expect("pem");
        let verifier =
            Verifier::new(vec![Key::rsa_pem(None, &pem).expect("a key")]).with_clock(|| NOW);

        assert_eq!(
            verifier.verify(&presented(&token)).expect("proven"),
            Verified::Proven
        );
    }

    #[test]
    fn an_es256_token_verifies_with_the_p256_public_key() {
        let signing = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let public = p256::PublicKey::from(signing.verifying_key());
        let token = mint(
            r#"{"alg":"ES256","kid":"e1"}"#,
            &claims(NOW + 300),
            |input| {
                let signature: p256::ecdsa::Signature = signing.sign(input);
                signature.to_vec()
            },
        );
        let pem = p256::pkcs8::EncodePublicKey::to_public_key_pem(
            &public,
            p256::pkcs8::LineEnding::default(),
        )
        .expect("pem");
        let verifier =
            Verifier::new(vec![Key::p256_pem(Some("e1"), &pem).expect("a key")]).with_clock(|| NOW);

        assert_eq!(
            verifier.verify(&presented(&token)).expect("proven"),
            Verified::Proven
        );
    }
}
