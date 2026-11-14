#![forbid(unsafe_code)]

//! Authenticate by jwt: verifies a token's signature (HS256, RS256, ES256),
//! expiry, issuer and audience.
//!
//! The first gate read the token's `sub` and presented it as the claim, with
//! the token itself riding as the `jwt.token` proof. This gate checks that
//! the token was signed by a key the node holds — a shared secret, an RSA or
//! a P-256 public key, chosen by the `kid` the header names — that it
//! carries an `exp` and sits inside its `nbf`/`exp` window with the
//! configured leeway, that `iss` and `aud` are the ones the node expects,
//! and that the subject is the value that was claimed. The issuer and the
//! audience are required when the verifier is made, and the three checks
//! are the capability's (`authenticate::claims`), the ones `oidc`, `oauth2`
//! and `saml` make too. A token without an `exp` is refused: it would prove
//! for ever. The issuer, the audience and the leeway are the `issuer`,
//! `audience` and `leeway` settings declared in [`settings`]; a Location
//! that leaves out the issuer or the audience is refused when it is read.
//! The algorithm is the header's and must be the named key's: `none` and an
//! algorithm the key does not serve are refused. Offline throughout (ADR-0045): the keys are configuration,
//! never fetched. The same token inside a payload is `jws` and another
//! gate's.

pub mod settings;

pub use settings::SETTINGS;

use authenticate::claims::{self, Expected};
use authenticate::clock::Clock;
use authenticate::jose::{Algorithm, KeySet};
use authenticate::{AuthenticateError, Authenticator, Conclusion};
use context::Verified;
use identify::Presented;
use identify::evidence::{self, JWT_TOKEN, SCOPE};
use identify::jwt::Compact;
use xcore::{Mechanism, mechanism};

/// The jwt authenticator: the keys the node holds and what it expects of a
/// token's claims. The keys are the capability's JOSE keys
/// (`authenticate::jose`), the ones `oidc` holds too.
pub struct Verifier {
    keys: KeySet,
    expected: Expected,
    clock: Clock,
}

impl Verifier {
    /// How far a clock may be off before `exp` and `nbf` bite.
    #[must_use]
    pub fn with_leeway(mut self, seconds: i64) -> Self {
        self.clock = self.clock.forgiving(seconds);
        self
    }

    /// Where the time comes from; the tests pin it.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = self.clock.reading(clock);
        self
    }

    fn check_claims(&self, compact: &Compact, subject: &str) -> Result<(), AuthenticateError> {
        claims::current(
            "the token",
            &self.clock,
            compact.numeric_claim("nbf"),
            ("exp", compact.numeric_claim("exp")),
        )?;
        self.expected
            .issued("the token", compact.claim("iss").as_deref())?;
        self.expected.addressed(
            "the token",
            compact.strings_claim("aud").iter().map(String::as_str),
        )?;
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
        self.conclude(presented)
            .map(|conclusion| conclusion.verified)
    }

    /// Proven, and the token's `scope` learned (RFC 9068 section 2.2.3): the
    /// signature covers it, and until the signature held it was anyone's
    /// word, so it is handed to the gate here and claimed nowhere.
    fn conclude(&self, presented: &Presented) -> Result<Conclusion, AuthenticateError> {
        let token = presented
            .proof(evidence::JWT_TOKEN)
            .ok_or_else(|| AuthenticateError::new(format!("no {JWT_TOKEN} proof was presented")))?;
        let compact =
            Compact::parse(token).map_err(|failure| AuthenticateError::new(failure.message))?;

        let named = compact.algorithm().unwrap_or_default();
        let algorithm = Algorithm::named(&named).ok_or_else(|| {
            AuthenticateError::new(format!(
                "the token's algorithm '{named}' is not one this node verifies"
            ))
        })?;
        self.keys.verify(
            algorithm,
            compact.key_id().as_deref(),
            compact.signing_input.as_bytes(),
            &compact.signature,
        )?;
        self.check_claims(&compact, &presented.value)?;

        let scopes = compact.strings_claim("scope");
        Ok(if scopes.is_empty() {
            Conclusion::proven()
        } else {
            Conclusion::proven().learning(SCOPE, scopes.join(" "))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticate::jose::Key;
    use p256::ecdsa::signature::Signer as _;
    use p256::elliptic_curve::Generate as _;
    use rsa::signature::{SignatureEncoding, Signer};

    const NOW: i64 = 1_800_000_000;

    fn mint(header: &str, claims: &str, sign: impl Fn(&[u8]) -> Vec<u8>) -> String {
        let input = format!(
            "{}.{}",
            codec::base64::encode_url_unpadded(header.as_bytes()),
            codec::base64::encode_url_unpadded(claims.as_bytes())
        );
        let signature = sign(input.as_bytes());
        format!("{input}.{}", codec::base64::encode_url_unpadded(&signature))
    }

    fn hs256(secret: &[u8]) -> impl Fn(&[u8]) -> Vec<u8> {
        let secret = secret.to_vec();
        move |input| codec::digest::hmac_sha256(&secret, input).to_vec()
    }

    fn claims(expiry: i64) -> String {
        format!(
            r#"{{"sub":"party-x","iss":"https://issuer.example","aud":["xmip"],"exp":{expiry}}}"#
        )
    }

    fn expected() -> Expected {
        Expected::new("https://issuer.example", "xmip").expect("both")
    }

    fn verifier() -> Verifier {
        Verifier::new(
            vec![Key::secret(Some("k1"), b"a-shared-secret")],
            expected(),
        )
        .with_clock(|| NOW)
    }

    #[test]
    fn a_token_without_an_expiry_is_refused_however_well_it_is_signed() {
        let token = mint(
            r#"{"alg":"HS256","kid":"k1"}"#,
            r#"{"sub":"party-x","iss":"https://issuer.example","aud":"xmip"}"#,
            hs256(b"a-shared-secret"),
        );

        let failure = verifier().verify(&presented(&token)).expect_err("no exp");

        assert!(failure.message.contains("carries no `exp`"), "{failure}");
    }

    #[test]
    fn a_token_from_another_issuer_or_naming_none_is_refused() {
        for claims in [
            format!(r#"{{"sub":"party-x","iss":"https://else","aud":"xmip","exp":{NOW}0}}"#),
            format!(r#"{{"sub":"party-x","aud":"xmip","exp":{NOW}0}}"#),
        ] {
            let token = mint(
                r#"{"alg":"HS256","kid":"k1"}"#,
                &claims,
                hs256(b"a-shared-secret"),
            );

            let failure = verifier().verify(&presented(&token)).expect_err("issuer");

            assert!(failure.message.contains("issuer is not"), "{failure}");
        }
    }

    #[test]
    fn a_token_naming_no_audience_is_refused() {
        let token = mint(
            r#"{"alg":"HS256","kid":"k1"}"#,
            &format!(
                r#"{{"sub":"party-x","iss":"https://issuer.example","exp":{}}}"#,
                NOW + 300
            ),
            hs256(b"a-shared-secret"),
        );

        let failure = verifier().verify(&presented(&token)).expect_err("no aud");

        assert_eq!(failure.message, "the token's audience does not name 'xmip'");
    }

    #[test]
    fn a_token_before_its_not_before_is_refused_and_the_leeway_forgives_a_little() {
        let token = mint(
            r#"{"alg":"HS256","kid":"k1"}"#,
            &claims(NOW + 600).replacen('{', &format!(r#"{{"nbf":{},"#, NOW + 120), 1),
            hs256(b"a-shared-secret"),
        );

        let early = verifier().verify(&presented(&token)).expect_err("early");
        let forgiven = verifier().with_leeway(180).verify(&presented(&token));

        assert!(early.message.contains("not valid before"), "{early}");
        assert_eq!(forgiven.expect("within the leeway"), Verified::Proven);
    }

    #[test]
    fn a_token_signed_with_an_algorithm_its_key_does_not_serve_is_refused() {
        // The classic confusion: an RS256 key's public half used as an HS256
        // secret. The key named serves one algorithm and no other.
        let token = mint(
            r#"{"alg":"RS256","kid":"k1"}"#,
            &claims(NOW + 300),
            hs256(b"a-shared-secret"),
        );

        let failure = verifier().verify(&presented(&token)).expect_err("refused");

        assert_eq!(
            failure.message,
            "the key 'k1' serves HS256 and the token is signed RS256"
        );
    }

    fn presented(token: &str) -> Presented {
        Presented::passed(mechanism::jwt(), "party-x").with_proof(evidence::JWT_TOKEN, token)
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
    fn a_proven_token_hands_the_gate_its_scopes_and_one_without_any_hands_none() {
        let scoped = claims(NOW + 300).replacen('{', r#"{"scope":"orders:read orders:write","#, 1);
        let token = mint(
            r#"{"alg":"HS256","kid":"k1"}"#,
            &scoped,
            hs256(b"a-shared-secret"),
        );
        let conclusion = verifier().conclude(&presented(&token)).expect("proven");
        assert_eq!(conclusion.learned(SCOPE), Some("orders:read orders:write"));

        let bare = mint(
            r#"{"alg":"HS256","kid":"k1"}"#,
            &claims(NOW + 300),
            hs256(b"a-shared-secret"),
        );
        let conclusion = verifier().conclude(&presented(&bare)).expect("proven");
        assert_eq!(conclusion.learned, [] as [(String, String); 0]);
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
                r#"{{"sub":"party-x","iss":"https://issuer.example","aud":"other","exp":{}}}"#,
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
        let claim = Presented::passed(mechanism::jwt(), "someone-else")
            .with_proof(evidence::JWT_TOKEN, token);

        let failure = verifier().verify(&claim).expect_err("refused");

        assert!(failure.message.contains("subject"));
    }

    #[test]
    fn a_claim_without_the_token_proof_names_what_is_missing() {
        let failure = verifier()
            .verify(&Presented::passed(mechanism::jwt(), "party-x"))
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
        let signer = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(private);
        let token = mint(r#"{"alg":"RS256"}"#, &claims(NOW + 300), |input| {
            signer.sign(input).to_vec()
        });
        let pem = rsa::pkcs8::EncodePublicKey::to_public_key_pem(
            &public,
            rsa::pkcs8::LineEnding::default(),
        )
        .expect("pem");
        let verifier = Verifier::new(vec![Key::rsa_pem(None, &pem).expect("a key")], expected())
            .with_clock(|| NOW);

        assert_eq!(
            verifier.verify(&presented(&token)).expect("proven"),
            Verified::Proven
        );
    }

    #[test]
    fn an_es256_token_verifies_with_the_p256_public_key() {
        let signing = p256::ecdsa::SigningKey::generate();
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
        let verifier = Verifier::new(
            vec![Key::p256_pem(Some("e1"), &pem).expect("a key")],
            expected(),
        )
        .with_clock(|| NOW);

        assert_eq!(
            verifier.verify(&presented(&token)).expect("proven"),
            Verified::Proven
        );
    }
}
