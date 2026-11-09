//! What a Receive Location configures the jwt authenticator with, declared
//! once (ADR-0064, amendment 2026-09-26) and read through that declaration.
//!
//! The issuer and the audience are required: a Location that leaves either
//! out, or gives it empty, is refused when it is read, so no verifier takes
//! a token from anyone, for anyone. The leeway on `exp` and `nbf` has a
//! default. The keys are the node's secrets and public keys, handed to
//! [`Verifier::configured`] apart from these.

use core::time::Duration;

use authenticate::AuthenticateError;
use authenticate::claims::Expected;
use authenticate::clock::Clock;
use authenticate::jose::{Key, KeySet};
use xcore::settings::{Applies, Fixed, Given, Kind, Presence, Setting, Settings};

use crate::Verifier;

/// How far a clock may be off before `exp` and `nbf` bite.
pub const LEEWAY: Duration = Duration::from_secs(60);

/// The jwt authenticator's settings.
pub const SETTINGS: &Settings = &Settings {
    technology: "xmip-core-authenticate-jwt",
    settings: &[
        Setting {
            name: "issuer",
            kind: Kind::Text,
            presence: Presence::Required,
            meaning: "The issuer a token's `iss` must be, exactly.",
            applies: Applies::Receive,
        },
        Setting {
            name: "audience",
            kind: Kind::Text,
            presence: Presence::Required,
            meaning: "The audience a token's `aud` must name.",
            applies: Applies::Receive,
        },
        Setting {
            name: "leeway",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(LEEWAY)),
            meaning: "How far a clock may be off before a token's `exp` and `nbf` bite.",
            applies: Applies::Receive,
        },
    ],
};

/// Whole seconds, as the capability's clock counts them.
fn seconds(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

impl Verifier {
    /// Verifies against these keys tokens `expected` names the issuer and
    /// audience of, with the default [`LEEWAY`] and the system clock.
    #[must_use]
    pub fn new(keys: Vec<Key>, expected: Expected) -> Self {
        Self {
            keys: KeySet::new(keys),
            expected,
            clock: Clock::system(seconds(LEEWAY)),
        }
    }

    /// Verifies against these keys with what a Receive Location `given`,
    /// read through [`SETTINGS`].
    ///
    /// # Errors
    ///
    /// Where the settings are refused — the issuer or the audience missing,
    /// a setting unknown or of another kind, each named — or the issuer or
    /// the audience is empty.
    pub fn configured(
        keys: Vec<Key>,
        given: &[(String, Given)],
    ) -> Result<Self, AuthenticateError> {
        let read = SETTINGS
            .read(Applies::Receive, given)
            .map_err(|refused| AuthenticateError::new(refused.to_string()))?;
        let expected = Expected::new(read.text("issuer"), read.text("audience"))?;
        Ok(Self::new(keys, expected).with_leeway(seconds(read.duration("leeway"))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn given(pairs: &[(&str, &str)]) -> Vec<(String, Given)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), Given::Text((*value).to_string())))
            .collect()
    }

    #[test]
    fn the_declaration_is_sound() {
        assert_eq!(SETTINGS.problems(), Vec::<String>::new());
    }

    #[test]
    fn a_configuration_without_an_issuer_or_an_audience_is_refused_in_words() {
        let refusal = |pairs: &[(&str, &str)]| match Verifier::configured(Vec::new(), &given(pairs))
        {
            Ok(_) => panic!("refused"),
            Err(refused) => refused.message,
        };

        assert_eq!(
            refusal(&[("audience", "xmip")]),
            "xmip-core-authenticate-jwt requires \"issuer\", and it is missing"
        );
        assert_eq!(
            refusal(&[("issuer", "https://issuer.example")]),
            "xmip-core-authenticate-jwt requires \"audience\", and it is missing"
        );
        assert!(
            refusal(&[("issuer", " "), ("audience", "xmip")]).contains("one is empty"),
            "an empty issuer is no issuer"
        );
        assert!(
            Verifier::configured(
                Vec::new(),
                &given(&[("issuer", "https://issuer.example"), ("audience", "xmip")])
            )
            .is_ok()
        );
    }
}
