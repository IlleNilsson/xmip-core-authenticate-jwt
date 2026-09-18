//! The keys a node verifies tokens with, and the check of one signature.
//!
//! RFC 7518 makes HS256 required and RS256 and ES256 recommended, and those
//! three are what this gate checks. A key serves one algorithm: a shared
//! secret serves HS256, an RSA public key RS256, a P-256 public key ES256.
//! A key may carry the `kid` a token names it by; a key without one is tried
//! where the token names none.

use authenticate::AuthenticateError;
use hmac::{Hmac, Mac};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier as _;
use sha2::Sha256;
use std::fmt;

/// One of the three signature algorithms this gate verifies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// HMAC over SHA-256 with a shared secret.
    Hs256,
    /// RSASSA-PKCS1-v1_5 over SHA-256.
    Rs256,
    /// ECDSA on P-256 over SHA-256.
    Es256,
}

impl Algorithm {
    /// The algorithm an `alg` header names, where it is one of the three.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        match name {
            "HS256" => Some(Self::Hs256),
            "RS256" => Some(Self::Rs256),
            "ES256" => Some(Self::Es256),
            _ => None,
        }
    }

    /// The `alg` name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hs256 => "HS256",
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }
}

/// What a key is made of.
#[derive(Clone)]
enum Material {
    Secret(Vec<u8>),
    Rsa(rsa::RsaPublicKey),
    P256(p256::ecdsa::VerifyingKey),
}

/// A key the node holds, serving one algorithm.
#[derive(Clone)]
pub struct Key {
    id: Option<String>,
    material: Material,
}

// The material is a secret or a public key of many bytes; neither belongs in
// a log line. The id and the algorithm say which key this is.
#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("id", &self.id)
            .field("algorithm", &self.algorithm().name())
            .finish()
    }
}

impl Key {
    /// A shared secret, for HS256.
    #[must_use]
    pub fn secret(id: Option<&str>, secret: impl AsRef<[u8]>) -> Self {
        Self {
            id: id.map(str::to_string),
            material: Material::Secret(secret.as_ref().to_vec()),
        }
    }

    /// An RSA public key from its SPKI PEM (`-----BEGIN PUBLIC KEY-----`),
    /// for RS256.
    ///
    /// # Errors
    ///
    /// Where the text is not an RSA public key in PEM.
    pub fn rsa_pem(id: Option<&str>, pem: &str) -> Result<Self, AuthenticateError> {
        let key = rsa::RsaPublicKey::from_public_key_pem(pem)
            .map_err(|_| AuthenticateError::new("the RSA key is not a public key in PEM"))?;
        Ok(Self {
            id: id.map(str::to_string),
            material: Material::Rsa(key),
        })
    }

    /// An RSA public key from its big-endian modulus and exponent, as a JWK
    /// carries them, for RS256.
    ///
    /// # Errors
    ///
    /// Where the pair is not a usable RSA key.
    pub fn rsa_components(
        id: Option<&str>,
        modulus: &[u8],
        exponent: &[u8],
    ) -> Result<Self, AuthenticateError> {
        let key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(modulus),
            rsa::BigUint::from_bytes_be(exponent),
        )
        .map_err(|_| AuthenticateError::new("the RSA modulus and exponent are not a key"))?;
        Ok(Self {
            id: id.map(str::to_string),
            material: Material::Rsa(key),
        })
    }

    /// A P-256 public key from its SPKI PEM, for ES256.
    ///
    /// # Errors
    ///
    /// Where the text is not a P-256 public key in PEM.
    pub fn p256_pem(id: Option<&str>, pem: &str) -> Result<Self, AuthenticateError> {
        let key = p256::PublicKey::from_public_key_pem(pem)
            .map_err(|_| AuthenticateError::new("the P-256 key is not a public key in PEM"))?;
        Ok(Self {
            id: id.map(str::to_string),
            material: Material::P256(p256::ecdsa::VerifyingKey::from(&key)),
        })
    }

    /// A P-256 public key from its affine coordinates, as a JWK carries
    /// them, for ES256.
    ///
    /// # Errors
    ///
    /// Where the coordinates are not thirty-two bytes each or not a point on
    /// the curve.
    pub fn p256_point(id: Option<&str>, x: &[u8], y: &[u8]) -> Result<Self, AuthenticateError> {
        if x.len() != 32 || y.len() != 32 {
            return Err(AuthenticateError::new(
                "a P-256 coordinate is thirty-two bytes",
            ));
        }
        let point = p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        let key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
            .map_err(|_| AuthenticateError::new("the P-256 coordinates are not on the curve"))?;
        Ok(Self {
            id: id.map(str::to_string),
            material: Material::P256(key),
        })
    }

    /// The `kid` this key answers to, where it has one.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// The one algorithm this key serves.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        match self.material {
            Material::Secret(_) => Algorithm::Hs256,
            Material::Rsa(_) => Algorithm::Rs256,
            Material::P256(_) => Algorithm::Es256,
        }
    }

    /// Check `signature` over `input` under `algorithm`.
    ///
    /// # Errors
    ///
    /// Where this key does not serve the algorithm, or the signature does
    /// not verify.
    pub fn verify(
        &self,
        algorithm: Algorithm,
        input: &[u8],
        signature: &[u8],
    ) -> Result<(), AuthenticateError> {
        let holds = match (&self.material, algorithm) {
            (Material::Secret(secret), Algorithm::Hs256) => {
                let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                    .map_err(|_| AuthenticateError::new("the HS256 secret is empty"))?;
                mac.update(input);
                mac.verify_slice(signature).is_ok()
            }
            (Material::Rsa(key), Algorithm::Rs256) => {
                let key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key.clone());
                rsa::pkcs1v15::Signature::try_from(signature)
                    .is_ok_and(|signature| key.verify(input, &signature).is_ok())
            }
            (Material::P256(key), Algorithm::Es256) => {
                p256::ecdsa::Signature::from_slice(signature)
                    .is_ok_and(|signature| key.verify(input, &signature).is_ok())
            }
            _ => {
                return Err(AuthenticateError::new(format!(
                    "the key serves {} and the token is signed {}",
                    self.algorithm().name(),
                    algorithm.name()
                )));
            }
        };

        if holds {
            Ok(())
        } else {
            Err(AuthenticateError::new(format!(
                "the {} signature does not verify with the node's key",
                algorithm.name()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_algorithm_is_named_by_its_header_value_and_nothing_else() {
        assert_eq!(Algorithm::named("HS256"), Some(Algorithm::Hs256));
        assert_eq!(Algorithm::named("none"), None);
        assert_eq!(Algorithm::named("hs256"), None);
    }

    #[test]
    fn a_secret_serves_hs256_and_refuses_another_algorithm_by_name() {
        let key = Key::secret(Some("k1"), b"secret");
        let failure = key
            .verify(Algorithm::Rs256, b"input", b"sig")
            .expect_err("refused");

        assert_eq!(key.algorithm(), Algorithm::Hs256);
        assert!(failure.message.contains("serves HS256"));
    }

    #[test]
    fn a_key_prints_its_id_and_algorithm_and_never_its_secret() {
        let printed = format!("{:?}", Key::secret(Some("k1"), b"hidden"));

        assert!(printed.contains("k1"));
        assert!(!printed.contains("hidden"));
    }

    #[test]
    fn a_p256_coordinate_of_the_wrong_length_is_refused() {
        let failure = Key::p256_point(None, &[1; 31], &[2; 32]).expect_err("refused");

        assert!(failure.message.contains("thirty-two"));
    }
}
