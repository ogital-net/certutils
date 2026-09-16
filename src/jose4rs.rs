use ::jose4rs::jwk::JsonWebKey;

use crate::{Error, PrivateKey, PublicKey, Result};

impl PrivateKey {
    /// Imports a supported private key from a `jose4rs` JSON Web Key.
    ///
    /// The conversion uses unencrypted PKCS#8 DER and rejects public-only and
    /// unsupported keys.
    pub fn from_jose_jwk(key: &JsonWebKey) -> Result<Self> {
        let der = key.to_pkcs8_der().ok_or_else(|| Error::InvalidInput {
            field: "JWK",
            reason: "must contain private asymmetric key material".to_owned(),
        })?;
        Self::from_pkcs8_der(&der)
    }

    /// Exports this private key as a `jose4rs` JSON Web Key.
    ///
    /// The conversion uses unencrypted PKCS#8 DER and includes private key
    /// material in the returned value.
    pub fn to_jose_jwk(&self) -> Result<JsonWebKey> {
        JsonWebKey::from_der(self.to_pkcs8_der()?).map_err(|_| Error::InvalidEncoding {
            encoding: "jose4rs JWK",
        })
    }
}

impl PublicKey {
    /// Imports a supported public key from a `jose4rs` JSON Web Key.
    ///
    /// The conversion uses `SubjectPublicKeyInfo` DER and rejects unsupported
    /// key algorithms and parameters.
    pub fn from_jose_jwk(key: &JsonWebKey) -> Result<Self> {
        let der = key.to_spki_der().ok_or_else(|| Error::InvalidInput {
            field: "JWK",
            reason: "must contain asymmetric key material".to_owned(),
        })?;
        Self::from_spki_der(&der)
    }

    /// Exports this public key as a public-only `jose4rs` JSON Web Key.
    ///
    /// The conversion uses `SubjectPublicKeyInfo` DER.
    pub fn to_jose_jwk(&self) -> Result<JsonWebKey> {
        JsonWebKey::from_der(self.as_spki_der()).map_err(|_| Error::InvalidEncoding {
            encoding: "jose4rs JWK",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{PrivateKey, PublicKey};
    use crate::RsaKeySize;

    #[test]
    fn private_keys_round_trip_through_jwk() {
        for key in [
            PrivateKey::generate().unwrap(),
            PrivateKey::generate_rsa(RsaKeySize::Bits2048).unwrap(),
        ] {
            let jwk = key.to_jose_jwk().unwrap();
            assert!(jwk.to_pkcs8_der().is_some());
            let parsed = PrivateKey::from_jose_jwk(&jwk).unwrap();
            assert_eq!(parsed.public_key().unwrap(), key.public_key().unwrap());
        }
    }

    #[test]
    fn public_keys_round_trip_through_jwk() {
        for key in [
            PrivateKey::generate().unwrap(),
            PrivateKey::generate_rsa(RsaKeySize::Bits2048).unwrap(),
        ] {
            let public_key = key.public_key().unwrap();
            let jwk = public_key.to_jose_jwk().unwrap();
            assert!(jwk.to_pkcs8_der().is_none());
            assert_eq!(PublicKey::from_jose_jwk(&jwk).unwrap(), public_key);
            assert!(matches!(
                PrivateKey::from_jose_jwk(&jwk),
                Err(crate::Error::InvalidInput { field: "JWK", .. })
            ));
        }
    }
}
