use std::fmt;

use crate::{ffi, Error, Result};

/// A signature algorithm supported by this crate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// ECDSA over NIST P-256 with SHA-256.
    EcdsaP256Sha256,
    /// ECDSA over NIST P-384 with SHA-384, supported for public keys and verification.
    ///
    /// P-384 private-key generation and import are not supported.
    EcdsaP384Sha384,
    /// RSA PKCS#1 v1.5 with SHA-256.
    RsaPkcs1Sha256,
}

/// A supported RSA modulus size.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RsaKeySize {
    /// 2048 bits.
    Bits2048,
    /// 3072 bits.
    Bits3072,
    /// 4096 bits.
    Bits4096,
}

impl RsaKeySize {
    fn bits(self) -> u32 {
        match self {
            Self::Bits2048 => 2048,
            Self::Bits3072 => 3072,
            Self::Bits4096 => 4096,
        }
    }
}

/// An opaque private key used to sign certificates and CSRs.
///
/// Supported private keys use P-256 or RSA with unencrypted PKCS#8 encoding.
/// Imported RSA keys must have a modulus of at least 2048 bits and use the
/// public exponent 65537.
pub struct PrivateKey {
    inner: ffi::PrivateKey,
    algorithm: SignatureAlgorithm,
}

impl PrivateKey {
    /// Generates a new ECDSA P-256 private key using AWS-LC randomness.
    pub fn generate() -> Result<Self> {
        ffi::PrivateKey::generate_p256()
            .map(|inner| Self {
                inner,
                algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            })
            .map_err(|error| map_key_error(error, "PKCS#8"))
    }

    /// Generates a new RSA private key using AWS-LC randomness.
    pub fn generate_rsa(size: RsaKeySize) -> Result<Self> {
        ffi::PrivateKey::generate_rsa(size.bits())
            .map(|inner| Self {
                inner,
                algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            })
            .map_err(|error| map_key_error(error, "PKCS#8"))
    }

    /// Imports a supported unencrypted PKCS#8 private key from DER.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let inner = ffi::PrivateKey::from_pkcs8_der(der)
            .map_err(|error| map_key_error(error, "PKCS#8 DER"))?;
        let algorithm = signature_algorithm(
            inner
                .algorithm()
                .map_err(|error| map_key_error(error, "PKCS#8 DER"))?,
        );
        Ok(Self { inner, algorithm })
    }

    /// Imports a supported unencrypted PKCS#8 private key from PEM.
    ///
    /// Requires one header-free `PRIVATE KEY` block at the start of the input,
    /// followed only by optional ASCII whitespace. The decoded payload must
    /// contain exactly one PKCS#8 DER value.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let inner = ffi::PrivateKey::from_pkcs8_pem(pem)
            .map_err(|error| map_key_error(error, "PKCS#8 PEM"))?;
        let algorithm = signature_algorithm(
            inner
                .algorithm()
                .map_err(|error| map_key_error(error, "PKCS#8 PEM"))?,
        );
        Ok(Self { inner, algorithm })
    }

    /// Returns the key's signature algorithm.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Extracts the public key.
    pub fn public_key(&self) -> Result<PublicKey> {
        let spki_der = self
            .inner
            .public_key_der()
            .map_err(|error| map_key_error(error, "SPKI DER"))?;
        Ok(PublicKey {
            spki_der,
            algorithm: self.algorithm,
        })
    }

    /// Exports the private key as unencrypted PKCS#8 DER.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        self.inner
            .to_pkcs8_der()
            .map_err(|error| map_key_error(error, "PKCS#8 DER"))
    }

    /// Exports the private key as unencrypted PKCS#8 PEM.
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        self.inner
            .to_pkcs8_pem()
            .map_err(|error| map_key_error(error, "PKCS#8 PEM"))
    }

    pub(crate) fn as_ffi(&self) -> &ffi::PrivateKey {
        &self.inner
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateKey")
            .field("algorithm", &self.algorithm())
            .field("private_material", &"[REDACTED]")
            .finish()
    }
}

/// A public key encoded internally as X.509 `SubjectPublicKeyInfo`.
///
/// Supports P-256, P-384, and RSA public keys. P-384 support allows reading and
/// verifying certificates issued by P-384 certificate authorities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    spki_der: Vec<u8>,
    algorithm: SignatureAlgorithm,
}

impl PublicKey {
    /// Parses and validates a supported `SubjectPublicKeyInfo` value from DER.
    ///
    /// EC public keys must use P-256 or P-384.
    /// RSA keys must have a modulus of at least 2048 bits and use the public
    /// exponent 65537.
    pub fn from_spki_der(der: &[u8]) -> Result<Self> {
        let key =
            ffi::PublicKey::from_spki_der(der).map_err(|error| map_key_error(error, "SPKI DER"))?;
        let spki_der = key
            .to_spki_der()
            .map_err(|error| map_key_error(error, "SPKI DER"))?;
        let algorithm = signature_algorithm(
            key.algorithm()
                .map_err(|error| map_key_error(error, "SPKI DER"))?,
        );
        Ok(Self {
            spki_der,
            algorithm,
        })
    }

    /// Parses and validates a supported `SubjectPublicKeyInfo` value from PEM.
    ///
    /// Requires one header-free `PUBLIC KEY` block at the start of the input,
    /// followed only by optional ASCII whitespace. The decoded payload must
    /// contain exactly one SPKI DER value.
    ///
    /// EC public keys must use P-256 or P-384.
    /// RSA keys must have a modulus of at least 2048 bits and use the public
    /// exponent 65537.
    pub fn from_spki_pem(pem: &str) -> Result<Self> {
        let key =
            ffi::PublicKey::from_spki_pem(pem).map_err(|error| map_key_error(error, "SPKI PEM"))?;
        let spki_der = key
            .to_spki_der()
            .map_err(|error| map_key_error(error, "SPKI DER"))?;
        let algorithm = signature_algorithm(
            key.algorithm()
                .map_err(|error| map_key_error(error, "SPKI PEM"))?,
        );
        Ok(Self {
            spki_der,
            algorithm,
        })
    }

    /// Returns the key's signature algorithm.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Borrows the `SubjectPublicKeyInfo` DER encoding.
    pub fn as_spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// Encodes the `SubjectPublicKeyInfo` value as PEM.
    pub fn to_spki_pem(&self) -> Result<String> {
        ffi::PublicKey::from_spki_der(&self.spki_der)
            .and_then(|key| key.to_spki_pem())
            .map_err(|error| map_key_error(error, "SPKI PEM"))
    }

    pub(crate) fn to_ffi(&self) -> Result<ffi::PublicKey> {
        ffi::PublicKey::from_spki_der(&self.spki_der)
            .map_err(|error| map_key_error(error, "SPKI DER"))
    }
}

fn signature_algorithm(algorithm: ffi::KeyAlgorithm) -> SignatureAlgorithm {
    match algorithm {
        ffi::KeyAlgorithm::EcdsaP256Sha256 => SignatureAlgorithm::EcdsaP256Sha256,
        ffi::KeyAlgorithm::EcdsaP384Sha384 => SignatureAlgorithm::EcdsaP384Sha384,
        ffi::KeyAlgorithm::RsaPkcs1Sha256 => SignatureAlgorithm::RsaPkcs1Sha256,
    }
}

fn map_key_error(error: ffi::Error, encoding: &'static str) -> Error {
    match error {
        ffi::Error::InvalidEncoding => Error::InvalidEncoding { encoding },
        ffi::Error::UnsupportedAlgorithm => Error::Unsupported {
            feature: "key algorithm",
        },
        ffi::Error::Allocation
        | ffi::Error::Crypto
        | ffi::Error::UnsupportedNameAttribute
        | ffi::Error::UnsupportedSubjectAltName
        | ffi::Error::Verification => Error::Crypto,
    }
}

#[cfg(test)]
mod tests {
    use super::{PrivateKey, PublicKey, RsaKeySize, SignatureAlgorithm};
    use crate::Error;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn key_types_are_send_and_sync() {
        assert_send_sync::<PrivateKey>();
        assert_send_sync::<PublicKey>();
        assert_send_sync::<crate::ffi::PrivateKey>();
        assert_send_sync::<crate::ffi::PublicKey>();
    }

    #[test]
    fn private_and_public_keys_round_trip() {
        for (key, algorithm) in [
            (
                PrivateKey::generate().unwrap(),
                SignatureAlgorithm::EcdsaP256Sha256,
            ),
            (
                PrivateKey::generate_rsa(RsaKeySize::Bits2048).unwrap(),
                SignatureAlgorithm::RsaPkcs1Sha256,
            ),
        ] {
            assert_eq!(key.algorithm(), algorithm);
            let public_key = key.public_key().unwrap();
            let private_der = key.to_pkcs8_der().unwrap();
            let private_pem = key.to_pkcs8_pem().unwrap();
            for parsed in [
                PrivateKey::from_pkcs8_der(&private_der).unwrap(),
                PrivateKey::from_pkcs8_pem(&private_pem).unwrap(),
            ] {
                assert_eq!(parsed.algorithm(), algorithm);
                assert_eq!(parsed.public_key().unwrap(), public_key);
                let request = crate::CertificateSigningRequest::builder()
                    .build(&parsed)
                    .unwrap();
                assert_eq!(
                    crate::CertificateSigningRequest::from_der(request.as_der())
                        .unwrap()
                        .public_key()
                        .unwrap(),
                    public_key
                );
            }
            for parsed in [
                PublicKey::from_spki_der(public_key.as_spki_der()).unwrap(),
                PublicKey::from_spki_pem(&public_key.to_spki_pem().unwrap()).unwrap(),
            ] {
                assert_eq!(parsed.algorithm(), algorithm);
                assert_eq!(parsed, public_key);
            }
        }
    }

    #[test]
    fn private_key_debug_is_redacted() {
        for key in [
            PrivateKey::generate().unwrap(),
            PrivateKey::generate_rsa(RsaKeySize::Bits2048).unwrap(),
        ] {
            let expected = format!(
                "PrivateKey {{ algorithm: {:?}, private_material: \"[REDACTED]\" }}",
                key.algorithm()
            );
            assert!(
                format!("{key:?}") == expected,
                "private-key Debug output must remain redacted"
            );
        }
    }

    #[test]
    fn reports_invalid_key_encodings() {
        assert!(matches!(
            PrivateKey::from_pkcs8_der(b"not DER"),
            Err(Error::InvalidEncoding {
                encoding: "PKCS#8 DER"
            })
        ));
        assert!(matches!(
            PublicKey::from_spki_pem("not PEM"),
            Err(Error::InvalidEncoding {
                encoding: "SPKI PEM"
            })
        ));
    }
}
