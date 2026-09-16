use std::net::IpAddr;
use std::time::SystemTime;

use crate::certificate::system_time_to_timestamp;
use crate::{ffi, Certificate, Error, Result, SubjectAltName};

/// The intended use of the certificate being verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VerificationPurpose {
    /// Validates a chain without endpoint key usage or EKU checks.
    ///
    /// This is not sufficient for TLS authentication. The caller is responsible
    /// for deciding whether the certificate is authorized for its intended use.
    ChainOnly,
    /// Validates a non-CA TLS server certificate and its chain's applicable
    /// key usage and server-authentication EKU restrictions.
    ///
    /// A concrete DNS name or IP address must be supplied with
    /// [`VerificationOptions::subject`].
    TlsServer,
    /// Validates a non-CA TLS client certificate and its chain's applicable
    /// key usage and client-authentication EKU restrictions.
    ///
    /// Name matching is optional; client authorization remains the caller's
    /// responsibility.
    TlsClient,
}

/// Options applied while validating a certificate chain.
///
/// Purpose must be selected explicitly; there is no default authentication policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationOptions {
    purpose: VerificationPurpose,
    time: Option<SystemTime>,
    subject: Option<SubjectAltName>,
}

impl VerificationOptions {
    /// Creates options for an explicit purpose at the current time.
    ///
    /// TLS server verification also requires [`Self::subject`].
    pub fn new(purpose: VerificationPurpose) -> Self {
        Self {
            purpose,
            time: None,
            subject: None,
        }
    }

    /// Overrides the verification time.
    pub fn at_time(mut self, time: SystemTime) -> Self {
        self.time = Some(time);
        self
    }

    /// Requires the end-entity certificate to match a DNS name or IP address.
    ///
    /// DNS reference names must be concrete, without wildcards; IP addresses
    /// must use [`SubjectAltName::Ip`]. Matching uses SANs only, never the common
    /// name, and permits only whole-label certificate wildcards.
    pub fn subject(mut self, subject: SubjectAltName) -> Self {
        self.subject = Some(subject);
        self
    }
}

/// Verifies certificate chains against explicit trust anchors.
///
/// This does not perform a TLS handshake, revocation or certificate-transparency
/// checks, fetch certificates, or load system trust roots. TLS applications must
/// also enforce their protocol and authorization requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateVerifier {
    trust_anchors: Vec<Certificate>,
}

impl CertificateVerifier {
    /// Creates a verifier from explicit trust anchors.
    pub fn new(trust_anchors: impl IntoIterator<Item = Certificate>) -> Self {
        Self {
            trust_anchors: trust_anchors.into_iter().collect(),
        }
    }

    /// Verifies an end-entity certificate and any supplied intermediates.
    pub fn verify(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        options: &VerificationOptions,
    ) -> Result<()> {
        if options.purpose == VerificationPurpose::TlsServer && options.subject.is_none() {
            return Err(Error::InvalidInput {
                field: "verification subject",
                reason: "TLS server verification requires a DNS name or IP address".to_owned(),
            });
        }
        if let Some(SubjectAltName::Dns(name)) = &options.subject {
            if name.as_str().contains('*') || name.as_str().parse::<IpAddr>().is_ok() {
                return Err(Error::InvalidInput {
                    field: "verification subject",
                    reason: "use a concrete DNS name, or the IP variant for an IP address"
                        .to_owned(),
                });
            }
        }
        let end_entity = end_entity.to_ffi()?;
        let intermediates = intermediates
            .iter()
            .map(Certificate::to_ffi)
            .collect::<Result<Vec<_>>>()?;
        let trust_anchors = self
            .trust_anchors
            .iter()
            .map(Certificate::to_ffi)
            .collect::<Result<Vec<_>>>()?;
        let time = options.time.map(system_time_to_timestamp).transpose()?;
        let subject = options.subject.as_ref().map(|subject| match subject {
            SubjectAltName::Dns(name) => ffi::verify::VerificationSubject::Dns(name.as_str()),
            SubjectAltName::Ip(address) => ffi::verify::VerificationSubject::Ip(*address),
        });

        let purpose = match options.purpose {
            VerificationPurpose::ChainOnly => ffi::verify::Purpose::ChainOnly,
            VerificationPurpose::TlsServer => ffi::verify::Purpose::TlsServer,
            VerificationPurpose::TlsClient => ffi::verify::Purpose::TlsClient,
        };
        ffi::verify::verify_chain(
            &end_entity,
            &intermediates,
            &trust_anchors,
            time,
            subject,
            purpose,
        )
        .map_err(map_verification_error)
    }
}

fn map_verification_error(error: ffi::Error) -> Error {
    match error {
        ffi::Error::Verification => Error::Verification,
        ffi::Error::InvalidEncoding => Error::InvalidEncoding {
            encoding: "X.509 certificate",
        },
        ffi::Error::UnsupportedAlgorithm => Error::Unsupported {
            feature: "signature algorithm",
        },
        ffi::Error::UnsupportedNameAttribute => Error::Unsupported {
            feature: "distinguished-name attribute",
        },
        ffi::Error::UnsupportedSubjectAltName => Error::Unsupported {
            feature: "subject alternative name",
        },
        ffi::Error::Allocation | ffi::Error::Crypto => Error::Crypto,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::{CertificateVerifier, VerificationOptions, VerificationPurpose};
    use crate::{
        Certificate, CertificateProfile, DistinguishedName, DnsName, PrivateKey, RsaKeySize,
        Validity,
    };

    #[test]
    fn enforces_verification_purposes() {
        let validity = Validity::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        )
        .unwrap();
        let issuer_key = PrivateKey::generate().unwrap();
        let issuer = Certificate::builder(
            DistinguishedName::builder()
                .common_name("Purpose test CA")
                .build()
                .unwrap(),
            validity,
            CertificateProfile::CertificateAuthority { path_length: None },
        )
        .self_signed(&issuer_key)
        .unwrap();
        let verifier = CertificateVerifier::new([issuer.clone()]);
        let key = PrivateKey::generate().unwrap();
        let name = crate::SubjectAltName::Dns(DnsName::new("service.example.com").unwrap());
        for (profile, server, client) in [
            (CertificateProfile::Server, true, false),
            (CertificateProfile::Client, false, true),
            (CertificateProfile::ServerAndClient, true, true),
            (
                CertificateProfile::CertificateAuthority {
                    path_length: Some(0),
                },
                false,
                false,
            ),
        ] {
            let certificate = Certificate::builder(
                DistinguishedName::builder()
                    .common_name("Endpoint")
                    .build()
                    .unwrap(),
                validity,
                profile,
            )
            .subject_alt_name(name.clone())
            .signed_by(&key.public_key().unwrap(), &issuer, &issuer_key)
            .unwrap();
            for (purpose, expected) in [
                (VerificationPurpose::ChainOnly, true),
                (VerificationPurpose::TlsServer, server),
                (VerificationPurpose::TlsClient, client),
            ] {
                let options = VerificationOptions::new(purpose)
                    .at_time(UNIX_EPOCH + Duration::from_secs(1_750_000_000))
                    .subject(name.clone());
                let result = verifier.verify(&certificate, &[], &options);
                if expected {
                    result.unwrap();
                } else {
                    assert!(
                        matches!(result, Err(crate::Error::Verification)),
                        "{profile:?} must be rejected for {purpose:?}"
                    );
                }
            }
            for (purpose, expected) in [
                (VerificationPurpose::ChainOnly, true),
                (VerificationPurpose::TlsClient, client),
            ] {
                let options = VerificationOptions::new(purpose)
                    .at_time(UNIX_EPOCH + Duration::from_secs(1_750_000_000));
                let result = verifier.verify(&certificate, &[], &options);
                if expected {
                    result.unwrap();
                } else {
                    assert!(
                        matches!(result, Err(crate::Error::Verification)),
                        "{profile:?} must be rejected for {purpose:?} without a subject"
                    );
                }
            }
        }
    }

    fn test_server_chain() -> (CertificateVerifier, Certificate, VerificationOptions) {
        let validity = Validity::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        )
        .unwrap();
        let ca_key = PrivateKey::generate().unwrap();
        let ca_subject = DistinguishedName::builder()
            .common_name("Test CA")
            .build()
            .unwrap();
        let ca = Certificate::builder(
            ca_subject,
            validity,
            CertificateProfile::CertificateAuthority {
                path_length: Some(0),
            },
        )
        .self_signed(&ca_key)
        .unwrap();

        let leaf_key = PrivateKey::generate().unwrap();
        let leaf = Certificate::builder(
            DistinguishedName::builder()
                .common_name("localhost")
                .build()
                .unwrap(),
            validity,
            CertificateProfile::Server,
        )
        .dns_name(DnsName::new("localhost").unwrap())
        .signed_by(&leaf_key.public_key().unwrap(), &ca, &ca_key)
        .unwrap();
        let options = VerificationOptions::new(VerificationPurpose::TlsServer)
            .at_time(UNIX_EPOCH + Duration::from_secs(1_750_000_000))
            .subject(crate::SubjectAltName::Dns(
                DnsName::new("localhost").unwrap(),
            ));

        let verifier = CertificateVerifier::new([ca]);
        verifier.verify(&leaf, &[], &options).unwrap();
        (verifier, leaf, options)
    }

    #[test]
    fn verifies_only_trusted_matching_current_certificates() {
        let (verifier, leaf, options) = test_server_chain();
        let validity = leaf.validity().unwrap();
        for time in [
            validity.not_before(),
            validity.not_after() - Duration::from_secs(1),
        ] {
            verifier
                .verify(&leaf, &[], &options.clone().at_time(time))
                .unwrap();
        }
        for time in [
            validity.not_before() - Duration::from_secs(1),
            validity.not_after() + Duration::from_secs(1),
        ] {
            assert!(
                matches!(
                    verifier.verify(&leaf, &[], &options.clone().at_time(time)),
                    Err(crate::Error::Verification)
                ),
                "certificate must be rejected at {time:?}"
            );
        }
        let wrong_name = options.clone().subject(crate::SubjectAltName::Dns(
            DnsName::new("other.example").unwrap(),
        ));
        assert!(matches!(
            verifier.verify(&leaf, &[], &wrong_name),
            Err(crate::Error::Verification)
        ));
        assert!(matches!(
            CertificateVerifier::new([]).verify(&leaf, &[], &options),
            Err(crate::Error::Verification)
        ));

        let other_ca = Certificate::builder(
            DistinguishedName::builder()
                .common_name("Test CA")
                .build()
                .unwrap(),
            validity,
            CertificateProfile::CertificateAuthority {
                path_length: Some(0),
            },
        )
        .generate_self_signed()
        .unwrap();
        assert!(matches!(
            CertificateVerifier::new([other_ca.certificate().clone()]).verify(&leaf, &[], &options),
            Err(crate::Error::Verification)
        ));
    }

    #[test]
    fn rejects_invalid_server_reference_identities() {
        let (verifier, leaf, _) = test_server_chain();
        let options = VerificationOptions::new(VerificationPurpose::TlsServer)
            .at_time(UNIX_EPOCH + Duration::from_secs(1_750_000_000));
        for options in [
            options.clone(),
            options.clone().subject(crate::SubjectAltName::Dns(
                DnsName::new("*.example.com").unwrap(),
            )),
            options.subject(crate::SubjectAltName::Dns(
                DnsName::new("127.0.0.1").unwrap(),
            )),
        ] {
            assert!(matches!(
                verifier.verify(&leaf, &[], &options),
                Err(crate::Error::InvalidInput {
                    field: "verification subject",
                    ..
                })
            ));
        }
    }

    #[test]
    fn verifies_a_certificate_signed_by_an_rsa_issuer() {
        let validity = Validity::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        )
        .unwrap();
        let ca_key = PrivateKey::generate_rsa(RsaKeySize::Bits2048).unwrap();
        let ca = Certificate::builder(
            DistinguishedName::builder()
                .common_name("RSA Test CA")
                .build()
                .unwrap(),
            validity,
            CertificateProfile::CertificateAuthority { path_length: None },
        )
        .self_signed(&ca_key)
        .unwrap();
        let leaf_key = PrivateKey::generate().unwrap();
        let leaf = Certificate::builder(
            DistinguishedName::builder()
                .common_name("localhost")
                .build()
                .unwrap(),
            validity,
            CertificateProfile::Server,
        )
        .dns_name(DnsName::new("localhost").unwrap())
        .signed_by(&leaf_key.public_key().unwrap(), &ca, &ca_key)
        .unwrap();
        let options = VerificationOptions::new(VerificationPurpose::TlsServer)
            .at_time(UNIX_EPOCH + Duration::from_secs(1_750_000_000))
            .subject(crate::SubjectAltName::Dns(
                DnsName::new("localhost").unwrap(),
            ));

        CertificateVerifier::new([ca])
            .verify(&leaf, &[], &options)
            .unwrap();
    }
}
