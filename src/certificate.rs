use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    ffi, DistinguishedName, DnsName, Error, PrivateKey, PublicKey, Result, SubjectAltName,
};

/// The validity interval of an X.509 certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validity {
    not_before: SystemTime,
    not_after: SystemTime,
}

impl Validity {
    /// Creates an interval after checking that its bounds are ordered.
    pub fn new(not_before: SystemTime, not_after: SystemTime) -> Result<Self> {
        let not_before = system_time_to_timestamp(not_before)?;
        let not_after = system_time_to_timestamp(not_after)?;
        if not_before > not_after {
            return Err(invalid_input(
                "validity",
                "not_before must not exceed not_after",
            ));
        }
        Ok(Self {
            not_before: timestamp_to_system_time(not_before)?,
            not_after: timestamp_to_system_time(not_after)?,
        })
    }

    /// Returns the inclusive lower validity bound.
    pub fn not_before(&self) -> SystemTime {
        self.not_before
    }

    /// Returns the inclusive upper validity bound.
    pub fn not_after(&self) -> SystemTime {
        self.not_after
    }
}

/// A positive X.509 certificate serial number.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SerialNumber(Vec<u8>);

impl SerialNumber {
    /// Validates big-endian serial-number bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > 20 {
            return Err(invalid_input("serial number", "must contain 1 to 20 bytes"));
        }
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(invalid_input("serial number", "must be positive"));
        }
        if bytes.len() > 1 && bytes[0] == 0 {
            return Err(invalid_input(
                "serial number",
                "must not contain leading zero bytes",
            ));
        }
        if bytes.len() == 20 && bytes[0] & 0x80 != 0 {
            return Err(invalid_input(
                "serial number",
                "positive DER encoding must not exceed 20 bytes",
            ));
        }
        Ok(Self(bytes))
    }

    /// Borrows the unsigned, big-endian serial-number bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// An opinionated certificate extension profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum CertificateProfile {
    /// An end-entity certificate for TLS servers.
    Server,
    /// An end-entity certificate for TLS clients.
    Client,
    /// An end-entity certificate for TLS servers and clients.
    ServerAndClient,
    /// A certificate authority, optionally constrained to a maximum path length.
    CertificateAuthority {
        /// The maximum number of subordinate CA certificates in a valid path.
        path_length: Option<u8>,
    },
}

/// An owned X.509 certificate.
///
/// Accessors such as [`Certificate::subject`] re-parse the certificate on
/// each call; use [`Certificate::details`] to read all supported fields in a
/// single pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    der: Vec<u8>,
}

/// A generated self-signed certificate and its private key.
///
/// This bundle is intended for ephemeral development identities. Persisted or
/// externally managed keys should use [`CertificateBuilder::self_signed`].
#[derive(Debug)]
pub struct SelfSignedCertificate {
    certificate: Certificate,
    private_key: PrivateKey,
}

impl SelfSignedCertificate {
    /// Borrows the generated certificate.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// Borrows the generated private key.
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Separates the bundle into its certificate and private key.
    pub fn into_parts(self) -> (Certificate, PrivateKey) {
        (self.certificate, self.private_key)
    }
}

impl Certificate {
    /// Starts a certificate builder with required fields.
    pub fn builder(
        subject: DistinguishedName,
        validity: Validity,
        profile: CertificateProfile,
    ) -> CertificateBuilder {
        CertificateBuilder::new(subject, validity, profile)
    }

    /// Parses and validates a DER-encoded certificate.
    ///
    /// Signature algorithms must be ECDSA with SHA-256 or SHA-384, or RSA
    /// PKCS#1 v1.5 with SHA-256 or SHA-384. The public key must satisfy the
    /// requirements of [`PublicKey::from_spki_der`]. Distinguished names and
    /// subject alternative names are validated when read.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let certificate = parse_certificate(der)?;
        let der = certificate.to_der().map_err(map_certificate_error)?;
        Ok(Self { der })
    }

    /// Parses and validates a PEM-encoded certificate.
    ///
    /// Applies the same validation as [`Certificate::from_der`].
    /// Requires one header-free `CERTIFICATE` block at the start of the input,
    /// followed only by optional ASCII whitespace.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let certificate = ffi::Certificate::from_pem(pem).map_err(map_certificate_pem_error)?;
        let der = certificate.to_der().map_err(map_certificate_error)?;
        Ok(Self { der })
    }

    /// Borrows the canonical DER encoding.
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// Encodes the certificate as PEM.
    pub fn to_pem(&self) -> Result<String> {
        parse_certificate(&self.der)?
            .to_pem()
            .map_err(map_certificate_pem_error)
    }

    /// Parses a PEM certificate chain bundle into one certificate per block.
    ///
    /// Each block must be a well-formed, header-free `CERTIFICATE` PEM,
    /// separated only by ASCII whitespace. At least one certificate is required,
    /// the first block must start at the beginning of the input, and only ASCII
    /// whitespace may follow the final block.
    /// Each certificate is validated as in [`Certificate::from_pem`].
    ///
    /// This matches the `application/pem-certificate-chain` body an ACME
    /// server returns from its certificate URL (leaf first, then
    /// intermediates); the ordering is preserved but not otherwise enforced.
    pub fn from_pem_chain(pem: &str) -> Result<Vec<Self>> {
        let certificates =
            ffi::Certificate::from_pem_chain(pem).map_err(map_certificate_pem_error)?;
        certificates.iter().map(certificate_from_ffi).collect()
    }

    /// Encodes a slice of certificates as a concatenated PEM chain bundle.
    ///
    /// The certificates appear in slice order; the result parses with
    /// [`Certificate::from_pem_chain`].
    pub fn certificates_to_pem(certificates: &[Certificate]) -> Result<String> {
        let mut output = String::new();
        for certificate in certificates {
            output.push_str(&certificate.to_pem()?);
        }
        Ok(output)
    }

    /// Returns the subject distinguished name.
    pub fn subject(&self) -> Result<DistinguishedName> {
        parse_certificate(&self.der)
            .and_then(|certificate| certificate.subject().map_err(map_certificate_error))
            .and_then(DistinguishedName::from_ffi)
    }

    /// Returns the issuer distinguished name.
    pub fn issuer(&self) -> Result<DistinguishedName> {
        parse_certificate(&self.der)
            .and_then(|certificate| certificate.issuer().map_err(map_certificate_error))
            .and_then(DistinguishedName::from_ffi)
    }

    /// Returns the certificate's subject alternative names.
    pub fn subject_alt_names(&self) -> Result<Vec<SubjectAltName>> {
        parse_certificate(&self.der)?
            .subject_alt_names()
            .map_err(map_certificate_error)?
            .into_iter()
            .map(SubjectAltName::from_ffi)
            .collect()
    }

    /// Returns the certificate's public key.
    pub fn public_key(&self) -> Result<PublicKey> {
        public_key_from_ffi(&parse_certificate(&self.der)?)
    }

    /// Returns the certificate validity interval.
    pub fn validity(&self) -> Result<Validity> {
        let (not_before, not_after) = parse_certificate(&self.der)?
            .validity()
            .map_err(map_certificate_error)?;
        Validity::new(
            timestamp_to_system_time(not_before)?,
            timestamp_to_system_time(not_after)?,
        )
    }

    /// Returns the certificate serial number.
    pub fn serial_number(&self) -> Result<SerialNumber> {
        serial_number_from_ffi(&parse_certificate(&self.der)?)
    }

    /// Parses the certificate once and returns all supported fields.
    ///
    /// Reading several fields from the returned snapshot is cheaper than
    /// calling the individual accessors, each of which re-parses the
    /// certificate.
    pub fn details(&self) -> Result<CertificateDetails> {
        let certificate = parse_certificate(&self.der)?;
        let subject = certificate.subject().map_err(map_certificate_error)?;
        let issuer = certificate.issuer().map_err(map_certificate_error)?;
        let subject_alt_names = certificate
            .subject_alt_names()
            .map_err(map_certificate_error)?
            .into_iter()
            .map(SubjectAltName::from_ffi)
            .collect::<Result<Vec<_>>>()?;
        let (not_before, not_after) = certificate.validity().map_err(map_certificate_error)?;
        Ok(CertificateDetails {
            subject: DistinguishedName::from_ffi(subject)?,
            issuer: DistinguishedName::from_ffi(issuer)?,
            subject_alt_names,
            public_key: public_key_from_ffi(&certificate)?,
            validity: Validity::new(
                timestamp_to_system_time(not_before)?,
                timestamp_to_system_time(not_after)?,
            )?,
            serial_number: serial_number_from_ffi(&certificate)?,
        })
    }

    /// Verifies the certificate signature using an issuer public key.
    pub fn verify_signature(&self, issuer_key: &PublicKey) -> Result<()> {
        let certificate = parse_certificate(&self.der)?;
        let issuer_key = issuer_key.to_ffi()?;
        certificate
            .verify_signature(&issuer_key)
            .map_err(map_certificate_error)
    }

    pub(crate) fn to_ffi(&self) -> Result<ffi::Certificate> {
        parse_certificate(&self.der)
    }
}

/// The supported fields of an X.509 certificate, parsed in one pass.
///
/// Returned by [`Certificate::details`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateDetails {
    subject: DistinguishedName,
    issuer: DistinguishedName,
    subject_alt_names: Vec<SubjectAltName>,
    public_key: PublicKey,
    validity: Validity,
    serial_number: SerialNumber,
}

impl CertificateDetails {
    /// Returns the subject distinguished name.
    pub fn subject(&self) -> &DistinguishedName {
        &self.subject
    }

    /// Returns the issuer distinguished name.
    pub fn issuer(&self) -> &DistinguishedName {
        &self.issuer
    }

    /// Returns the certificate's subject alternative names.
    pub fn subject_alt_names(&self) -> &[SubjectAltName] {
        &self.subject_alt_names
    }

    /// Returns the certificate's public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the certificate validity interval.
    pub fn validity(&self) -> Validity {
        self.validity
    }

    /// Returns the certificate serial number.
    pub fn serial_number(&self) -> &SerialNumber {
        &self.serial_number
    }
}

/// Builds a certificate using a constrained set of secure extension profiles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateBuilder {
    subject: DistinguishedName,
    validity: Validity,
    profile: CertificateProfile,
    serial_number: Option<SerialNumber>,
    subject_alt_names: Vec<SubjectAltName>,
}

impl CertificateBuilder {
    /// Creates a builder with required certificate fields.
    pub fn new(
        subject: DistinguishedName,
        validity: Validity,
        profile: CertificateProfile,
    ) -> Self {
        Self {
            subject,
            validity,
            profile,
            serial_number: None,
            subject_alt_names: Vec::new(),
        }
    }

    /// Uses a caller-provided serial number instead of generating one.
    pub fn serial_number(mut self, serial_number: SerialNumber) -> Self {
        self.serial_number = Some(serial_number);
        self
    }

    /// Appends a subject alternative name.
    pub fn subject_alt_name(mut self, name: SubjectAltName) -> Self {
        self.subject_alt_names.push(name);
        self
    }

    /// Appends a validated DNS subject alternative name.
    pub fn dns_name(self, name: DnsName) -> Self {
        self.subject_alt_name(SubjectAltName::Dns(name))
    }

    /// Appends an IP address subject alternative name.
    pub fn ip_address(self, address: IpAddr) -> Self {
        self.subject_alt_name(SubjectAltName::Ip(address))
    }

    /// Generates a private key and issues a self-signed certificate with it.
    pub fn generate_self_signed(self) -> Result<SelfSignedCertificate> {
        let private_key = PrivateKey::generate()?;
        let certificate = self.self_signed(&private_key)?;
        Ok(SelfSignedCertificate {
            certificate,
            private_key,
        })
    }

    /// Issues a self-signed certificate using a caller-provided private key.
    pub fn self_signed(self, key: &PrivateKey) -> Result<Certificate> {
        let subject = self.subject.to_ffi()?;
        let subject_alt_names = self.subject_alt_names_ffi();
        let params = self.ffi_params(&subject, &subject_alt_names)?;
        let certificate =
            ffi::Certificate::self_signed(params, key.as_ffi()).map_err(map_certificate_error)?;
        certificate_from_ffi(&certificate)
    }

    /// Issues a certificate for `subject_key` using a capable issuer certificate and key.
    ///
    /// The issuer must be a certificate authority, its key usage must permit
    /// certificate signing when present, and its path-length constraint must
    /// permit issuing a subordinate CA.
    ///
    /// The issuer may be generated in memory or loaded from an existing CA
    /// certificate and PKCS#8 private key with [`Certificate::from_pem`] and
    /// [`PrivateKey::from_pkcs8_pem`].
    pub fn signed_by(
        self,
        subject_key: &PublicKey,
        issuer: &Certificate,
        issuer_key: &PrivateKey,
    ) -> Result<Certificate> {
        if issuer.public_key()? != issuer_key.public_key()? {
            return Err(invalid_input(
                "issuer key",
                "does not match the issuer certificate",
            ));
        }
        let issuer = parse_certificate(issuer.as_der())?;
        let subordinate_ca = matches!(
            self.profile,
            CertificateProfile::CertificateAuthority { .. }
        );
        if !issuer.can_issue(subordinate_ca) {
            return Err(invalid_input(
                "issuer certificate",
                "is not authorized to issue the requested certificate",
            ));
        }
        let subject = self.subject.to_ffi()?;
        let subject_alt_names = self.subject_alt_names_ffi();
        let params = self.ffi_params(&subject, &subject_alt_names)?;
        let subject_key = subject_key.to_ffi()?;
        let certificate =
            ffi::Certificate::signed_by(params, &subject_key, &issuer, issuer_key.as_ffi())
                .map_err(map_certificate_error)?;
        certificate_from_ffi(&certificate)
    }

    fn subject_alt_names_ffi(&self) -> Vec<ffi::SubjectAlternativeName> {
        self.subject_alt_names
            .iter()
            .map(SubjectAltName::to_ffi)
            .collect()
    }

    fn ffi_params<'a>(
        &'a self,
        subject: &'a ffi::DistinguishedName,
        subject_alt_names: &'a [ffi::SubjectAlternativeName],
    ) -> Result<ffi::x509::CertificateParams<'a>> {
        if self.subject.entries().len() == 0 {
            if matches!(
                self.profile,
                CertificateProfile::CertificateAuthority { .. }
            ) {
                return Err(invalid_input(
                    "subject",
                    "certificate authorities require a non-empty subject",
                ));
            }
            if subject_alt_names.is_empty() {
                return Err(invalid_input(
                    "subject",
                    "an empty subject requires at least one subject alternative name",
                ));
            }
        }
        Ok(ffi::x509::CertificateParams {
            subject,
            not_before: system_time_to_timestamp(self.validity.not_before)?,
            not_after: system_time_to_timestamp(self.validity.not_after)?,
            serial_number: self.serial_number.as_ref().map(SerialNumber::as_bytes),
            subject_alt_names,
            profile: match self.profile {
                CertificateProfile::Server => ffi::x509::CertificateProfile::Server,
                CertificateProfile::Client => ffi::x509::CertificateProfile::Client,
                CertificateProfile::ServerAndClient => {
                    ffi::x509::CertificateProfile::ServerAndClient
                }
                CertificateProfile::CertificateAuthority { path_length } => {
                    ffi::x509::CertificateProfile::CertificateAuthority { path_length }
                }
            },
        })
    }
}

fn parse_certificate(der: &[u8]) -> Result<ffi::Certificate> {
    ffi::Certificate::from_der(der).map_err(map_certificate_error)
}

fn public_key_from_ffi(certificate: &ffi::Certificate) -> Result<PublicKey> {
    let key = certificate.public_key().map_err(map_certificate_error)?;
    let der = key.to_spki_der().map_err(map_certificate_error)?;
    PublicKey::from_spki_der(&der)
}

fn serial_number_from_ffi(certificate: &ffi::Certificate) -> Result<SerialNumber> {
    let bytes = certificate.serial_number().map_err(map_certificate_error)?;
    SerialNumber::new(bytes).map_err(|_| Error::InvalidEncoding {
        encoding: "X.509 certificate serial number",
    })
}

fn certificate_from_ffi(certificate: &ffi::Certificate) -> Result<Certificate> {
    certificate
        .to_der()
        .map(|der| Certificate { der })
        .map_err(map_certificate_error)
}

fn map_certificate_error(error: ffi::Error) -> Error {
    match error {
        ffi::Error::InvalidEncoding => Error::InvalidEncoding {
            encoding: "X.509 DER",
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
        ffi::Error::Verification => Error::Verification,
        ffi::Error::Allocation | ffi::Error::Crypto => Error::Crypto,
    }
}

fn map_certificate_pem_error(error: ffi::Error) -> Error {
    match error {
        ffi::Error::InvalidEncoding => Error::InvalidEncoding {
            encoding: "X.509 PEM",
        },
        error => map_certificate_error(error),
    }
}

pub(crate) fn system_time_to_timestamp(time: SystemTime) -> Result<i64> {
    let timestamp = match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::from(duration.as_secs()),
        Err(error) => {
            let duration = error.duration();
            -i128::from(duration.as_secs()) - i128::from(duration.subsec_nanos() != 0)
        }
    };
    i64::try_from(timestamp)
        .map_err(|_| invalid_input("validity", "time is outside the supported range"))
}

fn timestamp_to_system_time(timestamp: i64) -> Result<SystemTime> {
    let duration = Duration::from_secs(timestamp.unsigned_abs());
    let time = if timestamp >= 0 {
        UNIX_EPOCH.checked_add(duration)
    } else {
        UNIX_EPOCH.checked_sub(duration)
    };
    time.ok_or_else(|| invalid_input("validity", "time is outside the supported range"))
}

fn invalid_input(field: &'static str, reason: &str) -> Error {
    Error::InvalidInput {
        field,
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, UNIX_EPOCH};

    use super::{Certificate, CertificateProfile, SerialNumber, Validity};
    use crate::{
        CertificateVerifier, DistinguishedName, DnsName, Error, PrivateKey, RsaKeySize,
        SubjectAltName, VerificationOptions, VerificationPurpose,
    };

    // Test-only CA generated with LibreSSL, an independent implementation.
    const OPENSSL_CA_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBYjCCAQigAwIBAgIJANWygVGoL0iVMAoGCCqGSM49BAMCMCQxIjAgBgNVBAMM\n\
GWNlcnR1dGlscyBJbnRlcm9wIFRlc3QgQ0EwHhcNMjYwOTE2MDIzMDAyWhcNMzYw\n\
OTEzMDIzMDAyWjAkMSIwIAYDVQQDDBljZXJ0dXRpbHMgSW50ZXJvcCBUZXN0IENB\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY+uYXt9+foU3q/GQIvTK/RgZ2TJc\n\
hUAKQLMZ+vJSa5FM5U93sA+rU5AS4lkQiQbX4/np4rqV9wSy+PYej0hSyaMjMCEw\n\
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAw\n\
RQIgT0fV1145TVtL5O8qUvk0WfyE/82t9XEKVUF8eKbS32wCIQDE4pbKuo5Ir51g\n\
dB2uVS88XY8IDP9e60omlOXI37JzoQ==\n\
-----END CERTIFICATE-----\n";

    // Test-only PKCS#8 key for `OPENSSL_CA_CERTIFICATE`.
    const OPENSSL_CA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2mpOOCkX/OonrPFN\n\
nyw/slv7SLiVbvGtXn7x45f5EmehRANCAARj65he335+hTer8ZAi9Mr9GBnZMlyF\n\
QApAsxn68lJrkUzlT3ewD6tTkBLiWRCJBtfj+eniupX3BLL49h6PSFLJ\n\
-----END PRIVATE KEY-----\n";

    #[test]
    fn validates_validity_bounds() {
        assert!(matches!(
            Validity::new(UNIX_EPOCH + Duration::from_secs(2), UNIX_EPOCH),
            Err(Error::InvalidInput {
                field: "validity",
                ..
            })
        ));
        for (start, end) in [
            (UNIX_EPOCH, UNIX_EPOCH),
            (
                UNIX_EPOCH - Duration::from_secs(2),
                UNIX_EPOCH - Duration::from_secs(1),
            ),
            (
                UNIX_EPOCH - Duration::from_secs(1),
                UNIX_EPOCH + Duration::from_secs(1),
            ),
        ] {
            let validity = Validity::new(start, end).unwrap();
            assert_eq!(validity.not_before(), start);
            assert_eq!(validity.not_after(), end);
        }
    }

    #[test]
    fn validates_serial_number_encoding_boundaries() {
        for bytes in [
            vec![],
            vec![0],
            vec![0; 20],
            vec![0, 1],
            vec![1; 21],
            vec![0x80; 20],
        ] {
            assert!(matches!(
                SerialNumber::new(bytes),
                Err(Error::InvalidInput {
                    field: "serial number",
                    ..
                })
            ));
        }
        let key = PrivateKey::generate().unwrap();
        let builder = Certificate::builder(
            DistinguishedName::builder()
                .common_name("Serial test")
                .build()
                .unwrap(),
            Validity::new(UNIX_EPOCH, UNIX_EPOCH + Duration::from_secs(1)).unwrap(),
            CertificateProfile::Server,
        );
        for bytes in [vec![1], vec![0x80], vec![0xff; 19], vec![0x7f; 20]] {
            let serial = SerialNumber::new(bytes.clone()).unwrap();
            assert_eq!(serial.as_bytes(), bytes);
            let certificate = builder
                .clone()
                .serial_number(serial.clone())
                .self_signed(&key)
                .unwrap();
            let parsed = Certificate::from_der(certificate.as_der()).unwrap();
            assert_eq!(parsed.serial_number().unwrap(), serial);
            parsed.verify_signature(&key.public_key().unwrap()).unwrap();
        }
    }

    #[test]
    fn builds_and_reads_a_self_signed_certificate() {
        let subject = DistinguishedName::builder()
            .common_name("localhost")
            .build()
            .unwrap();
        let validity = Validity::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        )
        .unwrap();
        let identity = Certificate::builder(subject.clone(), validity, CertificateProfile::Server)
            .serial_number(SerialNumber::new([1]).unwrap())
            .dns_name(DnsName::new("localhost").unwrap())
            .generate_self_signed()
            .unwrap();
        let certificate = identity.certificate();

        certificate
            .verify_signature(&identity.private_key().public_key().unwrap())
            .unwrap();
        assert_eq!(certificate.subject().unwrap(), subject);
        assert_eq!(certificate.issuer().unwrap(), subject);
        assert_eq!(certificate.validity().unwrap(), validity);
        assert_eq!(certificate.serial_number().unwrap().as_bytes(), &[1]);
        let pem = certificate.to_pem().unwrap();
        assert_eq!(Certificate::from_pem(&pem).unwrap(), *certificate);
    }

    #[test]
    fn reads_all_fields_in_one_pass() {
        let subject = DistinguishedName::builder()
            .common_name("localhost")
            .build()
            .unwrap();
        let validity = Validity::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        )
        .unwrap();
        let names = vec![
            SubjectAltName::Dns(DnsName::new("localhost").unwrap()),
            SubjectAltName::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        let identity = Certificate::builder(subject.clone(), validity, CertificateProfile::Server)
            .serial_number(SerialNumber::new([0x01, 0x02]).unwrap())
            .subject_alt_name(names[0].clone())
            .subject_alt_name(names[1].clone())
            .generate_self_signed()
            .unwrap();

        let details = identity.certificate().details().unwrap();
        assert_eq!(details.subject(), &subject);
        assert_eq!(details.issuer(), &subject);
        assert_eq!(details.subject_alt_names(), names.as_slice());
        assert_eq!(
            details.public_key(),
            &identity.private_key().public_key().unwrap()
        );
        assert_eq!(details.validity(), validity);
        assert_eq!(details.serial_number().as_bytes(), &[0x01, 0x02]);
    }

    #[test]
    fn issues_a_certificate_from_an_openssl_ca() {
        let issuer = Certificate::from_pem(OPENSSL_CA_CERTIFICATE).unwrap();
        let issuer_key = PrivateKey::from_pkcs8_pem(OPENSSL_CA_PRIVATE_KEY).unwrap();
        assert_eq!(
            issuer.public_key().unwrap(),
            issuer_key.public_key().unwrap()
        );

        let validity = Validity::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        )
        .unwrap();
        let leaf_key = PrivateKey::generate().unwrap();
        let builder = Certificate::builder(
            DistinguishedName::builder()
                .common_name("leaf.example")
                .build()
                .unwrap(),
            validity,
            CertificateProfile::Server,
        )
        .dns_name(DnsName::new("leaf.example").unwrap());
        assert!(matches!(
            builder
                .clone()
                .signed_by(&leaf_key.public_key().unwrap(), &issuer, &leaf_key),
            Err(Error::InvalidInput {
                field: "issuer key",
                ..
            })
        ));
        let leaf = builder
            .signed_by(&leaf_key.public_key().unwrap(), &issuer, &issuer_key)
            .unwrap();

        leaf.verify_signature(&issuer_key.public_key().unwrap())
            .unwrap();
        assert_eq!(leaf.issuer().unwrap(), issuer.subject().unwrap());

        let options = VerificationOptions::new(VerificationPurpose::TlsServer)
            .at_time(UNIX_EPOCH + Duration::from_secs(1_795_000_000))
            .subject(SubjectAltName::Dns(DnsName::new("leaf.example").unwrap()));
        CertificateVerifier::new([issuer])
            .verify(&leaf, &[], &options)
            .unwrap();
    }

    #[test]
    fn round_trips_a_pem_certificate_chain() {
        let ca = Certificate::from_pem(OPENSSL_CA_CERTIFICATE).unwrap();
        let ca_key = PrivateKey::from_pkcs8_pem(OPENSSL_CA_PRIVATE_KEY).unwrap();
        let validity = Validity::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        )
        .unwrap();
        let leaf_key = PrivateKey::generate().unwrap();
        let leaf = Certificate::builder(
            DistinguishedName::builder()
                .common_name("leaf.example")
                .build()
                .unwrap(),
            validity,
            CertificateProfile::Server,
        )
        .dns_name(DnsName::new("leaf.example").unwrap())
        .signed_by(&leaf_key.public_key().unwrap(), &ca, &ca_key)
        .unwrap();

        // Leaf first, then the CA, as in an ACME certificate download.
        let chain = Certificate::certificates_to_pem(&[leaf.clone(), ca.clone()]).unwrap();
        let parsed = Certificate::from_pem_chain(&chain).unwrap();
        assert_eq!(parsed, vec![leaf, ca]);

        // A single certificate is a valid one-element chain.
        assert_eq!(
            Certificate::from_pem_chain(OPENSSL_CA_CERTIFICATE).unwrap(),
            vec![Certificate::from_pem(OPENSSL_CA_CERTIFICATE).unwrap()]
        );

        // Empty, non-certificate, and truncated bundles are rejected.
        assert!(Certificate::from_pem_chain("").is_err());
        assert!(Certificate::from_pem_chain("not PEM").is_err());
        let mut truncated = chain.clone();
        truncated.truncate(truncated.len() - 10);
        assert!(Certificate::from_pem_chain(&truncated).is_err());
    }

    #[test]
    fn builds_and_reads_an_rsa_self_signed_certificate() {
        let key = PrivateKey::generate_rsa(RsaKeySize::Bits2048).unwrap();
        let subject = DistinguishedName::builder()
            .common_name("localhost")
            .build()
            .unwrap();
        let validity = Validity::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        )
        .unwrap();
        let certificate = Certificate::builder(subject, validity, CertificateProfile::Server)
            .dns_name(DnsName::new("localhost").unwrap())
            .self_signed(&key)
            .unwrap();

        let parsed = Certificate::from_der(certificate.as_der()).unwrap();
        assert_eq!(parsed.public_key().unwrap(), key.public_key().unwrap());
        parsed.verify_signature(&key.public_key().unwrap()).unwrap();
    }

    #[test]
    fn rejects_invalid_issuance_profiles() {
        let validity = Validity::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        )
        .unwrap();
        let empty_subject = DistinguishedName::builder().build().unwrap();
        assert!(matches!(
            Certificate::builder(empty_subject, validity, CertificateProfile::Server)
                .generate_self_signed(),
            Err(Error::InvalidInput {
                field: "subject",
                ..
            })
        ));
        assert!(matches!(
            Certificate::builder(
                DistinguishedName::builder().build().unwrap(),
                validity,
                CertificateProfile::CertificateAuthority { path_length: None },
            )
            .dns_name(DnsName::new("ca.example").unwrap())
            .generate_self_signed(),
            Err(Error::InvalidInput {
                field: "subject",
                ..
            })
        ));

        let issuer_key = PrivateKey::generate().unwrap();
        let non_ca = Certificate::builder(
            DistinguishedName::builder()
                .common_name("Not a CA")
                .build()
                .unwrap(),
            validity,
            CertificateProfile::Server,
        )
        .self_signed(&issuer_key)
        .unwrap();
        let subject_key = PrivateKey::generate().unwrap().public_key().unwrap();
        assert!(matches!(
            Certificate::builder(
                DistinguishedName::builder()
                    .common_name("Leaf")
                    .build()
                    .unwrap(),
                validity,
                CertificateProfile::Server,
            )
            .signed_by(&subject_key, &non_ca, &issuer_key),
            Err(Error::InvalidInput {
                field: "issuer certificate",
                ..
            })
        ));

        let ca = Certificate::builder(
            DistinguishedName::builder()
                .common_name("Path Length Zero CA")
                .build()
                .unwrap(),
            validity,
            CertificateProfile::CertificateAuthority {
                path_length: Some(0),
            },
        )
        .self_signed(&issuer_key)
        .unwrap();
        assert!(matches!(
            Certificate::builder(
                DistinguishedName::builder()
                    .common_name("Subordinate CA")
                    .build()
                    .unwrap(),
                validity,
                CertificateProfile::CertificateAuthority { path_length: None },
            )
            .signed_by(&subject_key, &ca, &issuer_key),
            Err(Error::InvalidInput {
                field: "issuer certificate",
                ..
            })
        ));
    }
}
