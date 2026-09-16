use std::net::IpAddr;

use crate::{
    ffi, DistinguishedName, DnsName, Error, PrivateKey, PublicKey, Result, SubjectAltName,
};

/// An owned, signed PKCS#10 certificate signing request.
///
/// Accessors re-parse the request on each call; use
/// [`CertificateSigningRequest::details`] to read all supported fields in a
/// single pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateSigningRequest {
    der: Vec<u8>,
}

impl CertificateSigningRequest {
    /// Starts a certificate signing request builder.
    pub fn builder() -> CertificateSigningRequestBuilder {
        CertificateSigningRequestBuilder::default()
    }

    /// Parses a DER-encoded request and verifies its signature.
    ///
    /// The signature algorithm must be ECDSA with SHA-256 or SHA-384, or RSA
    /// PKCS#1 v1.5 with SHA-256 or SHA-384.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let request = parse_request(der)?;
        request.verify_signature().map_err(map_csr_error)?;
        let der = request.to_der().map_err(map_csr_error)?;
        Ok(Self { der })
    }

    /// Parses a PEM-encoded request and verifies its signature.
    ///
    /// Applies the same signature-algorithm policy as
    /// [`CertificateSigningRequest::from_der`].
    /// Requires one header-free `CERTIFICATE REQUEST` block at the start of
    /// the input, followed only by optional ASCII whitespace. The decoded
    /// payload must contain exactly one DER request.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let request = ffi::CertificateRequest::from_pem(pem).map_err(map_csr_pem_error)?;
        request.verify_signature().map_err(map_csr_error)?;
        let der = request.to_der().map_err(map_csr_error)?;
        Ok(Self { der })
    }

    /// Borrows the canonical DER encoding.
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// Encodes the request as PEM.
    pub fn to_pem(&self) -> Result<String> {
        parse_request(&self.der)?
            .to_pem()
            .map_err(map_csr_pem_error)
    }

    /// Returns the subject distinguished name.
    ///
    /// Imported values must satisfy the same constraints as the distinguished-name builder.
    pub fn subject(&self) -> Result<DistinguishedName> {
        parse_request(&self.der)
            .and_then(|request| request.subject().map_err(map_csr_error))
            .and_then(DistinguishedName::from_ffi)
    }

    /// Returns the requested subject alternative names.
    pub fn subject_alt_names(&self) -> Result<Vec<SubjectAltName>> {
        parse_request(&self.der)?
            .subject_alt_names()
            .map_err(map_csr_error)?
            .into_iter()
            .map(SubjectAltName::from_ffi)
            .collect()
    }

    /// Returns the request's public key.
    pub fn public_key(&self) -> Result<PublicKey> {
        request_public_key(&parse_request(&self.der)?)
    }

    /// Parses the request once and returns all supported fields.
    ///
    /// Reading several fields from the returned snapshot is cheaper than
    /// calling the individual accessors, each of which re-parses the request.
    pub fn details(&self) -> Result<CertificateSigningRequestDetails> {
        let request = parse_request(&self.der)?;
        let subject = request.subject().map_err(map_csr_error)?;
        let subject_alt_names = request
            .subject_alt_names()
            .map_err(map_csr_error)?
            .into_iter()
            .map(SubjectAltName::from_ffi)
            .collect::<Result<Vec<_>>>()?;
        Ok(CertificateSigningRequestDetails {
            subject: DistinguishedName::from_ffi(subject)?,
            subject_alt_names,
            public_key: request_public_key(&request)?,
        })
    }
}

/// The supported fields of a PKCS#10 request, parsed in one pass.
///
/// Returned by [`CertificateSigningRequest::details`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateSigningRequestDetails {
    subject: DistinguishedName,
    subject_alt_names: Vec<SubjectAltName>,
    public_key: PublicKey,
}

impl CertificateSigningRequestDetails {
    /// Returns the subject distinguished name.
    pub fn subject(&self) -> &DistinguishedName {
        &self.subject
    }

    /// Returns the requested subject alternative names.
    pub fn subject_alt_names(&self) -> &[SubjectAltName] {
        &self.subject_alt_names
    }

    /// Returns the request's public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Builds a PKCS#10 request with a supported key and SHA-256 signature.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CertificateSigningRequestBuilder {
    subject: Option<DistinguishedName>,
    subject_alt_names: Vec<SubjectAltName>,
}

impl CertificateSigningRequestBuilder {
    /// Sets the subject distinguished name.
    ///
    /// An omitted subject is encoded as an empty name, which is common for
    /// ACME requests that identify the subject entirely through SANs.
    pub fn subject(mut self, subject: DistinguishedName) -> Self {
        self.subject = Some(subject);
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

    /// Validates, signs, and encodes the request.
    pub fn build(self, key: &PrivateKey) -> Result<CertificateSigningRequest> {
        let subject = self.subject.unwrap_or_else(DistinguishedName::empty);
        let ffi_subject = subject.to_ffi()?;
        let subject_alt_names: Vec<_> = self
            .subject_alt_names
            .iter()
            .map(SubjectAltName::to_ffi)
            .collect();
        let request =
            ffi::CertificateRequest::build(&ffi_subject, &subject_alt_names, key.as_ffi())
                .map_err(map_csr_error)?;
        let der = request.to_der().map_err(map_csr_error)?;
        Ok(CertificateSigningRequest { der })
    }
}

fn parse_request(der: &[u8]) -> Result<ffi::CertificateRequest> {
    ffi::CertificateRequest::from_der(der).map_err(map_csr_error)
}

fn request_public_key(request: &ffi::CertificateRequest) -> Result<PublicKey> {
    let key = request.public_key().map_err(map_csr_error)?;
    let der = key.to_spki_der().map_err(map_csr_error)?;
    PublicKey::from_spki_der(&der)
}

fn map_csr_error(error: ffi::Error) -> Error {
    match error {
        ffi::Error::InvalidEncoding => Error::InvalidEncoding {
            encoding: "PKCS#10 DER",
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

fn map_csr_pem_error(error: ffi::Error) -> Error {
    match error {
        ffi::Error::InvalidEncoding => Error::InvalidEncoding {
            encoding: "PKCS#10 PEM",
        },
        error => map_csr_error(error),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::CertificateSigningRequest;
    use crate::{
        DistinguishedName, DnsName, Error, PrivateKey, RsaKeySize, SignatureAlgorithm,
        SubjectAltName,
    };

    const LIBRESSL_RSA_CSR: &str = "-----BEGIN CERTIFICATE REQUEST-----\n\
MIICWzCCAUMCAQAwFjEUMBIGA1UEAwwLcnNhLmV4YW1wbGUwggEiMA0GCSqGSIb3\n\
DQEBAQUAA4IBDwAwggEKAoIBAQDKyU2GNCCilUrBz03OvWKjvtCe/XpH2sNPL6Nz\n\
mg5IGc/o6R/ArKPzoq2wKzuEi97fjYJCc3uUUsNtNlJF1I45embcdJus71Dk34wt\n\
fP28BBd751pp7tvoZOFehuRAl2UMJ4UrYgCxWYxah5UUZGvvCDRWEernBmafk37L\n\
gdeBOeACBFvLGiI+37FuFq9ZUISXJBE5vmeDylhTFYddOB7iu8Of7o7rX5lO2yDm\n\
IzQ+OBGxexripxoH+wt76Toz564nfZj369m+Ket5Fc1X6Ek1gjzpnqD1H4hav606\n\
X4Te5NOc+hzJSxp9SHcSKLGCV+9aVWDtOdbOmUTqbpdGQVOpAgMBAAGgADANBgkq\n\
hkiG9w0BAQsFAAOCAQEAnYVUkDjXNdLa6A+4EzC54LpjGjveynBA3hOBN1/+nzb9\n\
/euLLPRf5GZcGkAU26cQZou+mpRHUwdln/KVaJzPMg916juAR8GtT+SWcc8pKuWg\n\
TV0GfpLs4vScpBgR6DLAvR9d1Gff+ShBizogFmRRWmWRfzziJeQgL3TIK4cit4th\n\
og2lAhHRIQHAQHY5I/+kvB6lMX3kgt/7VMVdUhySt1ntx0tMmwIqhmGwwazqzKNq\n\
ibamIDUrGGZ4GujxNQEfT8zrsYHNp6JBvMq2Vujzh8e/Gl82nYQ70jfdmWgT8Wht\n\
wWN9B0Ey8LjQt3WjVNcKyX1fDHu/WkHdby5n2Njmjg==\n\
-----END CERTIFICATE REQUEST-----\n";

    #[test]
    fn builds_and_parses_a_signed_request() {
        let key = PrivateKey::generate().unwrap();
        let subject = DistinguishedName::builder()
            .common_name("example.com")
            .build()
            .unwrap();
        let request = CertificateSigningRequest::builder()
            .subject(subject.clone())
            .dns_name(DnsName::new("example.com").unwrap())
            .ip_address(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .build(&key)
            .unwrap();

        let parsed = CertificateSigningRequest::from_der(request.as_der()).unwrap();
        assert_eq!(parsed.subject().unwrap(), subject);
        assert_eq!(
            parsed.subject_alt_names().unwrap(),
            vec![
                SubjectAltName::Dns(DnsName::new("example.com").unwrap()),
                SubjectAltName::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ]
        );
        assert_eq!(parsed.public_key().unwrap(), key.public_key().unwrap());

        let pem = request.to_pem().unwrap();
        assert_eq!(CertificateSigningRequest::from_pem(&pem).unwrap(), request);
    }

    #[test]
    fn reads_all_fields_in_one_pass() {
        let key = PrivateKey::generate().unwrap();
        let subject = DistinguishedName::builder()
            .common_name("example.com")
            .build()
            .unwrap();
        let names = vec![
            SubjectAltName::Dns(DnsName::new("example.com").unwrap()),
            SubjectAltName::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        let request = CertificateSigningRequest::builder()
            .subject(subject.clone())
            .subject_alt_name(names[0].clone())
            .subject_alt_name(names[1].clone())
            .build(&key)
            .unwrap();

        let details = request.details().unwrap();
        assert_eq!(details.subject(), &subject);
        assert_eq!(details.subject_alt_names(), names.as_slice());
        assert_eq!(details.public_key(), &key.public_key().unwrap());
    }

    #[test]
    fn builds_and_parses_an_rsa_signed_request() {
        let key = PrivateKey::generate_rsa(RsaKeySize::Bits2048).unwrap();
        let request = CertificateSigningRequest::builder()
            .dns_name(DnsName::new("example.com").unwrap())
            .build(&key)
            .unwrap();

        let parsed = CertificateSigningRequest::from_der(request.as_der()).unwrap();
        assert_eq!(parsed.public_key().unwrap(), key.public_key().unwrap());
        assert_eq!(
            CertificateSigningRequest::from_pem(&request.to_pem().unwrap()).unwrap(),
            request
        );
    }

    #[test]
    fn parses_a_libressl_rsa_signed_request() {
        let request = CertificateSigningRequest::from_pem(LIBRESSL_RSA_CSR).unwrap();
        assert_eq!(
            request.public_key().unwrap().algorithm(),
            SignatureAlgorithm::RsaPkcs1Sha256
        );
        assert_eq!(
            request.subject().unwrap(),
            DistinguishedName::builder()
                .common_name("rsa.example")
                .build()
                .unwrap()
        );
    }

    #[test]
    fn builds_acme_requests_with_empty_subjects() {
        let names = vec![
            SubjectAltName::Dns(DnsName::new("example.com").unwrap()),
            SubjectAltName::Dns(DnsName::new("*.example.com").unwrap()),
            SubjectAltName::Ip("192.0.2.1".parse().unwrap()),
            SubjectAltName::Ip("2001:db8::1".parse().unwrap()),
        ];
        for key in [
            PrivateKey::generate().unwrap(),
            PrivateKey::generate_rsa(RsaKeySize::Bits2048).unwrap(),
        ] {
            let mut builder = CertificateSigningRequest::builder();
            for name in &names {
                builder = builder.subject_alt_name(name.clone());
            }
            let request = builder.build(&key).unwrap();
            for parsed in [
                CertificateSigningRequest::from_der(request.as_der()).unwrap(),
                CertificateSigningRequest::from_pem(&request.to_pem().unwrap()).unwrap(),
            ] {
                assert_eq!(parsed, request);
                assert_eq!(parsed.subject().unwrap().entries().len(), 0);
                assert_eq!(parsed.subject_alt_names().unwrap(), names);
                assert_eq!(parsed.public_key().unwrap(), key.public_key().unwrap());
            }
        }
    }

    #[test]
    fn rejects_tampered_request_signatures() {
        for key in [
            PrivateKey::generate().unwrap(),
            PrivateKey::generate_rsa(RsaKeySize::Bits2048).unwrap(),
        ] {
            let request = CertificateSigningRequest::builder()
                .dns_name(DnsName::new("example.com").unwrap())
                .build(&key)
                .unwrap();
            CertificateSigningRequest::from_der(request.as_der()).unwrap();
            let mut der = request.as_der().to_vec();
            *der.last_mut().unwrap() ^= 1;
            let structurally_valid = crate::ffi::CertificateRequest::from_der(&der).unwrap();
            let pem = structurally_valid.to_pem().unwrap();
            assert!(matches!(
                CertificateSigningRequest::from_der(&der),
                Err(Error::Verification)
            ));
            assert!(matches!(
                CertificateSigningRequest::from_pem(&pem),
                Err(Error::Verification)
            ));
        }
    }

    #[test]
    fn rejects_an_invalid_request() {
        assert!(matches!(
            CertificateSigningRequest::from_der(b"not DER"),
            Err(Error::InvalidEncoding {
                encoding: "PKCS#10 DER"
            })
        ));
        assert!(matches!(
            CertificateSigningRequest::from_pem("not PEM"),
            Err(Error::InvalidEncoding {
                encoding: "PKCS#10 PEM"
            })
        ));
        let key = PrivateKey::generate().unwrap();
        let request = CertificateSigningRequest::builder().build(&key).unwrap();
        CertificateSigningRequest::from_der(request.as_der()).unwrap();
        let mut trailing = request.as_der().to_vec();
        trailing.push(0);
        for malformed in [
            &trailing[..],
            &request.as_der()[..request.as_der().len() - 1],
        ] {
            assert!(matches!(
                CertificateSigningRequest::from_der(malformed),
                Err(Error::InvalidEncoding {
                    encoding: "PKCS#10 DER"
                })
            ));
        }
    }
}
