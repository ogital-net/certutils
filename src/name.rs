use std::net::IpAddr;

use crate::{ffi, Error, Result};

/// A validated ASCII DNS name for use in a subject alternative name.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DnsName(String);

impl DnsName {
    /// Validates and owns a DNS name.
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_dns_name(&name)?;
        Ok(Self(name))
    }

    /// Returns the DNS name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for DnsName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// A supported subject alternative name.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SubjectAltName {
    /// A DNS identifier.
    Dns(DnsName),
    /// An IPv4 or IPv6 identifier.
    Ip(IpAddr),
}

/// A supported attribute in an X.509 distinguished name.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum DistinguishedNameAttribute {
    /// The country name (`C`).
    CountryName,
    /// The state or province name (`ST`).
    StateOrProvinceName,
    /// The locality name (`L`).
    LocalityName,
    /// The organization name (`O`).
    OrganizationName,
    /// The organizational unit name (`OU`).
    OrganizationalUnitName,
    /// The common name (`CN`).
    CommonName,
}

/// An ordered X.509 distinguished name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistinguishedName {
    entries: Vec<(DistinguishedNameAttribute, String)>,
}

impl DistinguishedName {
    /// Starts a distinguished-name builder.
    pub fn builder() -> DistinguishedNameBuilder {
        DistinguishedNameBuilder::default()
    }

    /// Iterates over attributes in encoded order.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = (DistinguishedNameAttribute, &str)> {
        self.entries
            .iter()
            .map(|(attribute, value)| (*attribute, value.as_str()))
    }
}

/// Builds and validates an ordered X.509 distinguished name.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DistinguishedNameBuilder {
    entries: Vec<(DistinguishedNameAttribute, String)>,
}

impl DistinguishedNameBuilder {
    /// Appends an attribute to the distinguished name.
    pub fn push(mut self, attribute: DistinguishedNameAttribute, value: impl Into<String>) -> Self {
        self.entries.push((attribute, value.into()));
        self
    }

    /// Appends a common name.
    pub fn common_name(self, value: impl Into<String>) -> Self {
        self.push(DistinguishedNameAttribute::CommonName, value)
    }

    /// Appends an organization name.
    pub fn organization(self, value: impl Into<String>) -> Self {
        self.push(DistinguishedNameAttribute::OrganizationName, value)
    }

    /// Validates and creates the distinguished name.
    pub fn build(self) -> Result<DistinguishedName> {
        for (attribute, value) in &self.entries {
            validate_name_value(*attribute, value)?;
        }
        Ok(DistinguishedName {
            entries: self.entries,
        })
    }
}

impl DistinguishedName {
    pub(crate) fn to_ffi(&self) -> Result<ffi::DistinguishedName> {
        ffi::DistinguishedName::new(
            self.entries()
                .map(|(attribute, value)| (attribute.to_ffi(), value)),
        )
        .map_err(map_name_error)
    }

    pub(crate) fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub(crate) fn from_ffi(entries: Vec<ffi::NameEntry>) -> Result<Self> {
        DistinguishedNameBuilder {
            entries: entries
                .into_iter()
                .map(|entry| {
                    (
                        DistinguishedNameAttribute::from_ffi(entry.attribute),
                        entry.value,
                    )
                })
                .collect(),
        }
        .build()
        .map_err(|_| Error::InvalidEncoding {
            encoding: "distinguished name",
        })
    }
}

impl DistinguishedNameAttribute {
    fn to_ffi(self) -> ffi::NameAttribute {
        match self {
            Self::CountryName => ffi::NameAttribute::Country,
            Self::StateOrProvinceName => ffi::NameAttribute::StateOrProvince,
            Self::LocalityName => ffi::NameAttribute::Locality,
            Self::OrganizationName => ffi::NameAttribute::Organization,
            Self::OrganizationalUnitName => ffi::NameAttribute::OrganizationalUnit,
            Self::CommonName => ffi::NameAttribute::Common,
        }
    }

    fn from_ffi(attribute: ffi::NameAttribute) -> Self {
        match attribute {
            ffi::NameAttribute::Country => Self::CountryName,
            ffi::NameAttribute::StateOrProvince => Self::StateOrProvinceName,
            ffi::NameAttribute::Locality => Self::LocalityName,
            ffi::NameAttribute::Organization => Self::OrganizationName,
            ffi::NameAttribute::OrganizationalUnit => Self::OrganizationalUnitName,
            ffi::NameAttribute::Common => Self::CommonName,
        }
    }
}

impl SubjectAltName {
    pub(crate) fn to_ffi(&self) -> ffi::SubjectAlternativeName {
        match self {
            Self::Dns(name) => ffi::SubjectAlternativeName::Dns(name.as_str().to_owned()),
            Self::Ip(address) => ffi::SubjectAlternativeName::Ip(*address),
        }
    }

    pub(crate) fn from_ffi(name: ffi::SubjectAlternativeName) -> Result<Self> {
        match name {
            ffi::SubjectAlternativeName::Dns(name) => DnsName::new(name).map(Self::Dns),
            ffi::SubjectAlternativeName::Ip(address) => Ok(Self::Ip(address)),
        }
    }
}

fn validate_dns_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return Err(invalid_name("must be an ASCII DNS name of 1 to 253 bytes"));
    }

    let mut labels = name.split('.');
    let first = labels.next().expect("a non-empty name has a first label");
    validate_dns_label(first, true)?;
    for label in labels {
        validate_dns_label(label, false)?;
    }
    Ok(())
}

fn validate_dns_label(label: &str, allow_wildcard: bool) -> Result<()> {
    if allow_wildcard && label == "*" {
        return Ok(());
    }
    if label.is_empty() || label.len() > 63 {
        return Err(invalid_name("each DNS label must contain 1 to 63 bytes"));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(invalid_name(
            "DNS labels must not start or end with a hyphen",
        ));
    }
    if !label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(invalid_name(
            "DNS labels may contain only ASCII letters, digits, and hyphens",
        ));
    }
    Ok(())
}

fn validate_name_value(attribute: DistinguishedNameAttribute, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(invalid_dn("values must not be empty"));
    }
    if value.contains('\0') {
        return Err(invalid_dn("values must not contain NUL"));
    }

    let maximum = match attribute {
        DistinguishedNameAttribute::CountryName => {
            if value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                return Err(invalid_dn("country names must be two ASCII letters"));
            }
            2
        }
        DistinguishedNameAttribute::CommonName
        | DistinguishedNameAttribute::OrganizationName
        | DistinguishedNameAttribute::OrganizationalUnitName => 64,
        DistinguishedNameAttribute::StateOrProvinceName
        | DistinguishedNameAttribute::LocalityName => 128,
    };
    if value.chars().count() > maximum {
        return Err(invalid_dn("value exceeds the X.509 attribute length limit"));
    }
    Ok(())
}

fn invalid_name(reason: &str) -> Error {
    Error::InvalidInput {
        field: "DNS name",
        reason: reason.to_owned(),
    }
}

fn invalid_dn(reason: &str) -> Error {
    Error::InvalidInput {
        field: "distinguished name",
        reason: reason.to_owned(),
    }
}

fn map_name_error(error: ffi::Error) -> Error {
    match error {
        ffi::Error::UnsupportedNameAttribute => Error::Unsupported {
            feature: "distinguished-name attribute",
        },
        ffi::Error::InvalidEncoding => Error::InvalidEncoding {
            encoding: "distinguished name",
        },
        ffi::Error::Allocation
        | ffi::Error::Crypto
        | ffi::Error::UnsupportedAlgorithm
        | ffi::Error::UnsupportedSubjectAltName
        | ffi::Error::Verification => Error::Crypto,
    }
}

#[cfg(test)]
mod tests {
    use super::{DistinguishedName, DistinguishedNameAttribute, DnsName};
    use crate::{ffi, Certificate, CertificateSigningRequest, Error, PrivateKey};

    #[test]
    fn validates_imported_distinguished_name_values() {
        for (attribute, value) in [
            (ffi::NameAttribute::Common, String::new()),
            (ffi::NameAttribute::Common, "bad\0name".to_owned()),
            (ffi::NameAttribute::Common, "a".repeat(65)),
            (ffi::NameAttribute::Organization, "a".repeat(65)),
            (ffi::NameAttribute::Locality, "a".repeat(129)),
            (ffi::NameAttribute::Country, "USA".to_owned()),
            (ffi::NameAttribute::Country, "12".to_owned()),
        ] {
            assert!(matches!(
                DistinguishedName::from_ffi(vec![ffi::NameEntry { attribute, value }]),
                Err(Error::InvalidEncoding { .. })
            ));
        }
        let name = DistinguishedName::from_ffi(vec![ffi::NameEntry {
            attribute: ffi::NameAttribute::Common,
            value: "a".repeat(64),
        }])
        .unwrap();
        assert_eq!(name.entries().next().unwrap().1.len(), 64);
        assert!(DistinguishedName::from_ffi(Vec::new()).is_ok());
    }

    #[test]
    fn rejects_nul_in_imported_certificate_and_request_names() {
        let key = PrivateKey::generate().unwrap();
        let subject =
            ffi::DistinguishedName::new([(ffi::NameAttribute::Common, "bad\0name")]).unwrap();
        let certificate = ffi::Certificate::self_signed(
            ffi::x509::CertificateParams {
                subject: &subject,
                not_before: 0,
                not_after: 1,
                serial_number: Some(&[1]),
                subject_alt_names: &[],
                profile: ffi::x509::CertificateProfile::Server,
            },
            key.as_ffi(),
        )
        .unwrap();
        let certificate = Certificate::from_der(&certificate.to_der().unwrap()).unwrap();
        certificate
            .verify_signature(&key.public_key().unwrap())
            .unwrap();
        let request = ffi::CertificateRequest::build(&subject, &[], key.as_ffi()).unwrap();
        let request = CertificateSigningRequest::from_der(&request.to_der().unwrap()).unwrap();
        for result in [
            certificate.subject().map(|_| ()),
            certificate.issuer().map(|_| ()),
            certificate.details().map(|_| ()),
            request.subject().map(|_| ()),
            request.details().map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(Error::InvalidEncoding {
                    encoding: "distinguished name"
                })
            ));
        }
    }

    #[test]
    fn validates_dns_names() {
        let maximum = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(maximum.len(), 253);
        for name in [
            "example.com",
            "*.example.com",
            "a",
            "EXAMPLE.com",
            "xn--mnich-kva.example",
            &format!("{}.example", "a".repeat(63)),
            &maximum,
        ] {
            let parsed = DnsName::new(name).unwrap();
            assert_eq!(parsed.as_str(), name);
        }
        for name in [
            "",
            "example_com",
            "-example.com",
            "example-.com",
            "example.com.",
            ".example.com",
            "a..example",
            "m\u{00fc}nich.example",
            "a\0.example",
            "foo*.example.com",
            "a.*.example.com",
            &format!("{}.example", "a".repeat(64)),
            &format!("{maximum}d"),
        ] {
            assert!(
                matches!(
                    DnsName::new(name),
                    Err(Error::InvalidInput {
                        field: "DNS name",
                        ..
                    })
                ),
                "invalid DNS name accepted: {name:?}"
            );
        }
    }

    #[test]
    fn validates_distinguished_name_length_boundaries() {
        for (attribute, maximum) in [
            (DistinguishedNameAttribute::CommonName, 64),
            (DistinguishedNameAttribute::OrganizationName, 64),
            (DistinguishedNameAttribute::OrganizationalUnitName, 64),
            (DistinguishedNameAttribute::StateOrProvinceName, 128),
            (DistinguishedNameAttribute::LocalityName, 128),
        ] {
            for character in ["a", "\u{00e9}"] {
                let value = character.repeat(maximum);
                let name = DistinguishedName::builder()
                    .push(attribute, value.clone())
                    .build()
                    .unwrap();
                let parsed =
                    DistinguishedName::from_ffi(name.to_ffi().unwrap().entries().unwrap()).unwrap();
                assert_eq!(parsed, name);
                assert_eq!(
                    parsed.entries().next().unwrap(),
                    (attribute, value.as_str())
                );
                let too_long = character.repeat(maximum + 1);
                assert!(
                    matches!(
                        DistinguishedName::builder()
                            .push(attribute, too_long)
                            .build(),
                        Err(Error::InvalidInput {
                            field: "distinguished name",
                            ..
                        })
                    ),
                    "{attribute:?} limit must be {maximum} characters"
                );
            }
        }
        for country in ["U", "USA", "12", "\u{00e9}"] {
            assert!(matches!(
                DistinguishedName::builder()
                    .push(DistinguishedNameAttribute::CountryName, country)
                    .build(),
                Err(Error::InvalidInput {
                    field: "distinguished name",
                    ..
                })
            ));
        }
    }

    #[test]
    fn validates_distinguished_name_values() {
        let name = DistinguishedName::builder()
            .push(DistinguishedNameAttribute::CountryName, "US")
            .organization("Example")
            .common_name("example.com")
            .build()
            .unwrap();
        assert_eq!(name.entries().len(), 3);
        assert!(name.to_ffi().is_ok());

        assert!(DistinguishedName::builder()
            .push(DistinguishedNameAttribute::CountryName, "USA")
            .build()
            .is_err());
        assert!(DistinguishedName::builder()
            .common_name("")
            .build()
            .is_err());
    }
}
