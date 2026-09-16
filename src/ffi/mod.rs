//! Private ownership and operation wrappers for AWS-LC.
//!
//! No raw AWS-LC pointer crosses this module boundary. Public modules consume
//! the safe operations defined here instead of calling `aws-lc-sys` directly.

mod der;
mod name;
mod owned;
mod pem;
mod pkey;
pub(crate) mod verify;
pub(crate) mod x509;

pub(crate) type Certificate = owned::Certificate;
pub(crate) type CertificateRequest = owned::CertificateRequest;
pub(crate) type DistinguishedName = owned::DistinguishedName;
pub(crate) use name::NameEntry;
pub(crate) type NameAttribute = name::NameAttribute;
pub(crate) use pkey::KeyAlgorithm;
pub(crate) type PrivateKey = owned::PrivateKey;
pub(crate) type PublicKey = owned::PublicKey;
pub(crate) type SubjectAlternativeName = name::SubjectAlternativeName;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Allocation,
    Crypto,
    InvalidEncoding,
    UnsupportedAlgorithm,
    UnsupportedNameAttribute,
    UnsupportedSubjectAltName,
    Verification,
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
