#![doc = include_str!("../README.md")]
#![warn(missing_docs, clippy::pedantic)]
// Public APIs use concise summaries instead of repetitive error sections and
// reserve `must_use` for values where discarding the result is likely a bug.
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::return_self_not_must_use
)]

mod certificate;
mod csr;
mod error;
#[allow(dead_code)]
mod ffi;
#[cfg(feature = "jose4rs")]
mod jose4rs;
mod key;
mod name;
mod verify;

pub use certificate::{
    Certificate, CertificateBuilder, CertificateDetails, CertificateProfile, SelfSignedCertificate,
    SerialNumber, Validity,
};
pub use csr::{
    CertificateSigningRequest, CertificateSigningRequestBuilder, CertificateSigningRequestDetails,
};
pub use error::{Error, Result};
pub use key::{PrivateKey, PublicKey, RsaKeySize, SignatureAlgorithm};
pub use name::{
    DistinguishedName, DistinguishedNameAttribute, DistinguishedNameBuilder, DnsName,
    SubjectAltName,
};
pub use verify::{CertificateVerifier, VerificationOptions, VerificationPurpose};
