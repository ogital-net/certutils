use std::fmt;

/// A result returned by `certutils` operations.
pub type Result<T> = std::result::Result<T, Error>;

/// An error produced while validating or processing X.509 data.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// A caller-provided field is not valid for the requested operation.
    InvalidInput {
        /// The field that failed validation.
        field: &'static str,
        /// A human-readable reason that does not contain secret material.
        reason: String,
    },
    /// DER or PEM input is malformed or has an unexpected label or structure.
    InvalidEncoding {
        /// The encoding being processed.
        encoding: &'static str,
    },
    /// The input uses an algorithm or X.509 option this crate does not support.
    Unsupported {
        /// The unsupported feature or value.
        feature: &'static str,
    },
    /// AWS-LC could not complete a cryptographic operation.
    Crypto,
    /// Certificate or CSR verification failed.
    Verification,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::InvalidEncoding { encoding } => {
                write!(formatter, "invalid {encoding} encoding")
            }
            Self::Unsupported { feature } => write!(formatter, "unsupported {feature}"),
            Self::Crypto => formatter.write_str("AWS-LC operation failed"),
            Self::Verification => formatter.write_str("verification failed"),
        }
    }
}

impl std::error::Error for Error {}
