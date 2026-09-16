# certutils

[![crates.io](https://img.shields.io/crates/v/certutils.svg)](https://crates.io/crates/certutils)
[![docs.rs](https://docs.rs/certutils/badge.svg)](https://docs.rs/certutils)
[![license](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](https://github.com/ogital-net/certutils/blob/main/LICENSE)

High-level X.509 certificate utilities backed by AWS-LC.

Certificates and requests are generated with ECDSA P-256 or RSA keys using
SHA-256 signatures. When reading, the crate additionally accepts SHA-384
signatures and P-384 public keys so that chains through P-384 certificate
authorities can be parsed and verified. Private-key generation and import
remain limited to P-256 and supported RSA keys.

## Minimum supported Rust version

The core crate supports Rust 1.71 and newer. The optional `jose4rs` feature
currently requires Rust 1.88, matching `jose4rs` 0.6.

## Verification policy

[`VerificationOptions::new`] requires an explicit [`VerificationPurpose`].
Use `TlsServer` or `TlsClient` for TLS certificate validation. `ChainOnly`
deliberately omits endpoint key usage and EKU checks and is not a TLS
authentication policy. TLS server verification also requires an expected
DNS name or IP address. An absent EKU extension is unconstrained; a present
EKU must permit the selected purpose, including in untrusted intermediates.

No mode performs a TLS handshake, revocation or certificate-transparency
checks, network fetching, or application authorization. Prefer the TLS
implementation's certificate verifier when integrating a TLS connection.

```rust
use std::time::{Duration, SystemTime};
use certutils::{
    Certificate, CertificateProfile, CertificateVerifier, DistinguishedName,
    DnsName, PrivateKey, SubjectAltName, Validity, VerificationOptions, VerificationPurpose,
};

fn main() -> certutils::Result<()> {
    let now = SystemTime::now();
    let validity = Validity::new(now, now + Duration::from_secs(3600))?;
    let authority = Certificate::builder(
        DistinguishedName::builder().common_name("Example CA").build()?,
        validity,
        CertificateProfile::CertificateAuthority { path_length: Some(0) },
    )
    .generate_self_signed()?;
    let server_key = PrivateKey::generate()?;
    let server = Certificate::builder(
        DistinguishedName::builder().common_name("localhost").build()?,
        validity,
        CertificateProfile::Server,
    )
    .dns_name(DnsName::new("localhost")?)
    .signed_by(&server_key.public_key()?, authority.certificate(), authority.private_key())?;
    let options = VerificationOptions::new(VerificationPurpose::TlsServer)
        .subject(SubjectAltName::Dns(DnsName::new("localhost")?));
    let verifier = CertificateVerifier::new([authority.certificate().clone()]);
    verifier.verify(&server, &[], &options)?;
    Ok(())
}
```

## Example

```rust
use certutils::{CertificateSigningRequest, DistinguishedName, DnsName, PrivateKey};

fn main() -> certutils::Result<()> {
    let key = PrivateKey::generate()?;
    let subject = DistinguishedName::builder()
        .common_name("example.com")
        .build()?;
    let dns_name = DnsName::new("example.com")?;
    let csr = CertificateSigningRequest::builder()
        .subject(subject)
        .dns_name(dns_name)
        .build(&key)?;

    let _csr_der = csr.as_der();
    Ok(())
}
```

## RSA key generation

Generated RSA keys use PKCS#1 v1.5 signatures with SHA-256.

```rust
use certutils::{CertificateSigningRequest, DnsName, PrivateKey, RsaKeySize};

fn main() -> certutils::Result<()> {
    let key = PrivateKey::generate_rsa(RsaKeySize::Bits2048)?;
    let _csr = CertificateSigningRequest::builder()
        .dns_name(DnsName::new("example.com")?)
        .build(&key)?;
    Ok(())
}
```

## Self-signed development certificate

```rust
use std::time::{Duration, SystemTime};
use certutils::{Certificate, CertificateProfile, DistinguishedName, DnsName, Validity};

fn main() -> certutils::Result<()> {
    let now = SystemTime::now();
    let validity = Validity::new(now, now + Duration::from_secs(24 * 60 * 60))?;
    let subject = DistinguishedName::builder()
        .common_name("localhost")
        .build()?;
    let identity = Certificate::builder(subject, validity, CertificateProfile::Server)
        .dns_name(DnsName::new("localhost")?)
        .generate_self_signed()?;

    let _certificate_pem = identity.certificate().to_pem()?;
    let _private_key_pem = identity.private_key().to_pkcs8_pem()?;
    Ok(())
}
```

[`VerificationOptions::new`]: https://docs.rs/certutils/latest/certutils/struct.VerificationOptions.html#method.new
[`VerificationPurpose`]: https://docs.rs/certutils/latest/certutils/enum.VerificationPurpose.html

## License

BSD-2-Clause. See [LICENSE](https://github.com/ogital-net/certutils/blob/main/LICENSE).