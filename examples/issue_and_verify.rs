use std::time::{Duration, SystemTime};

use certutils::{
    Certificate, CertificateProfile, CertificateVerifier, DistinguishedName, DnsName, PrivateKey,
    RsaKeySize, SubjectAltName, Validity, VerificationOptions, VerificationPurpose,
};

fn main() -> certutils::Result<()> {
    let now = SystemTime::now();
    let validity = Validity::new(now, now + Duration::from_secs(365 * 24 * 60 * 60))?;

    let issuer_key = PrivateKey::generate_rsa(RsaKeySize::Bits3072)?;
    let issuer = Certificate::builder(
        DistinguishedName::builder()
            .common_name("Example Test CA")
            .organization("Example Organization")
            .build()?,
        validity,
        CertificateProfile::CertificateAuthority {
            path_length: Some(0),
        },
    )
    .self_signed(&issuer_key)?;

    let server_key = PrivateKey::generate()?;
    let server = Certificate::builder(
        DistinguishedName::builder()
            .common_name("service.example.com")
            .build()?,
        validity,
        CertificateProfile::Server,
    )
    .dns_name(DnsName::new("service.example.com")?)
    .signed_by(&server_key.public_key()?, &issuer, &issuer_key)?;

    let expected_name = DnsName::new("service.example.com")?;
    let options = VerificationOptions::new(VerificationPurpose::TlsServer)
        .at_time(now)
        .subject(SubjectAltName::Dns(expected_name));
    CertificateVerifier::new([issuer]).verify(&server, &[], &options)?;

    println!("{}", server.to_pem()?);
    Ok(())
}
