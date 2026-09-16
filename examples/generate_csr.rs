use certutils::{CertificateSigningRequest, DistinguishedName, DnsName, PrivateKey, RsaKeySize};

fn main() -> certutils::Result<()> {
    let key = PrivateKey::generate_rsa(RsaKeySize::Bits3072)?;
    let private_key_pem = key.to_pkcs8_pem()?;
    let key = PrivateKey::from_pkcs8_pem(&private_key_pem)?;

    let subject = DistinguishedName::builder()
        .common_name("example.com")
        .organization("Example Organization")
        .build()?;
    let request = CertificateSigningRequest::builder()
        .subject(subject)
        .dns_name(DnsName::new("example.com")?)
        .dns_name(DnsName::new("www.example.com")?)
        .build(&key)?;

    let parsed = CertificateSigningRequest::from_der(request.as_der())?;
    assert_eq!(parsed.public_key()?, key.public_key()?);

    println!("{}", request.to_pem()?);
    Ok(())
}
