use std::time::{Duration, SystemTime};

use certutils::{Certificate, CertificateProfile, DistinguishedName, DnsName, Validity};

fn main() -> certutils::Result<()> {
    let now = SystemTime::now();
    let validity = Validity::new(now, now + Duration::from_secs(24 * 60 * 60))?;
    let subject = DistinguishedName::builder()
        .common_name("localhost")
        .organization("Local Development")
        .build()?;

    let identity = Certificate::builder(subject, validity, CertificateProfile::Server)
        .dns_name(DnsName::new("localhost")?)
        .ip_address("127.0.0.1".parse().expect("valid IP address"))
        .generate_self_signed()?;

    identity
        .certificate()
        .verify_signature(&identity.private_key().public_key()?)?;
    println!("{}", identity.certificate().to_pem()?);
    Ok(())
}
