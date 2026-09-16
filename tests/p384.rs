//! Interoperability tests using a non-production LibreSSL-generated chain.
//! The named-curve P-256 leaf, P-384 intermediate, and P-384 root are signed
//! with SHA-384. The fixture contains no private keys and needs no network.

use std::time::Duration;

use certutils::{
    Certificate, CertificateVerifier, DnsName, Error, PublicKey, SignatureAlgorithm,
    SubjectAltName, VerificationOptions, VerificationPurpose,
};

fn chain() -> [Certificate; 3] {
    Certificate::from_pem_chain(include_str!("fixtures/p384-chain.pem"))
        .unwrap()
        .try_into()
        .unwrap()
}

fn verification_options(leaf: &Certificate) -> VerificationOptions {
    VerificationOptions::new(VerificationPurpose::TlsServer)
        .at_time(leaf.validity().unwrap().not_before() + Duration::from_secs(60))
        .subject(SubjectAltName::Dns(
            DnsName::new("service.example.test").unwrap(),
        ))
}

#[test]
fn parses_and_verifies_p384_ca_chain() {
    let certificates = chain();
    let pem = Certificate::certificates_to_pem(&certificates).unwrap();
    assert_eq!(
        Certificate::from_pem_chain(&pem).unwrap().as_slice(),
        &certificates
    );
    let [leaf, intermediate, root] = certificates;
    assert_eq!(
        leaf.public_key().unwrap().algorithm(),
        SignatureAlgorithm::EcdsaP256Sha256
    );
    let intermediate_key = intermediate.public_key().unwrap();
    let root_key = root.public_key().unwrap();
    assert_eq!(
        intermediate_key.algorithm(),
        SignatureAlgorithm::EcdsaP384Sha384
    );
    assert_eq!(root_key.algorithm(), SignatureAlgorithm::EcdsaP384Sha384);
    leaf.verify_signature(&intermediate_key).unwrap();
    intermediate.verify_signature(&root_key).unwrap();
    root.verify_signature(&root_key).unwrap();
    assert!(matches!(
        leaf.verify_signature(&root_key),
        Err(Error::Verification)
    ));

    let options = verification_options(&leaf);
    let verifier = CertificateVerifier::new([root]);
    verifier.verify(&leaf, &[intermediate], &options).unwrap();
    assert!(matches!(
        verifier.verify(&leaf, &[], &options),
        Err(Error::Verification)
    ));
}

#[test]
fn p384_public_keys_round_trip() {
    let [_, intermediate, root] = chain();
    for certificate in [intermediate, root] {
        let key = certificate.public_key().unwrap();
        assert_eq!(certificate.details().unwrap().public_key(), &key);
        assert_eq!(PublicKey::from_spki_der(key.as_spki_der()).unwrap(), key);
        assert_eq!(
            PublicKey::from_spki_pem(&key.to_spki_pem().unwrap()).unwrap(),
            key
        );
        assert_eq!(
            Certificate::from_der(certificate.as_der()).unwrap(),
            certificate
        );
    }
}

#[test]
fn rejects_tampered_p384_signature() {
    let [leaf, intermediate, root] = chain();
    let options = verification_options(&leaf);
    let mut der = leaf.as_der().to_vec();
    *der.last_mut().unwrap() ^= 1;
    let tampered = Certificate::from_der(&der).unwrap();
    assert!(matches!(
        tampered.verify_signature(&intermediate.public_key().unwrap()),
        Err(Error::Verification)
    ));
    assert!(matches!(
        CertificateVerifier::new([root]).verify(&tampered, &[intermediate], &options),
        Err(Error::Verification)
    ));
}

#[cfg(feature = "jose4rs")]
#[test]
fn p384_public_keys_round_trip_through_jwk() {
    let [_, intermediate, _] = chain();
    let key = intermediate.public_key().unwrap();
    let jwk = key.to_jose_jwk().unwrap();
    assert!(jwk.to_pkcs8_der().is_none());
    assert_eq!(PublicKey::from_jose_jwk(&jwk).unwrap(), key);
}
