use std::ffi::c_void;
use std::ptr;

use aws_lc_sys::{
    d2i_X509, d2i_X509_REQ, i2d_X509, i2d_X509_REQ, ASN1_BIT_STRING_new, ASN1_BIT_STRING_set_bit,
    ASN1_INTEGER_new, ASN1_INTEGER_set_uint64, ASN1_INTEGER_to_BN, ASN1_TIME_new,
    ASN1_TIME_set_posix, ASN1_TIME_to_posix, BASIC_CONSTRAINTS_new, BN_bin2bn, BN_bn2bin,
    BN_is_negative, BN_num_bytes, BN_to_ASN1_INTEGER, EVP_sha256, EXTENDED_KEY_USAGE_new,
    NID_basic_constraints, NID_client_auth, NID_ecdsa_with_SHA256, NID_ecdsa_with_SHA384,
    NID_ext_key_usage, NID_ext_req, NID_key_usage, NID_server_auth, NID_sha256WithRSAEncryption,
    NID_sha384WithRSAEncryption, NID_subject_alt_name, OBJ_nid2obj, OBJ_obj2nid,
    OPENSSL_sk_new_null, OPENSSL_sk_push, PEM_write_bio_X509, PEM_write_bio_X509_REQ, RAND_bytes,
    X509V3_EXT_i2d, X509V3_get_d2i, X509_ALGOR_get0, X509_NAME_entry_count,
    X509_REQ_add_extensions, X509_REQ_get0_signature, X509_REQ_get_attr_by_NID,
    X509_REQ_get_extensions, X509_REQ_get_pubkey, X509_REQ_get_subject_name, X509_REQ_new,
    X509_REQ_set_pubkey, X509_REQ_set_subject_name, X509_REQ_set_version, X509_REQ_sign,
    X509_REQ_verify, X509_add_ext, X509_check_ca, X509_get0_notAfter, X509_get0_notBefore,
    X509_get0_serialNumber, X509_get0_signature, X509_get0_tbs_sigalg, X509_get_ext_d2i,
    X509_get_issuer_name, X509_get_key_usage, X509_get_pathlen, X509_get_pubkey,
    X509_get_subject_name, X509_new, X509_set1_notAfter, X509_set1_notBefore, X509_set_issuer_name,
    X509_set_pubkey, X509_set_serialNumber, X509_set_subject_name, X509_set_version, X509_sign,
    X509_verify, X509v3_KU_KEY_CERT_SIGN, OPENSSL_STACK, V_ASN1_NULL, V_ASN1_UNDEF,
};

use super::der;
use super::name::{read_name, NameEntry, SubjectAlternativeName};
use super::owned::{
    Asn1Integer, Asn1Time, BasicConstraints, BigNumber, BitString, Certificate, CertificateRequest,
    DistinguishedName, ExtendedKeyUsage, Extension, PrivateKey, PublicKey, Stack,
};
use super::pem;
use super::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CertificateProfile {
    Server,
    Client,
    ServerAndClient,
    CertificateAuthority { path_length: Option<u8> },
}

#[derive(Clone, Copy)]
pub(crate) struct CertificateParams<'a> {
    pub(crate) subject: &'a DistinguishedName,
    pub(crate) not_before: i64,
    pub(crate) not_after: i64,
    pub(crate) serial_number: Option<&'a [u8]>,
    pub(crate) subject_alt_names: &'a [SubjectAlternativeName],
    pub(crate) profile: CertificateProfile,
}

impl Certificate {
    pub(crate) fn from_der(input: &[u8]) -> Result<Self> {
        let length = der::input_length(input)?;
        let mut cursor = input.as_ptr();
        // SAFETY: `cursor` points to `length` readable bytes. A null output
        // pointer asks AWS-LC to allocate a new certificate.
        let certificate = unsafe { Self::from_raw(d2i_X509(ptr::null_mut(), &mut cursor, length)) }
            .map_err(|_| Error::InvalidEncoding)?;
        if !der::consumed_all(input, cursor) {
            return Err(Error::InvalidEncoding);
        }
        certificate.validate_supported_algorithms()?;
        Ok(certificate)
    }

    pub(crate) fn from_pem(input: &str) -> Result<Self> {
        pem::input(input, "CERTIFICATE", Self::from_der)
    }

    pub(crate) fn from_pem_chain(input: &str) -> Result<Vec<Self>> {
        let mut certificates = Vec::new();
        pem::chain_inputs(input, "CERTIFICATE", |der| {
            certificates.push(Self::from_der(der)?);
            Ok(())
        })?;
        Ok(certificates)
    }

    pub(crate) fn to_der(&self) -> Result<Vec<u8>> {
        der::encode(|output| {
            // SAFETY: `self` remains live for the call, and `output` follows
            // the i2d output-pointer contract.
            unsafe { i2d_X509(self.as_ptr(), output) }
        })
    }

    pub(crate) fn to_pem(&self) -> Result<String> {
        let bio = pem::output()?;
        // SAFETY: `bio` and `self` remain live for the duration of the call.
        if unsafe { PEM_write_bio_X509(bio.as_ptr(), self.as_ptr()) } != 1 {
            return Err(Error::Crypto);
        }
        pem::string(&bio)
    }

    pub(crate) fn public_key(&self) -> Result<PublicKey> {
        // SAFETY: `self` is live and AWS-LC returns a newly owned key reference.
        unsafe { PublicKey::from_raw_supported(X509_get_pubkey(self.as_ptr())) }
    }

    pub(crate) fn subject(&self) -> Result<Vec<NameEntry>> {
        // SAFETY: The returned name is borrowed from live `self` and copied
        // before this method returns.
        read_name(unsafe { X509_get_subject_name(self.as_ptr()) })
    }

    pub(crate) fn issuer(&self) -> Result<Vec<NameEntry>> {
        // SAFETY: The returned name is borrowed from live `self` and copied
        // before this method returns.
        read_name(unsafe { X509_get_issuer_name(self.as_ptr()) })
    }

    pub(crate) fn subject_alt_names(&self) -> Result<Vec<SubjectAlternativeName>> {
        let mut critical = -1;
        // SAFETY: `self` is live. For subjectAltName, AWS-LC returns a newly
        // owned GENERAL_NAMES value on success.
        let names = unsafe {
            X509_get_ext_d2i(
                self.as_ptr(),
                NID_subject_alt_name,
                &mut critical,
                ptr::null_mut(),
            )
        };
        decode_subject_alt_names(names, critical)
    }

    pub(crate) fn validity(&self) -> Result<(i64, i64)> {
        // SAFETY: Returned times are borrowed from live `self`.
        let not_before = unsafe { X509_get0_notBefore(self.as_ptr()) };
        let not_after = unsafe { X509_get0_notAfter(self.as_ptr()) };
        Ok((read_time(not_before)?, read_time(not_after)?))
    }

    pub(crate) fn serial_number(&self) -> Result<Vec<u8>> {
        // SAFETY: The returned integer is borrowed from live `self`.
        let integer = unsafe { X509_get0_serialNumber(self.as_ptr()) };
        if integer.is_null() {
            return Err(Error::InvalidEncoding);
        }
        // SAFETY: `integer` is live and AWS-LC allocates a new BIGNUM.
        let number = unsafe { BigNumber::from_raw(ASN1_INTEGER_to_BN(integer, ptr::null_mut())) }
            .map_err(|_| Error::InvalidEncoding)?;
        // SAFETY: `number` is live.
        if unsafe { BN_is_negative(number.as_ptr()) } != 0 {
            return Err(Error::InvalidEncoding);
        }
        // SAFETY: `number` is live.
        let length = usize::try_from(unsafe { BN_num_bytes(number.as_ptr()) })
            .map_err(|_| Error::InvalidEncoding)?;
        if length == 0 || length > 20 {
            return Err(Error::InvalidEncoding);
        }
        let mut bytes = vec![0; length];
        // SAFETY: `number` is live and `bytes` is writable for `length` bytes.
        if unsafe { BN_bn2bin(number.as_ptr(), bytes.as_mut_ptr()) } != length {
            return Err(Error::Crypto);
        }
        Ok(bytes)
    }

    pub(crate) fn verify_signature(&self, issuer_key: &PublicKey) -> Result<()> {
        // SAFETY: Both handles remain live for the call.
        if unsafe { X509_verify(self.as_ptr(), issuer_key.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }

    pub(crate) fn self_signed(params: CertificateParams<'_>, key: &PrivateKey) -> Result<Self> {
        build_certificate(params, key.as_ptr(), params.subject.as_ptr(), key.as_ptr())
    }

    pub(crate) fn signed_by(
        params: CertificateParams<'_>,
        subject_key: &PublicKey,
        issuer: &Certificate,
        issuer_key: &PrivateKey,
    ) -> Result<Self> {
        let subordinate_ca = matches!(
            params.profile,
            CertificateProfile::CertificateAuthority { .. }
        );
        if !issuer.can_issue(subordinate_ca) {
            return Err(Error::InvalidEncoding);
        }
        // SAFETY: `issuer` remains live and owns the returned borrowed name.
        let issuer_name = unsafe { X509_get_subject_name(issuer.as_ptr()) };
        if issuer_name.is_null() {
            return Err(Error::InvalidEncoding);
        }
        build_certificate(
            params,
            subject_key.as_ptr(),
            issuer_name,
            issuer_key.as_ptr(),
        )
    }

    pub(crate) fn can_issue(&self, subordinate_ca: bool) -> bool {
        // SAFETY: `self` contains a live certificate for each read-only call.
        if unsafe { X509_check_ca(self.as_ptr()) } != 1 {
            return false;
        }
        let subject = unsafe { X509_get_subject_name(self.as_ptr()) };
        if subject.is_null() || unsafe { X509_NAME_entry_count(subject) } <= 0 {
            return false;
        }
        // An absent keyUsage extension is unconstrained. When present, it must
        // authorize certificate signing.
        let key_usage = unsafe { X509_get_key_usage(self.as_ptr()) };
        let Ok(key_cert_sign) = u32::try_from(X509v3_KU_KEY_CERT_SIGN) else {
            return false;
        };
        if key_usage != u32::MAX && key_usage & key_cert_sign == 0 {
            return false;
        }
        if subordinate_ca {
            let path_length = unsafe { X509_get_pathlen(self.as_ptr()) };
            if path_length == 0 || path_length < -1 {
                return false;
            }
        }
        true
    }

    fn validate_supported_algorithms(&self) -> Result<()> {
        let _public_key = self.public_key()?;
        let mut signature_algorithm = ptr::null();
        // SAFETY: `self` is live. The returned algorithm is borrowed from it.
        unsafe { X509_get0_signature(ptr::null_mut(), &mut signature_algorithm, self.as_ptr()) };
        validate_signature_algorithm(signature_algorithm)?;
        // SAFETY: `self` is live and owns the returned borrowed algorithm.
        validate_signature_algorithm(unsafe { X509_get0_tbs_sigalg(self.as_ptr()) })
    }
}

impl CertificateRequest {
    pub(crate) fn from_der(input: &[u8]) -> Result<Self> {
        let length = der::input_length(input)?;
        let mut cursor = input.as_ptr();
        // SAFETY: `cursor` points to `length` readable bytes. A null output
        // pointer asks AWS-LC to allocate a new request.
        let request = unsafe { Self::from_raw(d2i_X509_REQ(ptr::null_mut(), &mut cursor, length)) }
            .map_err(|_| Error::InvalidEncoding)?;
        if !der::consumed_all(input, cursor) {
            return Err(Error::InvalidEncoding);
        }
        request.validate_signature_algorithm()?;
        Ok(request)
    }

    pub(crate) fn from_pem(input: &str) -> Result<Self> {
        pem::input(input, "CERTIFICATE REQUEST", Self::from_der)
    }

    pub(crate) fn to_der(&self) -> Result<Vec<u8>> {
        der::encode(|output| {
            // SAFETY: `self` remains live for the call, and `output` follows
            // the i2d output-pointer contract.
            unsafe { i2d_X509_REQ(self.as_ptr(), output) }
        })
    }

    pub(crate) fn to_pem(&self) -> Result<String> {
        let bio = pem::output()?;
        // SAFETY: `bio` and `self` remain live for the duration of the call.
        if unsafe { PEM_write_bio_X509_REQ(bio.as_ptr(), self.as_ptr()) } != 1 {
            return Err(Error::Crypto);
        }
        pem::string(&bio)
    }

    pub(crate) fn public_key(&self) -> Result<PublicKey> {
        // SAFETY: `self` is live and AWS-LC returns a newly owned key reference.
        unsafe { PublicKey::from_raw_supported(X509_REQ_get_pubkey(self.as_ptr())) }
    }

    pub(crate) fn subject(&self) -> Result<Vec<NameEntry>> {
        // SAFETY: The returned name is borrowed from live `self` and copied
        // before this method returns.
        read_name(unsafe { X509_REQ_get_subject_name(self.as_ptr()) })
    }

    pub(crate) fn subject_alt_names(&self) -> Result<Vec<SubjectAlternativeName>> {
        // SAFETY: `self` is live. AWS-LC returns a newly owned extension stack.
        let extensions = unsafe { X509_REQ_get_extensions(self.as_ptr()) };
        if extensions.is_null() {
            // SAFETY: `self` is live; this only inspects request attributes.
            return if unsafe { X509_REQ_get_attr_by_NID(self.as_ptr(), NID_ext_req, -1) } == -1 {
                Ok(Vec::new())
            } else {
                Err(Error::InvalidEncoding)
            };
        }
        // SAFETY: The returned stack owns X509_EXTENSION values.
        let extensions: Stack<aws_lc_sys::X509_EXTENSION> =
            unsafe { Stack::from_raw(extensions.cast::<OPENSSL_STACK>(), free_extension) }?;
        let mut critical = -1;
        // SAFETY: `extensions` is live. For subjectAltName, AWS-LC returns a
        // newly owned GENERAL_NAMES value on success.
        let names = unsafe {
            X509V3_get_d2i(
                extensions
                    .as_ptr()
                    .cast::<aws_lc_sys::stack_st_X509_EXTENSION>(),
                NID_subject_alt_name,
                &mut critical,
                ptr::null_mut(),
            )
        };
        decode_subject_alt_names(names, critical)
    }

    pub(crate) fn verify_signature(&self) -> Result<()> {
        self.validate_signature_algorithm()?;
        let public_key = self.public_key()?;
        // SAFETY: Both handles remain live for the call.
        if unsafe { X509_REQ_verify(self.as_ptr(), public_key.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }

    fn validate_signature_algorithm(&self) -> Result<()> {
        let mut signature_algorithm = ptr::null();
        // SAFETY: `self` is live. The returned algorithm is borrowed from it.
        unsafe {
            X509_REQ_get0_signature(self.as_ptr(), ptr::null_mut(), &mut signature_algorithm);
        };
        validate_signature_algorithm(signature_algorithm)
    }

    pub(crate) fn build(
        subject: &DistinguishedName,
        subject_alt_names: &[SubjectAlternativeName],
        key: &PrivateKey,
    ) -> Result<Self> {
        // SAFETY: AWS-LC returns a new owned request.
        let request = unsafe { Self::from_raw(X509_REQ_new()) }?;
        // SAFETY: All inputs remain live; the setters copy or retain their
        // inputs as documented by AWS-LC.
        if unsafe { X509_REQ_set_version(request.as_ptr(), 0) } != 1
            || unsafe { X509_REQ_set_subject_name(request.as_ptr(), subject.as_ptr()) } != 1
            || unsafe { X509_REQ_set_pubkey(request.as_ptr(), key.as_ptr()) } != 1
        {
            return Err(Error::Crypto);
        }

        if !subject_alt_names.is_empty() {
            let names = super::owned::GeneralNames::new(subject_alt_names)?;
            let extensions = ExtensionStack::new()?;
            extensions.push(names.to_extension(false)?)?;
            // SAFETY: Both values remain live. AWS-LC copies the extensions
            // into the request attribute.
            if unsafe {
                X509_REQ_add_extensions(
                    request.as_ptr(),
                    extensions
                        .as_ptr()
                        .cast::<aws_lc_sys::stack_st_X509_EXTENSION>(),
                )
            } != 1
            {
                return Err(Error::Crypto);
            }
        }

        // SAFETY: The request and private key are live, and EVP_sha256 returns
        // a process-lifetime digest descriptor.
        if unsafe { X509_REQ_sign(request.as_ptr(), key.as_ptr(), EVP_sha256()) } <= 0 {
            return Err(Error::Crypto);
        }
        request.verify_signature()?;
        Ok(request)
    }
}

fn validate_signature_algorithm(algorithm: *const aws_lc_sys::X509_ALGOR) -> Result<()> {
    if algorithm.is_null() {
        return Err(Error::InvalidEncoding);
    }
    let mut object = ptr::null();
    let mut parameter_type = 0;
    // SAFETY: `algorithm` is live and borrowed from its enclosing X.509 value;
    // the output pointers refer only to storage owned by that value.
    unsafe { X509_ALGOR_get0(&mut object, &mut parameter_type, ptr::null_mut(), algorithm) };
    if object.is_null() {
        return Err(Error::InvalidEncoding);
    }
    // SAFETY: `object` is live and borrowed from `algorithm`.
    let nid = unsafe { OBJ_obj2nid(object) };
    // Accepted when reading certificates and CSRs. ECDSA carries no algorithm
    // parameters; RSA PKCS#1 v1.5 requires explicit NULL parameters.
    // Generation is pinned to SHA-256 in `X509_sign` and `X509_REQ_sign`.
    let supported = ((nid == NID_ecdsa_with_SHA256 || nid == NID_ecdsa_with_SHA384)
        && parameter_type == V_ASN1_UNDEF)
        || ((nid == NID_sha256WithRSAEncryption || nid == NID_sha384WithRSAEncryption)
            && parameter_type == V_ASN1_NULL);
    if !supported {
        return Err(Error::UnsupportedAlgorithm);
    }
    Ok(())
}

fn decode_subject_alt_names(
    names: *mut c_void,
    critical: i32,
) -> Result<Vec<SubjectAlternativeName>> {
    if names.is_null() {
        return if critical == -1 {
            Ok(Vec::new())
        } else {
            Err(Error::InvalidEncoding)
        };
    }
    // SAFETY: For the subjectAltName NID, AWS-LC returned a newly owned
    // GENERAL_NAMES value.
    let names = unsafe { super::owned::GeneralNames::from_raw(names.cast()) }?;
    names.entries()
}

fn read_time(time: *const aws_lc_sys::ASN1_TIME) -> Result<i64> {
    if time.is_null() {
        return Err(Error::InvalidEncoding);
    }
    let mut timestamp = 0;
    // SAFETY: `time` is live and non-null, and `timestamp` is writable.
    if unsafe { ASN1_TIME_to_posix(time, &mut timestamp) } != 1 {
        return Err(Error::InvalidEncoding);
    }
    Ok(timestamp)
}

fn build_certificate(
    params: CertificateParams<'_>,
    subject_key: *mut aws_lc_sys::EVP_PKEY,
    issuer_name: *mut aws_lc_sys::X509_NAME,
    issuer_key: *mut aws_lc_sys::EVP_PKEY,
) -> Result<Certificate> {
    if params.not_before > params.not_after {
        return Err(Error::InvalidEncoding);
    }
    let subject_is_empty = params.subject.entries()?.is_empty();
    if subject_is_empty
        && (matches!(
            params.profile,
            CertificateProfile::CertificateAuthority { .. }
        ) || params.subject_alt_names.is_empty())
    {
        return Err(Error::InvalidEncoding);
    }
    // SAFETY: AWS-LC returns a new owned certificate.
    let certificate = unsafe { Certificate::from_raw(X509_new()) }?;
    let serial = match params.serial_number {
        Some(serial) => serial_number(serial)?,
        None => random_serial_number()?,
    };
    let not_before = asn1_time(params.not_before)?;
    let not_after = asn1_time(params.not_after)?;

    // SAFETY: All inputs remain live. AWS-LC copies the serial, names, times,
    // and public key into the certificate.
    if unsafe { X509_set_version(certificate.as_ptr(), 2) } != 1
        || unsafe { X509_set_serialNumber(certificate.as_ptr(), serial.as_ptr()) } != 1
        || unsafe { X509_set_subject_name(certificate.as_ptr(), params.subject.as_ptr()) } != 1
        || unsafe { X509_set_issuer_name(certificate.as_ptr(), issuer_name) } != 1
        || unsafe { X509_set1_notBefore(certificate.as_ptr(), not_before.as_ptr()) } != 1
        || unsafe { X509_set1_notAfter(certificate.as_ptr(), not_after.as_ptr()) } != 1
        || unsafe { X509_set_pubkey(certificate.as_ptr(), subject_key) } != 1
    {
        return Err(Error::Crypto);
    }

    for extension in profile_extensions(params.profile, params.subject_alt_names, subject_is_empty)?
    {
        // SAFETY: Both values remain live and AWS-LC copies the extension.
        if unsafe { X509_add_ext(certificate.as_ptr(), extension.as_ptr(), -1) } != 1 {
            return Err(Error::Crypto);
        }
    }

    // SAFETY: The certificate and issuer key remain live, and EVP_sha256
    // returns a process-lifetime digest descriptor.
    if unsafe { X509_sign(certificate.as_ptr(), issuer_key, EVP_sha256()) } <= 0 {
        return Err(Error::Crypto);
    }
    Ok(certificate)
}

fn profile_extensions(
    profile: CertificateProfile,
    subject_alt_names: &[SubjectAlternativeName],
    subject_is_empty: bool,
) -> Result<Vec<Extension>> {
    let mut extensions = Vec::with_capacity(4);
    match profile {
        CertificateProfile::Server => {
            extensions.push(Extension::basic_constraints(false, None, false)?);
            extensions.push(Extension::key_usage(&[0])?);
            extensions.push(Extension::extended_key_usage(&[NID_server_auth])?);
        }
        CertificateProfile::Client => {
            extensions.push(Extension::basic_constraints(false, None, false)?);
            extensions.push(Extension::key_usage(&[0])?);
            extensions.push(Extension::extended_key_usage(&[NID_client_auth])?);
        }
        CertificateProfile::ServerAndClient => {
            extensions.push(Extension::basic_constraints(false, None, false)?);
            extensions.push(Extension::key_usage(&[0])?);
            extensions.push(Extension::extended_key_usage(&[
                NID_server_auth,
                NID_client_auth,
            ])?);
        }
        CertificateProfile::CertificateAuthority { path_length } => {
            extensions.push(Extension::basic_constraints(true, path_length, true)?);
            extensions.push(Extension::key_usage(&[0, 5, 6])?);
        }
    }
    if !subject_alt_names.is_empty() {
        extensions.push(
            super::owned::GeneralNames::new(subject_alt_names)?.to_extension(subject_is_empty)?,
        );
    }
    Ok(extensions)
}

impl Extension {
    fn basic_constraints(ca: bool, path_length: Option<u8>, critical: bool) -> Result<Self> {
        // SAFETY: AWS-LC returns a new owned BASIC_CONSTRAINTS.
        let constraints = unsafe { BasicConstraints::from_raw(BASIC_CONSTRAINTS_new()) }?;
        // SAFETY: `constraints` is uniquely owned. `ca` uses ASN.1's canonical
        // true value. A path-length integer transfers to `constraints`.
        unsafe {
            (*constraints.as_ptr()).ca = if ca { 0xff } else { 0 };
        }
        if let Some(path_length) = path_length {
            // SAFETY: AWS-LC returns a new owned ASN1_INTEGER.
            let integer = unsafe { Asn1Integer::from_raw(ASN1_INTEGER_new()) }?;
            // SAFETY: `integer` is uniquely owned.
            if unsafe { ASN1_INTEGER_set_uint64(integer.as_ptr(), u64::from(path_length)) } != 1 {
                return Err(Error::Crypto);
            }
            // SAFETY: `constraints` is uniquely owned and takes ownership of
            // `integer`, which is then intentionally forgotten.
            unsafe { (*constraints.as_ptr()).pathlen = integer.as_ptr() };
            std::mem::forget(integer);
        }
        extension_from_typed(NID_basic_constraints, critical, constraints.as_ptr().cast())
    }

    fn key_usage(bits: &[i32]) -> Result<Self> {
        // SAFETY: AWS-LC returns a new owned ASN1_BIT_STRING.
        let usage = unsafe { BitString::from_raw(ASN1_BIT_STRING_new()) }?;
        for bit in bits {
            // SAFETY: `usage` is live and uniquely owned.
            if unsafe { ASN1_BIT_STRING_set_bit(usage.as_ptr(), *bit, 1) } != 1 {
                return Err(Error::Crypto);
            }
        }
        extension_from_typed(NID_key_usage, true, usage.as_ptr().cast())
    }

    fn extended_key_usage(nids: &[i32]) -> Result<Self> {
        // SAFETY: AWS-LC returns a new owned EXTENDED_KEY_USAGE stack.
        let usage = unsafe { ExtendedKeyUsage::from_raw(EXTENDED_KEY_USAGE_new()) }?;
        for nid in nids {
            // SAFETY: OBJ_nid2obj returns a process-lifetime static object.
            // EXTENDED_KEY_USAGE_free may call ASN1_OBJECT_free, which AWS-LC
            // documents as a no-op for static objects.
            let object = unsafe { OBJ_nid2obj(*nid) };
            if object.is_null()
                || unsafe {
                    OPENSSL_sk_push(
                        usage.as_ptr().cast::<OPENSSL_STACK>(),
                        object.cast::<c_void>(),
                    )
                } == 0
            {
                return Err(Error::Crypto);
            }
        }
        extension_from_typed(NID_ext_key_usage, false, usage.as_ptr().cast())
    }
}

fn extension_from_typed(nid: i32, critical: bool, value: *mut c_void) -> Result<Extension> {
    // SAFETY: Each caller passes the typed structure required by `nid`.
    unsafe { Extension::from_raw(X509V3_EXT_i2d(nid, i32::from(critical), value)) }
        .map_err(|_| Error::Crypto)
}

fn serial_number(bytes: &[u8]) -> Result<Asn1Integer> {
    if bytes.is_empty() || bytes.len() > 20 || bytes.iter().all(|byte| *byte == 0) {
        return Err(Error::InvalidEncoding);
    }
    // A 20-byte value with its high bit set needs a 21-byte positive DER
    // encoding, which exceeds RFC 5280's limit.
    if bytes.len() == 20 && bytes[0] & 0x80 != 0 {
        return Err(Error::InvalidEncoding);
    }
    // SAFETY: `bytes` is non-empty and readable. AWS-LC allocates the result.
    let number =
        unsafe { BigNumber::from_raw(BN_bin2bn(bytes.as_ptr(), bytes.len(), ptr::null_mut())) }?;
    // SAFETY: `number` is live and AWS-LC allocates the result.
    unsafe { Asn1Integer::from_raw(BN_to_ASN1_INTEGER(number.as_ptr(), ptr::null_mut())) }
}

fn random_serial_number() -> Result<Asn1Integer> {
    let mut bytes = [0_u8; 20];
    // SAFETY: `bytes` is writable for its full length.
    if unsafe { RAND_bytes(bytes.as_mut_ptr(), bytes.len()) } != 1 {
        return Err(Error::Crypto);
    }
    bytes[0] &= 0x7f;
    bytes[bytes.len() - 1] |= 1;
    serial_number(&bytes)
}

fn asn1_time(timestamp: i64) -> Result<Asn1Time> {
    // SAFETY: AWS-LC returns a new owned ASN1_TIME.
    let time = unsafe { Asn1Time::from_raw(ASN1_TIME_new()) }?;
    // SAFETY: `time` is live and uniquely owned.
    if unsafe { ASN1_TIME_set_posix(time.as_ptr(), timestamp) }.is_null() {
        return Err(Error::InvalidEncoding);
    }
    Ok(time)
}

unsafe extern "C" fn free_extension(pointer: *mut c_void) {
    // SAFETY: The extension stack contains only owned X509_EXTENSION values.
    unsafe { aws_lc_sys::X509_EXTENSION_free(pointer.cast()) };
}

struct ExtensionStack(Stack<aws_lc_sys::X509_EXTENSION>);

impl ExtensionStack {
    fn new() -> Result<Self> {
        // SAFETY: AWS-LC returns a new owned stack, and every inserted element
        // is an owned X509_EXTENSION.
        unsafe { Stack::from_raw(OPENSSL_sk_new_null(), free_extension) }.map(Self)
    }

    fn push(&self, extension: Extension) -> Result<()> {
        // SAFETY: Both values are live and uniquely owned. A successful push
        // transfers the extension to the stack.
        if unsafe { OPENSSL_sk_push(self.0.as_ptr(), extension.as_ptr().cast::<c_void>()) } == 0 {
            return Err(Error::Allocation);
        }
        std::mem::forget(extension);
        Ok(())
    }

    fn as_ptr(&self) -> *mut OPENSSL_STACK {
        self.0.as_ptr()
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use aws_lc_sys::{NID_subject_alt_name, X509_get_ext_d2i};

    use crate::ffi::verify::{verify_chain, Purpose, VerificationSubject};
    use crate::ffi::{
        Certificate, CertificateRequest, DistinguishedName, Error, NameAttribute, PrivateKey,
        SubjectAlternativeName,
    };

    use super::{CertificateParams, CertificateProfile};

    fn self_signed_certificate(subject: &DistinguishedName, key: &PrivateKey) -> Certificate {
        Certificate::self_signed(
            CertificateParams {
                subject,
                not_before: 1_700_000_000,
                not_after: 1_800_000_000,
                serial_number: Some(&[1]),
                subject_alt_names: &[],
                profile: CertificateProfile::Server,
            },
            key,
        )
        .expect("certificate construction should succeed")
    }

    fn test_authority() -> (Certificate, PrivateKey) {
        let key = PrivateKey::generate_p256().unwrap();
        let subject =
            DistinguishedName::new([(NameAttribute::Common, "Verification test CA")]).unwrap();
        let certificate = Certificate::self_signed(
            CertificateParams {
                subject: &subject,
                not_before: 1_700_000_000,
                not_after: 1_800_000_000,
                serial_number: Some(&[1]),
                subject_alt_names: &[],
                profile: CertificateProfile::CertificateAuthority { path_length: None },
            },
            &key,
        )
        .unwrap();
        (certificate, key)
    }

    fn test_issued_certificate(
        issuer: &Certificate,
        issuer_key: &PrivateKey,
        key: &PrivateKey,
        profile: CertificateProfile,
        names: &[SubjectAlternativeName],
    ) -> Certificate {
        let subject =
            DistinguishedName::new([(NameAttribute::Common, "service.example.com")]).unwrap();
        Certificate::signed_by(
            CertificateParams {
                subject: &subject,
                not_before: 1_700_000_000,
                not_after: 1_800_000_000,
                serial_number: Some(&[2]),
                subject_alt_names: names,
                profile,
            },
            &key.public_key().unwrap(),
            issuer,
            issuer_key,
        )
        .unwrap()
    }

    fn replace_test_extension(
        certificate: &Certificate,
        issuer_key: &PrivateKey,
        nid: i32,
        extension: Option<super::Extension>,
    ) {
        // SAFETY: This test owns the live certificate and has not yet read
        // cached extensions. Deletion transfers ownership of the old extension.
        let index = unsafe { aws_lc_sys::X509_get_ext_by_NID(certificate.as_ptr(), nid, -1) };
        if index >= 0 {
            let removed = unsafe {
                super::Extension::from_raw(aws_lc_sys::X509_delete_ext(certificate.as_ptr(), index))
            }
            .unwrap();
            drop(removed);
        }
        if let Some(extension) = extension {
            // SAFETY: Both objects are live; X509_add_ext copies the extension.
            assert_eq!(
                unsafe { super::X509_add_ext(certificate.as_ptr(), extension.as_ptr(), -1) },
                1
            );
        }
        // SAFETY: The certificate and issuer key are live. Signing refreshes
        // the encoded certificate after the extension change.
        assert!(
            unsafe {
                super::X509_sign(
                    certificate.as_ptr(),
                    issuer_key.as_ptr(),
                    super::EVP_sha256(),
                )
            } > 0
        );
    }

    #[test]
    fn tls_verification_enforces_intermediate_eku() {
        let (root, root_key) = test_authority();
        let intermediate_key = PrivateKey::generate_p256().unwrap();
        let leaf_key = PrivateKey::generate_p256().unwrap();
        for (eku, server, client) in [
            (None, true, true),
            (Some(super::NID_server_auth), true, false),
            (Some(super::NID_client_auth), false, true),
        ] {
            let intermediate = test_issued_certificate(
                &root,
                &root_key,
                &intermediate_key,
                CertificateProfile::CertificateAuthority {
                    path_length: Some(0),
                },
                &[],
            );
            if let Some(eku) = eku {
                replace_test_extension(
                    &intermediate,
                    &root_key,
                    super::NID_ext_key_usage,
                    Some(super::Extension::extended_key_usage(&[eku]).unwrap()),
                );
            }
            let leaf = test_issued_certificate(
                &intermediate,
                &intermediate_key,
                &leaf_key,
                CertificateProfile::ServerAndClient,
                &[SubjectAlternativeName::Dns(
                    "service.example.com".to_owned(),
                )],
            );
            for (purpose, expected) in [(Purpose::TlsServer, server), (Purpose::TlsClient, client)]
            {
                let result = verify_chain(
                    &leaf,
                    std::slice::from_ref(&intermediate),
                    std::slice::from_ref(&root),
                    Some(1_750_000_000),
                    Some(VerificationSubject::Dns("service.example.com")),
                    purpose,
                );
                if expected {
                    result.unwrap();
                } else {
                    assert!(matches!(result, Err(Error::Verification)));
                }
            }
        }
    }

    #[test]
    fn tls_verification_checks_key_usage_and_allows_absent_eku() {
        let (issuer, issuer_key) = test_authority();
        let key = PrivateKey::generate_p256().unwrap();
        for purpose in [Purpose::TlsServer, Purpose::TlsClient] {
            let leaf = test_issued_certificate(
                &issuer,
                &issuer_key,
                &key,
                CertificateProfile::ServerAndClient,
                &[SubjectAlternativeName::Dns(
                    "service.example.com".to_owned(),
                )],
            );
            replace_test_extension(&leaf, &issuer_key, super::NID_ext_key_usage, None);
            verify_chain(
                &leaf,
                &[],
                std::slice::from_ref(&issuer),
                Some(1_750_000_000),
                Some(VerificationSubject::Dns("service.example.com")),
                purpose,
            )
            .unwrap();
        }
        for purpose in [Purpose::TlsServer, Purpose::TlsClient] {
            let leaf = test_issued_certificate(
                &issuer,
                &issuer_key,
                &key,
                CertificateProfile::ServerAndClient,
                &[SubjectAlternativeName::Dns(
                    "service.example.com".to_owned(),
                )],
            );
            replace_test_extension(
                &leaf,
                &issuer_key,
                super::NID_key_usage,
                Some(super::Extension::key_usage(&[1]).unwrap()),
            );
            verify_chain(
                &leaf,
                &[],
                std::slice::from_ref(&issuer),
                Some(1_750_000_000),
                None,
                Purpose::ChainOnly,
            )
            .unwrap();
            assert!(matches!(
                verify_chain(
                    &leaf,
                    &[],
                    std::slice::from_ref(&issuer),
                    Some(1_750_000_000),
                    Some(VerificationSubject::Dns("service.example.com")),
                    purpose
                ),
                Err(Error::Verification)
            ));
        }
    }

    #[test]
    fn tls_verification_matches_only_sans_and_whole_label_wildcards() {
        let (issuer, issuer_key) = test_authority();
        let key = PrivateKey::generate_p256().unwrap();
        for (name, reference, expected) in [
            (None, "service.example.com", false),
            (Some("service.example.com"), "SERVICE.example.com", true),
            (Some("service.example.com"), "other.example.com", false),
            (Some("*.example.com"), "service.example.com", true),
            (Some("*.example.com"), "nested.service.example.com", false),
            (Some("*.example.com"), "example.com", false),
            (Some("serv*.example.com"), "service.example.com", false),
        ] {
            let names: Vec<_> = name
                .into_iter()
                .map(|name| SubjectAlternativeName::Dns(name.to_owned()))
                .collect();
            let leaf = test_issued_certificate(
                &issuer,
                &issuer_key,
                &key,
                CertificateProfile::Server,
                &names,
            );
            verify_chain(
                &leaf,
                &[],
                std::slice::from_ref(&issuer),
                Some(1_750_000_000),
                None,
                Purpose::ChainOnly,
            )
            .unwrap();
            let result = verify_chain(
                &leaf,
                &[],
                std::slice::from_ref(&issuer),
                Some(1_750_000_000),
                Some(VerificationSubject::Dns(reference)),
                Purpose::TlsServer,
            );
            if expected {
                result.unwrap();
            } else {
                assert!(
                    matches!(result, Err(Error::Verification)),
                    "SAN {name:?} must not match {reference:?}"
                );
            }
        }
        for address in ["127.0.0.1", "::1"] {
            let address = address.parse().unwrap();
            let leaf = test_issued_certificate(
                &issuer,
                &issuer_key,
                &key,
                CertificateProfile::Server,
                &[SubjectAlternativeName::Ip(address)],
            );
            verify_chain(
                &leaf,
                &[],
                std::slice::from_ref(&issuer),
                Some(1_750_000_000),
                Some(VerificationSubject::Ip(address)),
                Purpose::TlsServer,
            )
            .unwrap();
            assert!(matches!(
                verify_chain(
                    &leaf,
                    &[],
                    std::slice::from_ref(&issuer),
                    Some(1_750_000_000),
                    Some(VerificationSubject::Ip("192.0.2.1".parse().unwrap())),
                    Purpose::TlsServer
                ),
                Err(Error::Verification)
            ));
        }
    }

    #[test]
    fn rejects_malformed_certificate_der() {
        assert!(matches!(
            Certificate::from_der(b"not DER"),
            Err(Error::InvalidEncoding)
        ));
    }

    #[test]
    fn rejects_malformed_request_der() {
        assert!(matches!(
            CertificateRequest::from_der(b"not DER"),
            Err(Error::InvalidEncoding)
        ));
    }

    #[test]
    fn accepts_sha384_signatures_when_reading() {
        let subject = DistinguishedName::new([(NameAttribute::Common, "localhost")])
            .expect("name construction should succeed");
        for key in [
            PrivateKey::generate_p256().unwrap(),
            PrivateKey::generate_rsa(2048).unwrap(),
        ] {
            let request = CertificateRequest::build(&subject, &[], &key).unwrap();
            let certificate = self_signed_certificate(&subject, &key);
            // SAFETY: The request, certificate, and key are live test-owned
            // objects. AWS-LC supplies the process-lifetime SHA-384 descriptor.
            unsafe {
                assert!(
                    aws_lc_sys::X509_REQ_sign(
                        request.as_ptr(),
                        key.as_ptr(),
                        aws_lc_sys::EVP_sha384()
                    ) > 0
                );
                assert!(
                    aws_lc_sys::X509_sign(
                        certificate.as_ptr(),
                        key.as_ptr(),
                        aws_lc_sys::EVP_sha384()
                    ) > 0
                );
            }
            let request_der = request.to_der().unwrap();
            let request_pem = request.to_pem().unwrap();
            let parsed = crate::CertificateSigningRequest::from_der(&request_der).unwrap();
            assert_eq!(
                crate::CertificateSigningRequest::from_pem(&request_pem).unwrap(),
                parsed
            );
            assert_eq!(
                parsed.public_key().unwrap().as_spki_der(),
                key.public_key_der().unwrap()
            );

            let parsed = crate::Certificate::from_der(&certificate.to_der().unwrap()).unwrap();
            assert_eq!(
                crate::Certificate::from_pem(&certificate.to_pem().unwrap()).unwrap(),
                parsed
            );
            let public_key =
                crate::PublicKey::from_spki_der(&key.public_key_der().unwrap()).unwrap();
            parsed.verify_signature(&public_key).unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_signature_algorithms() {
        let subject = DistinguishedName::new([(NameAttribute::Common, "localhost")])
            .expect("name construction should succeed");
        for key in [
            PrivateKey::generate_p256().unwrap(),
            PrivateKey::generate_rsa(2048).unwrap(),
        ] {
            let request = CertificateRequest::build(&subject, &[], &key).unwrap();
            let certificate = self_signed_certificate(&subject, &key);
            let public_key = key.public_key().unwrap();
            // SAFETY: Test-owned objects are live; signing and direct AWS-LC
            // verification establish a valid signature outside this crate's policy.
            unsafe {
                assert!(
                    aws_lc_sys::X509_REQ_sign(
                        request.as_ptr(),
                        key.as_ptr(),
                        aws_lc_sys::EVP_sha512()
                    ) > 0
                );
                assert!(
                    aws_lc_sys::X509_sign(
                        certificate.as_ptr(),
                        key.as_ptr(),
                        aws_lc_sys::EVP_sha512()
                    ) > 0
                );
                assert_eq!(
                    aws_lc_sys::X509_REQ_verify(request.as_ptr(), public_key.as_ptr()),
                    1
                );
                assert_eq!(
                    aws_lc_sys::X509_verify(certificate.as_ptr(), public_key.as_ptr()),
                    1
                );
            }
            assert!(matches!(
                CertificateRequest::from_der(&request.to_der().unwrap()),
                Err(Error::UnsupportedAlgorithm)
            ));
            assert!(matches!(
                CertificateRequest::from_pem(&request.to_pem().unwrap()),
                Err(Error::UnsupportedAlgorithm)
            ));
            assert!(matches!(
                Certificate::from_der(&certificate.to_der().unwrap()),
                Err(Error::UnsupportedAlgorithm)
            ));
            assert!(matches!(
                Certificate::from_pem(&certificate.to_pem().unwrap()),
                Err(Error::UnsupportedAlgorithm)
            ));
        }
    }

    #[test]
    fn enforces_empty_subject_rules() {
        let key = PrivateKey::generate_p256().expect("key generation should succeed");
        let subject = DistinguishedName::new(std::iter::empty())
            .expect("empty name construction should succeed");
        let base_params = CertificateParams {
            subject: &subject,
            not_before: 1_700_000_000,
            not_after: 1_800_000_000,
            serial_number: Some(&[1]),
            subject_alt_names: &[],
            profile: CertificateProfile::Server,
        };
        assert!(matches!(
            Certificate::self_signed(base_params, &key),
            Err(Error::InvalidEncoding)
        ));

        let names = [SubjectAlternativeName::Dns("localhost".to_owned())];
        let certificate = Certificate::self_signed(
            CertificateParams {
                subject_alt_names: &names,
                ..base_params
            },
            &key,
        )
        .expect("a SAN permits an empty subject");
        let mut critical = -1;
        // SAFETY: `certificate` is live. AWS-LC returns newly owned names.
        let names = unsafe {
            X509_get_ext_d2i(
                certificate.as_ptr(),
                NID_subject_alt_name,
                &mut critical,
                ptr::null_mut(),
            )
        };
        // SAFETY: subjectAltName decoding returned an owned GENERAL_NAMES.
        let _names = unsafe { super::super::owned::GeneralNames::from_raw(names.cast()) }
            .expect("subjectAltName should decode");
        assert_eq!(critical, 1);
    }

    #[test]
    fn rejects_an_issuer_without_ca_capability() {
        let issuer_key = PrivateKey::generate_p256().expect("issuer key generation should succeed");
        let issuer_subject = DistinguishedName::new([(NameAttribute::Common, "Not a CA")])
            .expect("issuer name construction should succeed");
        let issuer = Certificate::self_signed(
            CertificateParams {
                subject: &issuer_subject,
                not_before: 1_700_000_000,
                not_after: 1_800_000_000,
                serial_number: Some(&[1]),
                subject_alt_names: &[],
                profile: CertificateProfile::Server,
            },
            &issuer_key,
        )
        .expect("issuer construction should succeed");
        let subject_key = PrivateKey::generate_p256()
            .expect("subject key generation should succeed")
            .public_key()
            .expect("public key extraction should succeed");
        let subject = DistinguishedName::new([(NameAttribute::Common, "Leaf")])
            .expect("subject name construction should succeed");
        assert!(matches!(
            Certificate::signed_by(
                CertificateParams {
                    subject: &subject,
                    not_before: 1_700_000_000,
                    not_after: 1_800_000_000,
                    serial_number: Some(&[2]),
                    subject_alt_names: &[],
                    profile: CertificateProfile::Server,
                },
                &subject_key,
                &issuer,
                &issuer_key,
            ),
            Err(Error::InvalidEncoding)
        ));
    }

    #[test]
    fn builds_and_verifies_certificate_request() {
        let key = PrivateKey::generate_p256().expect("key generation should succeed");
        let subject = DistinguishedName::new([(NameAttribute::Common, "localhost")])
            .expect("name construction should succeed");
        let names = [SubjectAlternativeName::Dns("localhost".to_owned())];

        let request = CertificateRequest::build(&subject, &names, &key)
            .expect("request construction should succeed");
        request
            .verify_signature()
            .expect("request signature should verify");
        let der = request.to_der().expect("request encoding should succeed");
        let parsed = CertificateRequest::from_der(&der).expect("request parsing should succeed");
        parsed
            .verify_signature()
            .expect("parsed request signature should verify");
        assert_eq!(
            parsed.subject().expect("request subject should parse")[0].value,
            "localhost"
        );
        assert_eq!(
            parsed
                .subject_alt_names()
                .expect("request SANs should parse"),
            names
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn builds_self_signed_and_issuer_signed_certificates() {
        let ca_key = PrivateKey::generate_p256().expect("CA key generation should succeed");
        let ca_subject = DistinguishedName::new([(NameAttribute::Common, "Test CA")])
            .expect("CA name construction should succeed");
        let ca = Certificate::self_signed(
            CertificateParams {
                subject: &ca_subject,
                not_before: 1_700_000_000,
                not_after: 1_800_000_000,
                serial_number: Some(&[1]),
                subject_alt_names: &[],
                profile: CertificateProfile::CertificateAuthority {
                    path_length: Some(0),
                },
            },
            &ca_key,
        )
        .expect("CA certificate construction should succeed");
        let ca_public_key = ca_key
            .public_key()
            .expect("public key extraction should succeed");
        ca.verify_signature(&ca_public_key)
            .expect("self-signature should verify");

        let leaf_key = PrivateKey::generate_p256().expect("leaf key generation should succeed");
        let leaf_public_key = leaf_key
            .public_key()
            .expect("leaf public key extraction should succeed");
        let leaf_subject = DistinguishedName::new([(NameAttribute::Common, "localhost")])
            .expect("leaf name construction should succeed");
        let names = [
            SubjectAlternativeName::Dns("localhost".to_owned()),
            SubjectAlternativeName::Ip("127.0.0.1".parse().expect("valid IP address")),
        ];
        let leaf = Certificate::signed_by(
            CertificateParams {
                subject: &leaf_subject,
                not_before: 1_700_000_000,
                not_after: 1_800_000_000,
                serial_number: None,
                subject_alt_names: &names,
                profile: CertificateProfile::Server,
            },
            &leaf_public_key,
            &ca,
            &ca_key,
        )
        .expect("leaf certificate construction should succeed");
        leaf.verify_signature(&ca_public_key)
            .expect("issuer signature should verify");

        let der = leaf.to_der().expect("certificate encoding should succeed");
        let parsed = Certificate::from_der(&der).expect("certificate parsing should succeed");
        let pem = parsed.to_pem().expect("certificate PEM should encode");
        let parsed = Certificate::from_pem(&pem).expect("certificate PEM should parse");
        parsed
            .verify_signature(&ca_public_key)
            .expect("parsed certificate signature should verify");
        assert_eq!(
            parsed.subject().expect("subject should parse")[0].value,
            "localhost"
        );
        assert_eq!(
            parsed.issuer().expect("issuer should parse")[0].value,
            "Test CA"
        );
        assert_eq!(
            parsed.subject_alt_names().expect("SANs should parse"),
            names
        );
        assert_eq!(
            parsed.validity().expect("validity should parse"),
            (1_700_000_000, 1_800_000_000)
        );
        assert_ne!(
            parsed.serial_number().expect("serial should parse"),
            [] as [u8; 0]
        );
        let _parsed_public_key = parsed.public_key().expect("public key should parse");

        verify_chain(
            &parsed,
            &[],
            std::slice::from_ref(&ca),
            Some(1_750_000_000),
            Some(VerificationSubject::Dns("localhost")),
            Purpose::TlsServer,
        )
        .expect("trusted chain and DNS name should verify");
        verify_chain(
            &parsed,
            &[],
            std::slice::from_ref(&ca),
            Some(1_750_000_000),
            Some(VerificationSubject::Ip(
                "127.0.0.1".parse().expect("valid IP address"),
            )),
            Purpose::TlsServer,
        )
        .expect("trusted chain and IP address should verify");
        assert!(matches!(
            verify_chain(
                &parsed,
                &[],
                std::slice::from_ref(&ca),
                Some(1_750_000_000),
                Some(VerificationSubject::Dns("example.com")),
                Purpose::TlsServer,
            ),
            Err(Error::Verification)
        ));
        assert!(matches!(
            verify_chain(
                &parsed,
                &[],
                &[],
                Some(1_750_000_000),
                Some(VerificationSubject::Dns("localhost")),
                Purpose::TlsServer,
            ),
            Err(Error::Verification)
        ));
    }
}
