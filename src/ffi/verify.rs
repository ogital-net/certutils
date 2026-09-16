use std::ffi::c_void;
use std::net::IpAddr;
use std::ptr::NonNull;

use aws_lc_sys::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_push, X509_STORE_CTX_get0_param,
    X509_STORE_CTX_init, X509_STORE_CTX_new, X509_STORE_add_cert, X509_STORE_new,
    X509_VERIFY_PARAM_set1_host, X509_VERIFY_PARAM_set1_ip, X509_VERIFY_PARAM_set_hostflags,
    X509_VERIFY_PARAM_set_purpose, X509_VERIFY_PARAM_set_time_posix, X509_check_ca,
    X509_verify_cert, OPENSSL_STACK, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS, X509_PURPOSE_SSL_CLIENT, X509_PURPOSE_SSL_SERVER,
};

use super::owned::{Certificate, CertificateStore, CertificateStoreContext};
use super::{Error, Result};

pub(crate) enum VerificationSubject<'a> {
    Dns(&'a str),
    Ip(IpAddr),
}

#[derive(Clone, Copy)]
pub(crate) enum Purpose {
    ChainOnly,
    TlsServer,
    TlsClient,
}

pub(crate) fn verify_chain(
    end_entity: &Certificate,
    intermediates: &[Certificate],
    trust_anchors: &[Certificate],
    time: Option<i64>,
    subject: Option<VerificationSubject<'_>>,
    purpose: Purpose,
) -> Result<()> {
    // SAFETY: AWS-LC returns a new owned trust store.
    let store = unsafe { CertificateStore::from_raw(X509_STORE_new()) }?;
    for trust_anchor in trust_anchors {
        // SAFETY: Both values are live. AWS-LC increments the certificate's
        // reference count, so the store retains its own reference.
        if unsafe { X509_STORE_add_cert(store.as_ptr(), trust_anchor.as_ptr()) } != 1 {
            return Err(Error::Crypto);
        }
    }

    let intermediate_stack = BorrowedCertificateStack::new()?;
    for intermediate in intermediates {
        intermediate_stack.push(intermediate)?;
    }

    // Declared after its borrowed dependencies so it is dropped first.
    // SAFETY: AWS-LC returns a new owned store context.
    let context = unsafe { CertificateStoreContext::from_raw(X509_STORE_CTX_new()) }?;
    // SAFETY: Store, leaf, and intermediate stack all outlive `context`.
    if unsafe {
        X509_STORE_CTX_init(
            context.as_ptr(),
            store.as_ptr(),
            end_entity.as_ptr(),
            intermediate_stack
                .as_ptr()
                .cast::<aws_lc_sys::stack_st_X509>(),
        )
    } != 1
    {
        return Err(Error::Crypto);
    }

    // SAFETY: The returned parameters are borrowed from live `context`.
    let parameters = unsafe { X509_STORE_CTX_get0_param(context.as_ptr()) };
    if parameters.is_null() {
        return Err(Error::Crypto);
    }
    let purpose = match purpose {
        Purpose::ChainOnly => None,
        Purpose::TlsServer => Some(X509_PURPOSE_SSL_SERVER),
        Purpose::TlsClient => Some(X509_PURPOSE_SSL_CLIENT),
    };
    if let Some(purpose) = purpose {
        // SAFETY: The certificate is live. TLS endpoints must not be CAs.
        if unsafe { X509_check_ca(end_entity.as_ptr()) } != 0 {
            return Err(Error::Verification);
        }
        // SAFETY: The parameters belong to this live context, and purpose is
        // one of AWS-LC's supported key usage and EKU validation policies.
        if unsafe { X509_VERIFY_PARAM_set_purpose(parameters, purpose) } != 1 {
            return Err(Error::Crypto);
        }
    }
    if let Some(time) = time {
        // SAFETY: `parameters` is live and uniquely associated with context.
        unsafe { X509_VERIFY_PARAM_set_time_posix(parameters, time) };
    }
    if let Some(subject) = subject {
        set_subject(parameters, &subject)?;
    }

    // SAFETY: The initialized context and all borrowed dependencies are live.
    if unsafe { X509_verify_cert(context.as_ptr()) } == 1 {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

fn set_subject(
    parameters: *mut aws_lc_sys::X509_VERIFY_PARAM,
    subject: &VerificationSubject<'_>,
) -> Result<()> {
    // SAFETY: `parameters` is live. These flags disable common-name fallback
    // and partial-label wildcards in certificate DNS names.
    unsafe {
        X509_VERIFY_PARAM_set_hostflags(
            parameters,
            u32::try_from(
                X509_CHECK_FLAG_NEVER_CHECK_SUBJECT | X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
            )
            .map_err(|_| Error::Crypto)?,
        );
    };
    let result = match subject {
        VerificationSubject::Dns(name) => {
            if !name.is_ascii() || name.as_bytes().contains(&0) {
                return Err(Error::InvalidEncoding);
            }
            // SAFETY: The bytes are readable for `name.len()` and AWS-LC copies
            // the hostname into the parameter object.
            unsafe { X509_VERIFY_PARAM_set1_host(parameters, name.as_ptr().cast(), name.len()) }
        }
        VerificationSubject::Ip(IpAddr::V4(address)) => {
            let bytes = address.octets();
            // SAFETY: `bytes` is readable for four bytes and AWS-LC copies it.
            unsafe { X509_VERIFY_PARAM_set1_ip(parameters, bytes.as_ptr(), bytes.len()) }
        }
        VerificationSubject::Ip(IpAddr::V6(address)) => {
            let bytes = address.octets();
            // SAFETY: `bytes` is readable for 16 bytes and AWS-LC copies it.
            unsafe { X509_VERIFY_PARAM_set1_ip(parameters, bytes.as_ptr(), bytes.len()) }
        }
    };
    if result == 1 {
        Ok(())
    } else {
        Err(Error::Crypto)
    }
}

struct BorrowedCertificateStack(NonNull<OPENSSL_STACK>);

impl BorrowedCertificateStack {
    fn new() -> Result<Self> {
        // SAFETY: AWS-LC returns a new owned, empty stack.
        let pointer = unsafe { OPENSSL_sk_new_null() };
        NonNull::new(pointer).map(Self).ok_or(Error::Allocation)
    }

    fn push(&self, certificate: &Certificate) -> Result<()> {
        // SAFETY: The stack and certificate are live. The stack borrows this
        // pointer only for the enclosing verification call.
        if unsafe { OPENSSL_sk_push(self.0.as_ptr(), certificate.as_ptr().cast::<c_void>()) } == 0 {
            Err(Error::Allocation)
        } else {
            Ok(())
        }
    }

    fn as_ptr(&self) -> *mut OPENSSL_STACK {
        self.0.as_ptr()
    }
}

impl Drop for BorrowedCertificateStack {
    fn drop(&mut self) {
        // SAFETY: This stack owns only its container, not certificate values.
        unsafe { OPENSSL_sk_free(self.0.as_ptr()) };
    }
}
