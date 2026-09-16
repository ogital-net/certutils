use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::NonNull;

use aws_lc_sys::{
    ASN1_BIT_STRING_free, ASN1_INTEGER_free, ASN1_STRING_free, ASN1_TIME_free,
    BASIC_CONSTRAINTS_free, BIO_free, BN_free, EVP_PKEY_free, EXTENDED_KEY_USAGE_free,
    GENERAL_NAMES_free, GENERAL_NAME_free, OPENSSL_sk_pop_free_ex, RSA_free, X509_EXTENSION_free,
    X509_NAME_free, X509_REQ_free, X509_STORE_CTX_free, X509_STORE_free, X509_free,
    ASN1_BIT_STRING, ASN1_INTEGER, ASN1_STRING, ASN1_TIME, BASIC_CONSTRAINTS, BIGNUM, BIO,
    EVP_PKEY, EXTENDED_KEY_USAGE, GENERAL_NAME, GENERAL_NAMES, OPENSSL_STACK, RSA, X509,
    X509_EXTENSION, X509_NAME, X509_REQ, X509_STORE, X509_STORE_CTX,
};

use super::{Error, Result};

type Free<T> = unsafe extern "C" fn(*mut T);

pub(super) struct Owned<T> {
    pointer: NonNull<T>,
    free: Free<T>,
}

impl<T> Owned<T> {
    /// Takes ownership of a pointer returned by an AWS-LC allocating function.
    ///
    /// The pointer must either be null or uniquely owned, and `free` must be
    /// the matching destructor for `T`.
    pub(super) unsafe fn from_raw(pointer: *mut T, free: Free<T>) -> Result<Self> {
        let pointer = NonNull::new(pointer).ok_or(Error::Allocation)?;
        Ok(Self { pointer, free })
    }

    pub(super) fn as_ptr(&self) -> *mut T {
        self.pointer.as_ptr()
    }
}

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        // SAFETY: `pointer` is uniquely owned and `free` is its matching
        // destructor by the invariant of `from_raw`.
        unsafe { (self.free)(self.pointer.as_ptr()) };
    }
}

macro_rules! owned_handle {
    ($name:ident, $raw:ty, $free:path) => {
        pub(crate) struct $name(Owned<$raw>);

        impl $name {
            /// Takes ownership of a value allocated by AWS-LC.
            ///
            /// The pointer must be null or carry one owned reference.
            pub(super) unsafe fn from_raw(pointer: *mut $raw) -> Result<Self> {
                // SAFETY: The caller provides the ownership invariant and this
                // wrapper supplies the matching AWS-LC destructor.
                unsafe { Owned::from_raw(pointer, $free) }.map(Self)
            }

            pub(super) fn as_ptr(&self) -> *mut $raw {
                self.0.as_ptr()
            }
        }
    };
}

owned_handle!(PrivateKey, EVP_PKEY, EVP_PKEY_free);
owned_handle!(PublicKey, EVP_PKEY, EVP_PKEY_free);

// SAFETY: AWS-LC EVP_PKEY values are reference-counted, may be freed on any
// thread, and these wrappers expose only immutable operations after creation.
unsafe impl Send for PrivateKey {}
// SAFETY: Concurrent immutable EVP_PKEY operations are supported by AWS-LC.
unsafe impl Sync for PrivateKey {}
// SAFETY: The same guarantees apply to public-only EVP_PKEY values.
unsafe impl Send for PublicKey {}
// SAFETY: The same guarantees apply to public-only EVP_PKEY values.
unsafe impl Sync for PublicKey {}

owned_handle!(Certificate, X509, X509_free);
owned_handle!(CertificateRequest, X509_REQ, X509_REQ_free);
owned_handle!(DistinguishedName, X509_NAME, X509_NAME_free);
owned_handle!(CertificateStore, X509_STORE, X509_STORE_free);
owned_handle!(CertificateStoreContext, X509_STORE_CTX, X509_STORE_CTX_free);

unsafe extern "C" fn free_bio(pointer: *mut BIO) {
    // SAFETY: The caller passes an owned BIO pointer.
    let _ = unsafe { BIO_free(pointer) };
}

owned_handle!(Bio, BIO, free_bio);
owned_handle!(Asn1String, ASN1_STRING, ASN1_STRING_free);
owned_handle!(GeneralName, GENERAL_NAME, GENERAL_NAME_free);
owned_handle!(GeneralNames, GENERAL_NAMES, GENERAL_NAMES_free);
owned_handle!(Extension, X509_EXTENSION, X509_EXTENSION_free);
owned_handle!(Asn1Integer, ASN1_INTEGER, ASN1_INTEGER_free);
owned_handle!(Asn1Time, ASN1_TIME, ASN1_TIME_free);
owned_handle!(BigNumber, BIGNUM, BN_free);
owned_handle!(BitString, ASN1_BIT_STRING, ASN1_BIT_STRING_free);
owned_handle!(BasicConstraints, BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_free);
owned_handle!(Rsa, RSA, RSA_free);
owned_handle!(
    ExtendedKeyUsage,
    EXTENDED_KEY_USAGE,
    EXTENDED_KEY_USAGE_free
);

pub(super) struct Stack<T> {
    pointer: NonNull<OPENSSL_STACK>,
    free_element: unsafe extern "C" fn(*mut c_void),
    _element: PhantomData<T>,
}

impl<T> Stack<T> {
    /// Takes ownership of an AWS-LC stack and each element it contains.
    ///
    /// The pointer must be null or uniquely owned, and `free_element` must be
    /// the matching destructor for every element in the stack.
    pub(super) unsafe fn from_raw(
        pointer: *mut OPENSSL_STACK,
        free_element: unsafe extern "C" fn(*mut c_void),
    ) -> Result<Self> {
        let pointer = NonNull::new(pointer).ok_or(Error::Allocation)?;
        Ok(Self {
            pointer,
            free_element,
            _element: PhantomData,
        })
    }

    pub(super) fn as_ptr(&self) -> *mut OPENSSL_STACK {
        self.pointer.as_ptr()
    }
}

unsafe extern "C" fn call_free_element(
    free_element: Option<unsafe extern "C" fn(*mut c_void)>,
    element: *mut c_void,
) {
    if let Some(free_element) = free_element {
        // SAFETY: AWS-LC supplies an element owned by the stack, and
        // `Stack::from_raw` requires the matching element destructor.
        unsafe { free_element(element) };
    }
}

impl<T> Drop for Stack<T> {
    fn drop(&mut self) {
        // SAFETY: The stack and its elements are uniquely owned, and the
        // callback is the matching element destructor by `from_raw`.
        unsafe {
            OPENSSL_sk_pop_free_ex(
                self.pointer.as_ptr(),
                Some(call_free_element),
                Some(self.free_element),
            );
        };
    }
}
