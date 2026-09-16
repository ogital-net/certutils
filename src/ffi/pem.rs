use std::ffi::c_void;
use std::{ptr, slice};

use aws_lc_sys::{
    BIO_ctrl, BIO_get_mem_ptr, BIO_new, BIO_new_mem_buf, BIO_s_mem, OPENSSL_free, PEM_read_bio,
    BIO_CTRL_INFO,
};

use super::owned::Bio;
use super::{Error, Result};

pub(super) fn input<T>(input: &str, label: &str, decode: impl Fn(&[u8]) -> Result<T>) -> Result<T> {
    let mut result = None;
    chain_inputs(input, label, |der| {
        if result.is_some() {
            return Err(Error::InvalidEncoding);
        }
        result = Some(decode(der)?);
        Ok(())
    })?;
    result.ok_or(Error::InvalidEncoding)
}

pub(super) fn output() -> Result<Bio> {
    // SAFETY: BIO_new allocates a BIO owned by the returned wrapper.
    unsafe { Bio::from_raw(BIO_new(BIO_s_mem())) }
}

pub(super) fn string(bio: &Bio) -> Result<String> {
    let mut data = ptr::null_mut::<c_void>();
    // SAFETY: `bio` is a live memory BIO and `data` points to writable storage
    // for the borrowed buffer pointer.
    let length = unsafe {
        BIO_ctrl(
            bio.as_ptr(),
            BIO_CTRL_INFO,
            0,
            ptr::addr_of_mut!(data).cast(),
        )
    };
    let length = usize::try_from(length).map_err(|_| Error::Crypto)?;
    if data.is_null() {
        return if length == 0 {
            Ok(String::new())
        } else {
            Err(Error::Crypto)
        };
    }
    // SAFETY: BIO_CTRL_INFO returned a buffer of `length` bytes owned by `bio`.
    let bytes = unsafe { slice::from_raw_parts(data.cast::<u8>(), length) };
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::Crypto)
}

/// Returns the unread byte offset of a memory BIO within its original buffer.
fn remaining_offset(bio: &Bio, original_len: usize) -> Result<usize> {
    let mut contents = ptr::null_mut::<aws_lc_sys::BUF_MEM>();
    // SAFETY: `bio` is a live memory BIO and `contents` points to writable
    // storage for the borrowed BUF_MEM pointer.
    if unsafe { BIO_get_mem_ptr(bio.as_ptr(), ptr::addr_of_mut!(contents)) } != 1 {
        return Err(Error::Crypto);
    }
    // An empty memory BIO reports a null buffer; it is fully consumed.
    if contents.is_null() {
        return Ok(original_len);
    }
    // SAFETY: `contents` is live and its `length` is the unread byte count.
    let remaining = unsafe { (*contents).length };
    original_len
        .checked_sub(remaining)
        .ok_or(Error::InvalidEncoding)
}

/// Reads each `label` PEM block, invoking `handle` with its decoded bytes.
///
/// The scan is strict: the first block must start at offset 0, each
/// subsequent block must start exactly where the previous one ended (only
/// ASCII whitespace may separate blocks), and at least one block is required.
pub(super) fn chain_inputs(
    input: &str,
    label: &str,
    mut handle: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    if !input.is_ascii() || input.as_bytes().contains(&0) {
        return Err(Error::InvalidEncoding);
    }
    let begin = format!("-----BEGIN {label}-----");
    let mut remaining = input.as_bytes();
    let mut count = 0_usize;
    loop {
        if count > 0 {
            let whitespace = remaining
                .iter()
                .take_while(|byte| byte.is_ascii_whitespace())
                .count();
            remaining = &remaining[whitespace..];
        }
        if remaining.is_empty() {
            return if count > 0 {
                Ok(())
            } else {
                Err(Error::InvalidEncoding)
            };
        }
        if !remaining
            .strip_prefix(begin.as_bytes())
            .is_some_and(|suffix| suffix.starts_with(b"\n") || suffix.starts_with(b"\r\n"))
        {
            return Err(Error::InvalidEncoding);
        }
        let length = isize::try_from(remaining.len()).map_err(|_| Error::InvalidEncoding)?;
        // SAFETY: `remaining` outlives this non-owning memory BIO. Its length
        // is checked and it begins at the exact expected PEM boundary.
        let bio = unsafe { Bio::from_raw(BIO_new_mem_buf(remaining.as_ptr().cast(), length)) }?;
        let mut name = ptr::null_mut();
        let mut header = ptr::null_mut();
        let mut data = ptr::null_mut();
        let mut data_len = 0;
        // SAFETY: `bio` is live. On success AWS-LC allocates `name`, `header`,
        // and `data`, each released below with OPENSSL_free.
        let found = unsafe {
            PEM_read_bio(
                bio.as_ptr(),
                &mut name,
                &mut header,
                &mut data,
                &mut data_len,
            )
        };
        if found != 1 {
            return Err(Error::InvalidEncoding);
        }
        // SAFETY: `name`, `header`, and `data` were allocated by AWS-LC for
        // this PEM block.
        let block = unsafe { ParsedBlock::from_raw(name, header, data, data_len) }?;
        let consumed = remaining_offset(&bio, remaining.len())?;
        if consumed == 0 || block.name() != label || !block.header_is_empty() {
            return Err(Error::InvalidEncoding);
        }
        handle(block.data())?;
        remaining = &remaining[consumed..];
        count += 1;
    }
}

/// Owned buffers returned by `PEM_read_bio`, released with `OPENSSL_free`.
struct ParsedBlock {
    name: ptr::NonNull<c_void>,
    header: ptr::NonNull<c_void>,
    data: ptr::NonNull<c_void>,
    data_len: usize,
}

impl ParsedBlock {
    /// Takes ownership of the buffers AWS-LC allocated for one PEM block.
    ///
    /// All three pointers must be non-null AWS-LC allocations; `len` is the
    /// decoded byte count for `data`.
    unsafe fn from_raw(
        name: *mut c_char,
        header: *mut c_char,
        data: *mut u8,
        len: std::ffi::c_long,
    ) -> Result<Self> {
        let data_len = usize::try_from(len).map_err(|_| Error::InvalidEncoding)?;
        Ok(Self {
            name: ptr::NonNull::new(name.cast::<c_void>()).ok_or(Error::InvalidEncoding)?,
            header: ptr::NonNull::new(header.cast::<c_void>()).ok_or(Error::InvalidEncoding)?,
            data: ptr::NonNull::new(data.cast::<c_void>()).ok_or(Error::InvalidEncoding)?,
            data_len,
        })
    }

    fn name(&self) -> &str {
        // SAFETY: `name` is a NUL-terminated string allocated by AWS-LC.
        unsafe { std::ffi::CStr::from_ptr(self.name.as_ptr().cast::<c_char>()) }
            .to_str()
            .unwrap_or("")
    }

    fn data(&self) -> &[u8] {
        // SAFETY: `data` points to `data_len` decoded bytes owned by `self`.
        unsafe { slice::from_raw_parts(self.data.as_ptr().cast::<u8>(), self.data_len) }
    }

    fn header_is_empty(&self) -> bool {
        // SAFETY: `header` is a NUL-terminated string allocated by AWS-LC.
        unsafe { std::ffi::CStr::from_ptr(self.header.as_ptr().cast::<c_char>()) }
            .to_bytes()
            .is_empty()
    }
}

impl Drop for ParsedBlock {
    fn drop(&mut self) {
        // SAFETY: each pointer was allocated by AWS-LC in `PEM_read_bio`.
        unsafe {
            OPENSSL_free(self.name.as_ptr());
            OPENSSL_free(self.header.as_ptr());
            OPENSSL_free(self.data.as_ptr());
        }
    }
}

use std::ffi::c_char;

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::ptr;
    use std::time::{Duration, UNIX_EPOCH};

    use crate::{
        Certificate, CertificateProfile, CertificateSigningRequest, DistinguishedName, PrivateKey,
        PublicKey, Validity,
    };

    use super::{chain_inputs, input, output, string};

    const BLOCK: &str = "-----BEGIN TEST-----\nMAA=\n-----END TEST-----\n";

    fn assert_rejects_der_suffix(
        label: &str,
        der: &[u8],
        encoding: &str,
        parse: impl Fn(&str) -> crate::Result<()>,
    ) {
        let label = CString::new(label).unwrap();
        for suffix in [&[][..], &[0][..], der] {
            let mut payload = der.to_vec();
            payload.extend_from_slice(suffix);
            let bio = output().unwrap();
            // SAFETY: The BIO, NUL-terminated label, and byte buffer remain live.
            // AWS-LC reads the checked byte count and writes into the memory BIO.
            assert!(
                unsafe {
                    aws_lc_sys::PEM_write_bio(
                        bio.as_ptr(),
                        label.as_ptr(),
                        ptr::null(),
                        payload.as_ptr(),
                        payload.len().try_into().unwrap(),
                    )
                } > 0
            );
            let result = parse(&string(&bio).unwrap());
            if suffix.is_empty() {
                result.unwrap();
            } else {
                assert!(
                    matches!(result, Err(crate::Error::InvalidEncoding { encoding: actual }) if actual == encoding),
                    "{label:?}: DER suffix of {} bytes must be rejected as {encoding}",
                    suffix.len()
                );
            }
        }
    }

    #[test]
    fn rejects_trailing_der_in_all_pem_imports() {
        let key = PrivateKey::generate().unwrap();
        let certificate = Certificate::builder(
            DistinguishedName::builder()
                .common_name("PEM test")
                .build()
                .unwrap(),
            Validity::new(UNIX_EPOCH, UNIX_EPOCH + Duration::from_secs(1)).unwrap(),
            CertificateProfile::Server,
        )
        .self_signed(&key)
        .unwrap();
        let request = CertificateSigningRequest::builder().build(&key).unwrap();
        assert_rejects_der_suffix("CERTIFICATE", certificate.as_der(), "X.509 PEM", |pem| {
            Certificate::from_pem(pem).map(|_| ())
        });
        assert_rejects_der_suffix("CERTIFICATE", certificate.as_der(), "X.509 PEM", |pem| {
            Certificate::from_pem_chain(pem).map(|_| ())
        });
        assert_rejects_der_suffix(
            "CERTIFICATE REQUEST",
            request.as_der(),
            "PKCS#10 PEM",
            |pem| CertificateSigningRequest::from_pem(pem).map(|_| ()),
        );
        assert_rejects_der_suffix(
            "PRIVATE KEY",
            &key.to_pkcs8_der().unwrap(),
            "PKCS#8 PEM",
            |pem| PrivateKey::from_pkcs8_pem(pem).map(|_| ()),
        );
        assert_rejects_der_suffix(
            "PUBLIC KEY",
            key.public_key().unwrap().as_spki_der(),
            "SPKI PEM",
            |pem| PublicKey::from_spki_pem(pem).map(|_| ()),
        );
    }

    #[test]
    fn accepts_only_whitespace_between_blocks() {
        for separator in ["", "\n", " \t\r\n", " \t"] {
            let pem = format!("{BLOCK}{separator}{BLOCK}\n \t");
            let mut count = 0;
            chain_inputs(&pem, "TEST", |der| {
                assert_eq!(der, &[0x30, 0x00]);
                count += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(count, 2);
        }
        assert!(input(&BLOCK.replace('\n', "\r\n"), "TEST", |_| Ok(())).is_ok());
        assert!(input(BLOCK.trim_end(), "TEST", |_| Ok(())).is_ok());
    }

    #[test]
    fn rejects_malformed_or_ambiguous_envelopes() {
        for pem in [
            String::new(),
            format!("junk\n{BLOCK}"),
            format!("\n{BLOCK}"),
            format!("{BLOCK}junk\n{BLOCK}"),
            format!("{BLOCK}-----BEGIN TEST-----junk\n{BLOCK}"),
            format!("-----BEGIN TEST-----junk\n{BLOCK}"),
            format!("{BLOCK}junk"),
            format!("{BLOCK}-----BEGIN TEST-----\nMAA="),
            BLOCK.replace("END TEST", "END OTHER"),
            BLOCK.replace("MAA=", "!!!!"),
            BLOCK.replace("MAA=", "MAA=\0ignored"),
            BLOCK.replace("MAA=", "Comment: unsupported\n\nMAA="),
            BLOCK.replace("MAA=", "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00000000000000000000000000000000\n\nMAA="),
        ] {
            assert!(matches!(chain_inputs(&pem, "TEST", |_| Ok(())), Err(super::Error::InvalidEncoding)),
                "malformed envelope was not rejected: {pem:?}");
        }
        assert!(matches!(
            input(&format!("{BLOCK}{BLOCK}"), "TEST", |_| Ok(())),
            Err(super::Error::InvalidEncoding)
        ));
        assert!(matches!(
            input(BLOCK, "OTHER", |_| Ok(())),
            Err(super::Error::InvalidEncoding)
        ));
    }

    #[test]
    fn reads_an_empty_memory_bio() {
        let bio = output().expect("memory BIO allocation should succeed");
        assert_eq!(string(&bio).expect("empty BIO should be readable"), "");
    }
}
