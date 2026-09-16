use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::{self, NonNull};
use std::slice;

use aws_lc_sys::{
    ASN1_IA5STRING_new, ASN1_OCTET_STRING_new, ASN1_STRING_set, ASN1_STRING_to_UTF8,
    GENERAL_NAMES_new, GENERAL_NAME_get0_value, GENERAL_NAME_new, GENERAL_NAME_set0_value,
    NID_commonName, NID_countryName, NID_localityName, NID_organizationName,
    NID_organizationalUnitName, NID_stateOrProvinceName, NID_subject_alt_name, OBJ_obj2nid,
    OPENSSL_free, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, X509V3_EXT_i2d,
    X509_NAME_ENTRY_get_data, X509_NAME_ENTRY_get_object, X509_NAME_add_entry_by_NID,
    X509_NAME_entry_count, X509_NAME_get_entry, X509_NAME_new, GEN_DNS, GEN_IPADD, MBSTRING_UTF8,
    OPENSSL_STACK,
};

use super::owned::{Asn1String, DistinguishedName, Extension, GeneralName, GeneralNames};
use super::{Error, Result};

/// A distinguished-name attribute supported by the public API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NameAttribute {
    Country,
    StateOrProvince,
    Locality,
    Organization,
    OrganizationalUnit,
    Common,
}

/// An owned distinguished-name entry returned from AWS-LC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NameEntry {
    pub(crate) attribute: NameAttribute,
    pub(crate) value: String,
}

/// A subject alternative name supported by the public API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SubjectAlternativeName {
    Dns(String),
    Ip(IpAddr),
}

impl DistinguishedName {
    pub(crate) fn new<'a>(
        entries: impl IntoIterator<Item = (NameAttribute, &'a str)>,
    ) -> Result<Self> {
        // SAFETY: AWS-LC returns a new owned X509_NAME.
        let name = unsafe { Self::from_raw(X509_NAME_new()) }?;
        for (attribute, value) in entries {
            let length = isize::try_from(value.len()).map_err(|_| Error::InvalidEncoding)?;
            // SAFETY: `name` is live, and `value` points to `length` readable
            // bytes. AWS-LC copies the value into the new entry.
            if unsafe {
                X509_NAME_add_entry_by_NID(
                    name.as_ptr(),
                    attribute.nid(),
                    MBSTRING_UTF8,
                    value.as_ptr(),
                    length,
                    -1,
                    0,
                )
            } != 1
            {
                return Err(Error::Crypto);
            }
        }
        Ok(name)
    }

    pub(crate) fn entries(&self) -> Result<Vec<NameEntry>> {
        read_name(self.as_ptr())
    }
}

impl NameAttribute {
    fn nid(self) -> i32 {
        match self {
            Self::Country => NID_countryName,
            Self::StateOrProvince => NID_stateOrProvinceName,
            Self::Locality => NID_localityName,
            Self::Organization => NID_organizationName,
            Self::OrganizationalUnit => NID_organizationalUnitName,
            Self::Common => NID_commonName,
        }
    }

    fn from_nid(nid: i32) -> Result<Self> {
        if nid == NID_countryName {
            Ok(Self::Country)
        } else if nid == NID_stateOrProvinceName {
            Ok(Self::StateOrProvince)
        } else if nid == NID_localityName {
            Ok(Self::Locality)
        } else if nid == NID_organizationName {
            Ok(Self::Organization)
        } else if nid == NID_organizationalUnitName {
            Ok(Self::OrganizationalUnit)
        } else if nid == NID_commonName {
            Ok(Self::Common)
        } else {
            Err(Error::UnsupportedNameAttribute)
        }
    }
}

pub(super) fn read_name(name: *const aws_lc_sys::X509_NAME) -> Result<Vec<NameEntry>> {
    if name.is_null() {
        return Err(Error::InvalidEncoding);
    }
    // SAFETY: `name` is live for this call.
    let count = unsafe { X509_NAME_entry_count(name) };
    let count = usize::try_from(count).map_err(|_| Error::InvalidEncoding)?;
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let index = i32::try_from(index).map_err(|_| Error::InvalidEncoding)?;
        // SAFETY: `index` is within the count reported by AWS-LC. The entry,
        // object, and value pointers are borrowed from `name`.
        let entry = unsafe { X509_NAME_get_entry(name, index) };
        if entry.is_null() {
            return Err(Error::InvalidEncoding);
        }
        let object = unsafe { X509_NAME_ENTRY_get_object(entry) };
        let value = unsafe { X509_NAME_ENTRY_get_data(entry) };
        if object.is_null() || value.is_null() {
            return Err(Error::InvalidEncoding);
        }
        let attribute = NameAttribute::from_nid(unsafe { OBJ_obj2nid(object) })?;
        entries.push(NameEntry {
            attribute,
            value: asn1_string_to_utf8(value)?,
        });
    }
    Ok(entries)
}

impl GeneralNames {
    pub(crate) fn new(names: &[SubjectAlternativeName]) -> Result<Self> {
        // SAFETY: AWS-LC returns a new owned GENERAL_NAMES stack.
        let general_names = unsafe { Self::from_raw(GENERAL_NAMES_new()) }?;
        for name in names {
            let general_name = match name {
                SubjectAlternativeName::Dns(name) => {
                    make_general_name(GEN_DNS, name.as_bytes(), ASN1_IA5STRING_new)?
                }
                SubjectAlternativeName::Ip(IpAddr::V4(address)) => {
                    make_general_name(GEN_IPADD, &address.octets(), ASN1_OCTET_STRING_new)?
                }
                SubjectAlternativeName::Ip(IpAddr::V6(address)) => {
                    make_general_name(GEN_IPADD, &address.octets(), ASN1_OCTET_STRING_new)?
                }
            };
            // SAFETY: Both values are live and uniquely owned. A successful
            // push transfers ownership of `general_name` to `general_names`.
            if unsafe {
                OPENSSL_sk_push(
                    general_names.as_ptr().cast::<OPENSSL_STACK>(),
                    general_name.as_ptr().cast::<c_void>(),
                )
            } == 0
            {
                return Err(Error::Allocation);
            }
            std::mem::forget(general_name);
        }
        Ok(general_names)
    }

    pub(crate) fn entries(&self) -> Result<Vec<SubjectAlternativeName>> {
        let stack = self.as_ptr().cast::<OPENSSL_STACK>();
        // SAFETY: `stack` is a live GENERAL_NAMES stack.
        let count = unsafe { OPENSSL_sk_num(stack) };
        let mut names = Vec::with_capacity(count);
        for index in 0..count {
            // SAFETY: `index` is within the count reported by AWS-LC. The
            // returned GENERAL_NAME is borrowed from `self`.
            let name = unsafe { OPENSSL_sk_value(stack, index) }.cast::<aws_lc_sys::GENERAL_NAME>();
            if name.is_null() {
                return Err(Error::InvalidEncoding);
            }
            let mut name_type = -1;
            // SAFETY: `name` is live and `name_type` is writable. The returned
            // ASN1_STRING is borrowed and is interpreted only after type check.
            let value = unsafe { GENERAL_NAME_get0_value(name, &mut name_type) };
            if !matches!(name_type, GEN_DNS | GEN_IPADD) {
                return Err(Error::UnsupportedSubjectAltName);
            }
            if value.is_null() {
                return Err(Error::InvalidEncoding);
            }
            let bytes = asn1_string_bytes(value.cast())?;
            match name_type {
                GEN_DNS => {
                    let dns = std::str::from_utf8(&bytes)
                        .map_err(|_| Error::InvalidEncoding)?
                        .to_owned();
                    names.push(SubjectAlternativeName::Dns(dns));
                }
                GEN_IPADD => match bytes.as_slice() {
                    [a, b, c, d] => names.push(SubjectAlternativeName::Ip(IpAddr::V4(
                        Ipv4Addr::new(*a, *b, *c, *d),
                    ))),
                    bytes if bytes.len() == 16 => {
                        let octets: [u8; 16] =
                            bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
                        names.push(SubjectAlternativeName::Ip(IpAddr::V6(Ipv6Addr::from(
                            octets,
                        ))));
                    }
                    _ => return Err(Error::InvalidEncoding),
                },
                _ => return Err(Error::UnsupportedSubjectAltName),
            }
        }
        Ok(names)
    }

    pub(crate) fn to_extension(&self, critical: bool) -> Result<Extension> {
        // SAFETY: `self` is a GENERAL_NAMES value, the type required for the
        // subjectAltName NID. AWS-LC returns a newly owned extension.
        unsafe {
            Extension::from_raw(X509V3_EXT_i2d(
                NID_subject_alt_name,
                i32::from(critical),
                self.as_ptr().cast::<c_void>(),
            ))
        }
        .map_err(|_| Error::Crypto)
    }
}

fn make_general_name(
    name_type: i32,
    bytes: &[u8],
    new_string: unsafe extern "C" fn() -> *mut aws_lc_sys::ASN1_STRING,
) -> Result<GeneralName> {
    // SAFETY: The constructor returns a new owned ASN1_STRING.
    let string = unsafe { Asn1String::from_raw(new_string()) }?;
    let length = isize::try_from(bytes.len()).map_err(|_| Error::InvalidEncoding)?;
    // SAFETY: `string` is live, and `bytes` points to `length` readable bytes.
    if unsafe { ASN1_STRING_set(string.as_ptr(), bytes.as_ptr().cast(), length) } != 1 {
        return Err(Error::Crypto);
    }
    // SAFETY: AWS-LC returns a new, empty GENERAL_NAME.
    let name = unsafe { GeneralName::from_raw(GENERAL_NAME_new()) }?;
    // SAFETY: `name` is empty and the type matches the allocated string kind.
    // Ownership of `string` transfers to `name`.
    unsafe { GENERAL_NAME_set0_value(name.as_ptr(), name_type, string.as_ptr().cast()) };
    std::mem::forget(string);
    Ok(name)
}

fn asn1_string_to_utf8(value: *const aws_lc_sys::ASN1_STRING) -> Result<String> {
    let mut output = ptr::null_mut();
    // SAFETY: `value` is live for the call. AWS-LC allocates `output` on
    // success, and it must be released with OPENSSL_free.
    let length = unsafe { ASN1_STRING_to_UTF8(&mut output, value) };
    let length = usize::try_from(length).map_err(|_| Error::InvalidEncoding)?;
    let output = NonNull::new(output).ok_or(Error::InvalidEncoding)?;
    // SAFETY: AWS-LC initialized `length` bytes at `output`.
    let bytes = unsafe { slice::from_raw_parts(output.as_ptr(), length) };
    let value = std::str::from_utf8(bytes)
        .map_err(|_| Error::InvalidEncoding)
        .map(str::to_owned);
    // SAFETY: `output` was allocated by AWS-LC for ASN1_STRING_to_UTF8.
    unsafe { OPENSSL_free(output.as_ptr().cast()) };
    value
}

fn asn1_string_bytes(value: *const aws_lc_sys::ASN1_STRING) -> Result<Vec<u8>> {
    // SAFETY: `value` is a live ASN1_STRING borrowed by the caller.
    let length = unsafe { aws_lc_sys::ASN1_STRING_length(value) };
    let length = usize::try_from(length).map_err(|_| Error::InvalidEncoding)?;
    // SAFETY: AWS-LC returns its internal buffer, valid for `length` bytes and
    // for the lifetime of the owning GENERAL_NAME.
    let data = unsafe { aws_lc_sys::ASN1_STRING_get0_data(value) };
    if data.is_null() {
        return if length == 0 {
            Ok(Vec::new())
        } else {
            Err(Error::InvalidEncoding)
        };
    }
    // SAFETY: The pointer and length are supplied by the same ASN1_STRING.
    Ok(unsafe { slice::from_raw_parts(data, length) }.to_vec())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::ptr;

    use crate::ffi::owned::GeneralNames;
    use crate::ffi::{DistinguishedName, Error, NameAttribute, SubjectAlternativeName};

    #[test]
    fn rejects_non_string_subject_alt_names() {
        let fixtures: &[&[u8]] = &[
            &[
                0x30, 0x0e, 0xa0, 0x0c, 0x06, 0x03, 0x2a, 0x03, 0x04, 0xa0, 0x05, 0x0c, 0x03, b'Q',
                b'A', b'!',
            ],
            &[0x30, 0x04, 0xa4, 0x02, 0x30, 0x00],
            &[0x30, 0x05, 0x88, 0x03, 0x2a, 0x03, 0x04],
        ];
        for der in fixtures {
            let mut cursor = der.as_ptr();
            // SAFETY: The cursor covers the complete fixture. AWS-LC allocates
            // a GENERAL_NAMES whose ownership transfers to the wrapper.
            let names = unsafe {
                GeneralNames::from_raw(aws_lc_sys::d2i_GENERAL_NAMES(
                    ptr::null_mut(),
                    &mut cursor,
                    der.len().try_into().unwrap(),
                ))
            }
            .unwrap();
            assert_eq!(cursor, der.as_ptr().wrapping_add(der.len()));
            assert!(matches!(
                names.entries(),
                Err(Error::UnsupportedSubjectAltName)
            ));
        }
    }

    #[test]
    fn round_trips_supported_distinguished_name_entries() {
        let name = DistinguishedName::new([
            (NameAttribute::Country, "US"),
            (NameAttribute::Organization, "Example"),
            (NameAttribute::Common, "localhost"),
        ])
        .expect("name construction should succeed");

        let entries = name.entries().expect("name reading should succeed");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].value, "localhost");
    }

    #[test]
    fn round_trips_supported_subject_alt_names() {
        let expected = vec![
            SubjectAlternativeName::Dns("localhost".to_owned()),
            SubjectAlternativeName::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        let names = GeneralNames::new(&expected).expect("SAN construction should succeed");
        assert_eq!(
            names.entries().expect("SAN reading should succeed"),
            expected
        );
        let _extension = names
            .to_extension(false)
            .expect("SAN extension construction should succeed");
    }
}
