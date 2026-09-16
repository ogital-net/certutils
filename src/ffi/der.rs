use std::ffi::c_long;

use super::{Error, Result};

pub(super) fn input_length(input: &[u8]) -> Result<c_long> {
    c_long::try_from(input.len()).map_err(|_| Error::InvalidEncoding)
}

pub(super) fn consumed_all(input: &[u8], cursor: *const u8) -> bool {
    cursor == input.as_ptr().wrapping_add(input.len())
}

pub(super) fn encode(mut encode: impl FnMut(*mut *mut u8) -> i32) -> Result<Vec<u8>> {
    let length = encode(std::ptr::null_mut());
    let length = usize::try_from(length).map_err(|_| Error::Crypto)?;
    if length == 0 {
        return Err(Error::Crypto);
    }

    let mut der = vec![0; length];
    let mut cursor = der.as_mut_ptr();
    let written = encode(&mut cursor);
    if usize::try_from(written).ok() != Some(length)
        || cursor != der.as_mut_ptr().wrapping_add(length)
    {
        return Err(Error::Crypto);
    }
    Ok(der)
}
