use std::ffi::c_void;
use std::ptr;

use aws_lc_sys::{
    d2i_PKCS8_PRIV_KEY_INFO, d2i_PUBKEY, i2d_PKCS8_PRIV_KEY_INFO, i2d_PUBKEY, BN_get_word, BN_new,
    BN_set_word, EC_GROUP_get_curve_name, EC_KEY_free, EC_KEY_generate_key, EC_KEY_get0_group,
    EC_KEY_get0_private_key, EC_KEY_new_by_curve_name, EVP_PKEY_assign, EVP_PKEY_get0_EC_KEY,
    EVP_PKEY_get0_RSA, EVP_PKEY_id, EVP_PKEY_new, NID_X9_62_prime256v1, NID_secp384r1,
    PEM_write_bio_PKCS8_PRIV_KEY_INFO, PEM_write_bio_PUBKEY, PKCS8_PRIV_KEY_INFO_free, RSA_bits,
    RSA_generate_key_ex, RSA_get0_key, RSA_new, EVP_PKCS82PKEY, EVP_PKEY2PKCS8, EVP_PKEY_EC,
    EVP_PKEY_RSA, PKCS8_PRIV_KEY_INFO, RSA_F4,
};

use super::der;
use super::owned::{BigNumber, Owned, PrivateKey, PublicKey, Rsa};
use super::pem;
use super::{Error, Result};

type PrivateKeyInfo = Owned<PKCS8_PRIV_KEY_INFO>;

const MIN_RSA_BITS: u32 = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyAlgorithm {
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    RsaPkcs1Sha256,
}

impl PrivateKey {
    pub(crate) fn generate_p256() -> Result<Self> {
        // SAFETY: This allocates a fresh EC key with no aliases.
        let key = unsafe {
            Owned::from_raw(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free)?
        };

        // SAFETY: `key` points to a live, uniquely owned EC_KEY.
        if unsafe { EC_KEY_generate_key(key.as_ptr()) } != 1 {
            return Err(Error::Crypto);
        }

        // SAFETY: This allocates a fresh EVP_PKEY with no aliases.
        let pkey = unsafe { Self::from_raw(EVP_PKEY_new())? };

        // SAFETY: Both pointers are live and uniquely owned. On success,
        // EVP_PKEY_assign takes ownership of `key`.
        if unsafe { EVP_PKEY_assign(pkey.as_ptr(), EVP_PKEY_EC, key.as_ptr().cast::<c_void>()) }
            != 1
        {
            return Err(Error::Crypto);
        }

        std::mem::forget(key);
        Ok(pkey)
    }

    pub(crate) fn generate_rsa(bits: u32) -> Result<Self> {
        // SAFETY: AWS-LC returns fresh, uniquely owned values.
        let rsa = unsafe { Rsa::from_raw(RSA_new())? };
        let exponent = unsafe { BigNumber::from_raw(BN_new())? };
        // SAFETY: `exponent` and `rsa` are live and uniquely owned. AWS-LC
        // generates the private key using its configured random source.
        if unsafe { BN_set_word(exponent.as_ptr(), RSA_F4 as _) } != 1
            || unsafe {
                RSA_generate_key_ex(
                    rsa.as_ptr(),
                    i32::try_from(bits).map_err(|_| Error::Crypto)?,
                    exponent.as_ptr(),
                    ptr::null_mut(),
                )
            } != 1
        {
            return Err(Error::Crypto);
        }

        // SAFETY: This allocates a fresh EVP_PKEY with no aliases.
        let pkey = unsafe { Self::from_raw(EVP_PKEY_new())? };
        // SAFETY: Both pointers are live and uniquely owned. On success,
        // EVP_PKEY_assign takes ownership of `rsa`.
        if unsafe { EVP_PKEY_assign(pkey.as_ptr(), EVP_PKEY_RSA, rsa.as_ptr().cast::<c_void>()) }
            != 1
        {
            return Err(Error::Crypto);
        }

        std::mem::forget(rsa);
        Ok(pkey)
    }

    pub(crate) fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let length = der::input_length(der)?;
        let mut cursor = der.as_ptr();

        // SAFETY: `cursor` points to `length` readable bytes. Passing a null
        // output pointer asks AWS-LC to allocate a new PKCS#8 object.
        let info = unsafe {
            PrivateKeyInfo::from_raw(
                d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &mut cursor, length),
                PKCS8_PRIV_KEY_INFO_free,
            )
        }
        .map_err(|_| Error::InvalidEncoding)?;

        if !der::consumed_all(der, cursor) {
            return Err(Error::InvalidEncoding);
        }

        // SAFETY: `info` is a live PKCS#8 object. AWS-LC returns a new owned
        // EVP_PKEY and does not take ownership of `info`.
        let key = unsafe { Self::from_raw(EVP_PKCS82PKEY(info.as_ptr())) }
            .map_err(|_| Error::InvalidEncoding)?;
        validate_supported_key(key.as_ptr(), true)?;
        Ok(key)
    }

    pub(crate) fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        pem::input(pem, "PRIVATE KEY", Self::from_pkcs8_der)
    }

    pub(crate) fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        // SAFETY: `self` contains a live supported EVP_PKEY. AWS-LC returns a new
        // owned PKCS#8 object.
        let info = unsafe {
            PrivateKeyInfo::from_raw(EVP_PKEY2PKCS8(self.as_ptr()), PKCS8_PRIV_KEY_INFO_free)
        }
        .map_err(|_| Error::Crypto)?;
        der::encode(|output| {
            // SAFETY: `info` remains live for the call, and `output` follows
            // the i2d output-pointer contract.
            unsafe { i2d_PKCS8_PRIV_KEY_INFO(info.as_ptr(), output) }
        })
    }

    pub(crate) fn to_pkcs8_pem(&self) -> Result<String> {
        // SAFETY: `self` contains a live supported EVP_PKEY. AWS-LC returns a new
        // owned PKCS#8 object.
        let info = unsafe {
            PrivateKeyInfo::from_raw(EVP_PKEY2PKCS8(self.as_ptr()), PKCS8_PRIV_KEY_INFO_free)
        }
        .map_err(|_| Error::Crypto)?;
        let bio = pem::output()?;

        // SAFETY: `bio` and `info` remain live for the duration of the call.
        if unsafe { PEM_write_bio_PKCS8_PRIV_KEY_INFO(bio.as_ptr(), info.as_ptr()) } != 1 {
            return Err(Error::Crypto);
        }
        pem::string(&bio)
    }

    pub(crate) fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_spki_der(&self.public_key_der()?)
    }

    pub(crate) fn public_key_der(&self) -> Result<Vec<u8>> {
        encode_public_key(self.as_ptr())
    }

    pub(crate) fn algorithm(&self) -> Result<KeyAlgorithm> {
        validate_supported_key(self.as_ptr(), true)
    }
}

impl PublicKey {
    pub(crate) fn from_spki_der(der: &[u8]) -> Result<Self> {
        let length = der::input_length(der)?;
        let mut cursor = der.as_ptr();

        // SAFETY: `cursor` points to `length` readable bytes. Passing a null
        // output pointer asks AWS-LC to allocate a new EVP_PKEY.
        let key = unsafe { Self::from_raw(d2i_PUBKEY(ptr::null_mut(), &mut cursor, length)) }
            .map_err(|_| Error::InvalidEncoding)?;

        if !der::consumed_all(der, cursor) {
            return Err(Error::InvalidEncoding);
        }

        validate_supported_key(key.as_ptr(), false)?;
        Ok(key)
    }

    pub(crate) fn from_spki_pem(pem: &str) -> Result<Self> {
        pem::input(pem, "PUBLIC KEY", Self::from_spki_der)
    }

    pub(super) unsafe fn from_raw_supported(pointer: *mut aws_lc_sys::EVP_PKEY) -> Result<Self> {
        // SAFETY: The caller transfers one owned EVP_PKEY reference.
        let key = unsafe { Self::from_raw(pointer) }?;
        validate_supported_key(key.as_ptr(), false)?;
        Ok(key)
    }

    pub(crate) fn to_spki_der(&self) -> Result<Vec<u8>> {
        encode_public_key(self.as_ptr())
    }

    pub(crate) fn to_spki_pem(&self) -> Result<String> {
        let bio = pem::output()?;
        // SAFETY: `bio` and `self` remain live for the duration of the call.
        if unsafe { PEM_write_bio_PUBKEY(bio.as_ptr(), self.as_ptr()) } != 1 {
            return Err(Error::Crypto);
        }
        pem::string(&bio)
    }

    pub(crate) fn algorithm(&self) -> Result<KeyAlgorithm> {
        validate_supported_key(self.as_ptr(), false)
    }
}

fn validate_supported_key(
    key: *mut aws_lc_sys::EVP_PKEY,
    require_private: bool,
) -> Result<KeyAlgorithm> {
    // SAFETY: Callers pass a live EVP_PKEY for the duration of this function.
    match unsafe { EVP_PKEY_id(key) } {
        EVP_PKEY_EC => validate_ec(key, require_private),
        EVP_PKEY_RSA => {
            validate_rsa(key, require_private)?;
            Ok(KeyAlgorithm::RsaPkcs1Sha256)
        }
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

fn validate_ec(key: *mut aws_lc_sys::EVP_PKEY, require_private: bool) -> Result<KeyAlgorithm> {
    // SAFETY: Callers pass a live EVP_PKEY for the duration of this function.
    if unsafe { EVP_PKEY_id(key) } != EVP_PKEY_EC {
        return Err(Error::UnsupportedAlgorithm);
    }

    // SAFETY: The type check above establishes that this is an EC key. The
    // returned EC_KEY and group are borrowed from `key`.
    let ec_key = unsafe { EVP_PKEY_get0_EC_KEY(key) };
    if ec_key.is_null() {
        return Err(Error::Crypto);
    }
    // SAFETY: `ec_key` is live and borrowed from `key`.
    let group = unsafe { EC_KEY_get0_group(ec_key) };
    if group.is_null() {
        return Err(Error::Crypto);
    }
    // SAFETY: `group` is live and borrowed from `ec_key`.
    let curve = unsafe { EC_GROUP_get_curve_name(group) };
    let algorithm = if curve == NID_X9_62_prime256v1 {
        KeyAlgorithm::EcdsaP256Sha256
    } else if curve == NID_secp384r1 && !require_private {
        KeyAlgorithm::EcdsaP384Sha384
    } else {
        return Err(Error::UnsupportedAlgorithm);
    };
    // SAFETY: `ec_key` is live and borrowed from `key`.
    if require_private && unsafe { EC_KEY_get0_private_key(ec_key) }.is_null() {
        return Err(Error::InvalidEncoding);
    }

    Ok(algorithm)
}

fn validate_rsa(key: *mut aws_lc_sys::EVP_PKEY, require_private: bool) -> Result<()> {
    // SAFETY: The caller has established that `key` is a live RSA EVP_PKEY.
    let rsa = unsafe { EVP_PKEY_get0_RSA(key) };
    if rsa.is_null() {
        return Err(Error::Crypto);
    }
    let mut modulus = ptr::null();
    let mut public_exponent = ptr::null();
    let mut private_exponent = ptr::null();
    // SAFETY: `rsa` is live. The returned values borrow from `rsa`.
    unsafe {
        RSA_get0_key(
            rsa,
            &mut modulus,
            &mut public_exponent,
            &mut private_exponent,
        );
    };
    if modulus.is_null() || public_exponent.is_null() {
        return Err(Error::InvalidEncoding);
    }
    // SAFETY: `rsa` and `public_exponent` are live and borrowed from `key`.
    if unsafe { RSA_bits(rsa) } < MIN_RSA_BITS
        || unsafe { BN_get_word(public_exponent) }
            != aws_lc_sys::BN_ULONG::try_from(RSA_F4).map_err(|_| Error::Crypto)?
    {
        return Err(Error::UnsupportedAlgorithm);
    }
    if require_private && private_exponent.is_null() {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}

fn encode_public_key(key: *mut aws_lc_sys::EVP_PKEY) -> Result<Vec<u8>> {
    der::encode(|output| {
        // SAFETY: The caller holds `key` live for this call, and `output`
        // follows the i2d output-pointer contract.
        unsafe { i2d_PUBKEY(key, output) }
    })
}

#[cfg(test)]
mod tests {
    use crate::ffi::pkey::KeyAlgorithm;
    use crate::ffi::{Error, PrivateKey, PublicKey};

    #[test]
    fn accepts_p384_public_keys_without_expanding_private_key_support() {
        for (curve, supported) in [
            (aws_lc_sys::NID_secp384r1, true),
            (aws_lc_sys::NID_secp521r1, false),
        ] {
            // SAFETY: AWS-LC allocates uniquely owned test keys. The wrapper
            // supplies the matching destructor until ownership transfers below.
            let ec_key = unsafe {
                super::Owned::from_raw(
                    aws_lc_sys::EC_KEY_new_by_curve_name(curve),
                    aws_lc_sys::EC_KEY_free,
                )
            }
            .unwrap();
            // SAFETY: The EC key is live and uniquely owned during generation.
            assert_eq!(
                unsafe { aws_lc_sys::EC_KEY_generate_key(ec_key.as_ptr()) },
                1
            );
            // SAFETY: AWS-LC allocates a new owned EVP_PKEY.
            let key = unsafe { PrivateKey::from_raw(aws_lc_sys::EVP_PKEY_new()) }.unwrap();
            // SAFETY: On success the live EVP_PKEY takes ownership of the EC key.
            assert_eq!(
                unsafe {
                    aws_lc_sys::EVP_PKEY_assign(
                        key.as_ptr(),
                        aws_lc_sys::EVP_PKEY_EC,
                        ec_key.as_ptr().cast(),
                    )
                },
                1
            );
            std::mem::forget(ec_key);

            let public_der = key.public_key_der().unwrap();
            let public = PublicKey::from_spki_der(&public_der);
            if supported {
                let public = public.unwrap();
                assert_eq!(public.algorithm().unwrap(), KeyAlgorithm::EcdsaP384Sha384);
                assert_eq!(public.to_spki_der().unwrap(), public_der);
                let pem = public.to_spki_pem().unwrap();
                assert_eq!(
                    PublicKey::from_spki_pem(&pem)
                        .unwrap()
                        .to_spki_der()
                        .unwrap(),
                    public_der
                );
            } else {
                assert!(matches!(public, Err(Error::UnsupportedAlgorithm)));
            }
            assert!(matches!(
                PrivateKey::from_pkcs8_der(&key.to_pkcs8_der().unwrap()),
                Err(Error::UnsupportedAlgorithm)
            ));
            assert!(matches!(
                PrivateKey::from_pkcs8_pem(&key.to_pkcs8_pem().unwrap()),
                Err(Error::UnsupportedAlgorithm)
            ));
        }
    }

    #[test]
    fn generates_p256_private_key() {
        let _key = PrivateKey::generate_p256().expect("P-256 key generation should succeed");
    }

    #[test]
    fn generates_supported_rsa_private_keys() {
        for bits in [2048, 3072, 4096] {
            let key = PrivateKey::generate_rsa(bits).expect("RSA key generation should succeed");
            assert_eq!(key.algorithm().unwrap(), KeyAlgorithm::RsaPkcs1Sha256);
            // SAFETY: `key` is a live RSA key for the duration of these calls.
            let rsa = unsafe { aws_lc_sys::EVP_PKEY_get0_RSA(key.as_ptr()) };
            assert!(!rsa.is_null());
            assert_eq!(unsafe { aws_lc_sys::RSA_bits(rsa) }, bits);
        }
    }

    #[test]
    fn round_trips_strict_key_encodings() {
        let key = PrivateKey::generate_p256().expect("P-256 key generation should succeed");
        let expected_public_der = key.public_key_der().unwrap();

        let private_der = key.to_pkcs8_der().expect("PKCS#8 encoding should succeed");
        let parsed_private =
            PrivateKey::from_pkcs8_der(&private_der).expect("PKCS#8 parsing should succeed");

        let public_der = parsed_private
            .public_key_der()
            .expect("SPKI encoding should succeed");
        assert_eq!(public_der, expected_public_der);
        let public = PublicKey::from_spki_der(&public_der).expect("SPKI parsing should succeed");
        assert_eq!(
            public
                .to_spki_der()
                .expect("SPKI re-encoding should succeed"),
            public_der
        );

        let private_pem = key
            .to_pkcs8_pem()
            .expect("PKCS#8 PEM encoding should succeed");
        let parsed_private =
            PrivateKey::from_pkcs8_pem(&private_pem).expect("PKCS#8 PEM parsing should succeed");
        assert_eq!(
            parsed_private.public_key_der().unwrap(),
            expected_public_der
        );

        let public_pem = public
            .to_spki_pem()
            .expect("SPKI PEM encoding should succeed");
        let parsed_public =
            PublicKey::from_spki_pem(&public_pem).expect("SPKI PEM parsing should succeed");
        assert_eq!(parsed_public.to_spki_der().unwrap(), expected_public_der);
    }

    #[test]
    fn round_trips_rsa_key_encodings() {
        let key = PrivateKey::generate_rsa(2048).expect("RSA key generation should succeed");
        let expected_public_der = key.public_key_der().unwrap();
        let private_der = key.to_pkcs8_der().expect("PKCS#8 encoding should succeed");
        let parsed_private = PrivateKey::from_pkcs8_der(&private_der).unwrap();
        assert_eq!(
            parsed_private.algorithm().unwrap(),
            KeyAlgorithm::RsaPkcs1Sha256
        );

        let public_der = parsed_private.public_key_der().unwrap();
        assert_eq!(public_der, expected_public_der);
        let public = PublicKey::from_spki_der(&public_der).unwrap();
        assert_eq!(public.algorithm().unwrap(), KeyAlgorithm::RsaPkcs1Sha256);
        assert_eq!(public.to_spki_der().unwrap(), expected_public_der);

        let private_pem = key.to_pkcs8_pem().unwrap();
        let parsed_private = PrivateKey::from_pkcs8_pem(&private_pem).unwrap();
        assert_eq!(
            parsed_private.public_key_der().unwrap(),
            expected_public_der
        );
        let public_pem = public.to_spki_pem().unwrap();
        let parsed_public = PublicKey::from_spki_pem(&public_pem).unwrap();
        assert_eq!(parsed_public.to_spki_der().unwrap(), expected_public_der);
    }

    #[test]
    fn rejects_small_rsa_keys() {
        let key = PrivateKey::generate_rsa(1024).expect("test key generation should succeed");
        let private_der = key.to_pkcs8_der().unwrap();
        let public_der = key.public_key_der().unwrap();

        assert!(matches!(
            PrivateKey::from_pkcs8_der(&private_der),
            Err(Error::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            PublicKey::from_spki_der(&public_der),
            Err(Error::UnsupportedAlgorithm)
        ));
    }

    #[test]
    fn rejects_trailing_der_data() {
        let key = PrivateKey::generate_p256().expect("P-256 key generation should succeed");

        let mut private_der = key.to_pkcs8_der().expect("PKCS#8 encoding should succeed");
        private_der.push(0);
        assert!(matches!(
            PrivateKey::from_pkcs8_der(&private_der),
            Err(Error::InvalidEncoding)
        ));

        let mut public_der = key.public_key_der().expect("SPKI encoding should succeed");
        public_der.push(0);
        assert!(matches!(
            PublicKey::from_spki_der(&public_der),
            Err(Error::InvalidEncoding)
        ));
    }

    #[test]
    fn rejects_wrong_or_ambiguous_pem_envelopes() {
        let key = PrivateKey::generate_p256().expect("P-256 key generation should succeed");
        let private_pem = key
            .to_pkcs8_pem()
            .expect("PKCS#8 PEM encoding should succeed");
        let public_pem = key.public_key().unwrap().to_spki_pem().unwrap();

        assert!(matches!(
            PrivateKey::from_pkcs8_pem(&public_pem),
            Err(Error::InvalidEncoding)
        ));
        assert!(matches!(
            PrivateKey::from_pkcs8_pem(&format!("{private_pem}{private_pem}")),
            Err(Error::InvalidEncoding)
        ));
    }
}
