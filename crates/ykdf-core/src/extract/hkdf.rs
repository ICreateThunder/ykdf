use hmac::{Hmac, Mac};
use zeroize::Zeroize;

use crate::Result;
use crate::error::Error;
use crate::types::{Ikm, MasterKey};

const SALT: &[u8] = b"ykdf-v1";

/// Generate an HKDF-Extract function for a 64-byte-output hash.
///
/// Uses HMAC directly (`HMAC-<Hash>(salt, IKM)`) rather than the `hkdf`
/// crate's `extract()`, which returns an `Hkdf` instance that retains an
/// un-zeroizable copy of the PRK internally.
///
/// The hash must produce 64 bytes so the PRK fills `MasterKey` exactly
/// (satisfied by SHA-512 and SHA3-512). Adding a new hash is one line.
macro_rules! hkdf_extract {
    ($(#[$doc:meta])* $name:ident, $hash:ty) => {
        $(#[$doc])*
        ///
        /// # Errors
        ///
        /// This function is infallible but returns `Result` for API consistency.
        #[must_use = "master key must not be discarded"]
        pub fn $name(ikm: &Ikm) -> Result<MasterKey> {
            let mut mac = <Hmac<$hash>>::new_from_slice(SALT)
                .map_err(|_| Error::InvalidPrkLength {
                    len: SALT.len(),
                    expected: 0,
                })?;
            mac.update(ikm.as_bytes());
            let mut result = mac.finalize().into_bytes();
            let mut key = [0u8; 64];
            key.copy_from_slice(&result);
            result.as_mut_slice().zeroize();
            Ok(MasterKey::from_bytes(key))
        }
    };
}

hkdf_extract! {
    /// HKDF-Extract-SHA512: HMAC-SHA512(salt, IKM) producing a 64-byte PRK.
    extract_sha512, sha2::Sha512
}

hkdf_extract! {
    /// HKDF-Extract-SHA3-512: HMAC-SHA3-512(salt, IKM) producing a 64-byte PRK.
    extract_sha3_512, sha3::Sha3_512
}

/// Generate an HMAC-based cascade function for combining entropy sources.
///
/// TLS 1.3 pattern: `HMAC-Hash(key=early_secret, msg=additional_ikm)`.
/// The early secret acts as the HMAC key (salt position per RFC 5869)
/// and the additional IKM is the message.
macro_rules! hkdf_cascade {
    ($(#[$doc:meta])* $name:ident, $hash:ty) => {
        $(#[$doc])*
        ///
        /// # Errors
        ///
        /// This function is infallible but returns `Result` for API consistency.
        #[must_use = "cascaded key must not be discarded"]
        pub fn $name(
            early_secret: &MasterKey,
            additional_ikm: &[u8],
        ) -> Result<MasterKey> {
            let mut mac = <Hmac<$hash>>::new_from_slice(early_secret.as_bytes())
                .map_err(|_| Error::InvalidPrkLength {
                    len: early_secret.as_bytes().len(),
                    expected: 64,
                })?;
            mac.update(additional_ikm);
            let mut result = mac.finalize().into_bytes();
            let mut key = [0u8; 64];
            key.copy_from_slice(&result);
            result.as_mut_slice().zeroize();
            Ok(MasterKey::from_bytes(key))
        }
    };
}

hkdf_cascade! {
    /// HMAC-SHA512 cascaded extract using early secret as key.
    cascade_sha512, sha2::Sha512
}

hkdf_cascade! {
    /// HMAC-SHA3-512 cascaded extract using early secret as key.
    cascade_sha3_512, sha3::Sha3_512
}
