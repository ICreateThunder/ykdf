use hkdf::Hkdf;
use zeroize::Zeroize;

use crate::Result;
use crate::types::{Ikm, MasterKey};

const SALT: &[u8] = b"ykdf-v1";

/// Generate an HKDF-Extract function for a 64-byte-output hash.
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
            let (mut prk, _hk) = Hkdf::<$hash>::extract(Some(SALT), ikm.as_bytes());

            let mut key = [0u8; 64];
            key.copy_from_slice(&prk);
            prk.as_mut_slice().zeroize();
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
