use hkdf::Hkdf;

use crate::Result;
use crate::context::Context;
use crate::error::Error;
use crate::types::{ExpandedBytes, MasterKey};

/// Generate an HKDF-Expand function for a given hash. Adding a new hash is
/// one line and stays in lockstep with the matching extract function.
macro_rules! hkdf_expand {
    ($(#[$doc:meta])* $name:ident, $hash:ty) => {
        $(#[$doc])*
        ///
        /// # Errors
        ///
        /// Returns `Error::Hkdf` if the PRK is invalid or the requested length
        /// exceeds the HKDF output limit (255 * hash length).
        pub fn $name(
            master_key: &MasterKey,
            context: &Context,
            len: usize,
        ) -> Result<ExpandedBytes> {
            let hk = Hkdf::<$hash>::from_prk(master_key.as_bytes())
                .map_err(|_| Error::Hkdf(hkdf::InvalidLength))?;
            let info = context.kdf_info(len);
            let mut okm = vec![0u8; len];
            hk.expand(&info, &mut okm)?;
            Ok(ExpandedBytes::new(okm))
        }
    };
}

hkdf_expand! {
    /// HKDF-Expand-SHA512: derive `len` bytes from a master key and context.
    expand_sha512, sha2::Sha512
}

hkdf_expand! {
    /// HKDF-Expand-SHA3-512: derive `len` bytes from a master key and context.
    expand_sha3_512, sha3::Sha3_512
}
