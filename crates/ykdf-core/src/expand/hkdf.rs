use hmac::{Hmac, Mac};
use zeroize::Zeroize;

use crate::Result;
use crate::context::Context;
use crate::error::Error;
use crate::types::{ExpandedBytes, MasterKey};

/// Generate an HKDF-Expand function implementing RFC 5869 Section 2.3.
///
/// Uses direct HMAC iteration rather than the `hkdf` crate, so the PRK
/// is never copied into a wrapper struct that lacks `Zeroize`.
///
/// The hash must produce `$hash_len` bytes (64 for SHA-512 and SHA3-512).
/// Adding a new hash is one line.
macro_rules! hkdf_expand {
    ($(#[$doc:meta])* $name:ident, $hash:ty, $hash_len:expr) => {
        $(#[$doc])*
        ///
        /// # Errors
        ///
        /// Returns `Error::ExpandOutputTooLong` if the requested length
        /// exceeds 255 * hash length. Returns `Error::InvalidPrkLength` if
        /// the master key size does not match the hash output size.
        pub fn $name(
            master_key: &MasterKey,
            context: &Context,
            len: usize,
        ) -> Result<ExpandedBytes> {
            let max_output = 255 * $hash_len;
            if len > max_output {
                return Err(Error::ExpandOutputTooLong {
                    requested: len,
                    max: max_output,
                });
            }
            if master_key.as_bytes().len() != $hash_len {
                return Err(Error::InvalidPrkLength {
                    len: master_key.as_bytes().len(),
                    expected: $hash_len,
                });
            }

            let info = context.kdf_info(len);
            let n = len.div_ceil($hash_len);
            let mut okm = Vec::with_capacity(len);
            let mut t_prev: Vec<u8> = Vec::new();

            for i in 1..=n {
                let mut mac = <Hmac<$hash>>::new_from_slice(master_key.as_bytes())
                    .map_err(|_| Error::InvalidPrkLength {
                        len: master_key.as_bytes().len(),
                        expected: $hash_len,
                    })?;
                mac.update(&t_prev);
                mac.update(&info);
                // Safe: n <= 255 is enforced by the max_output check above.
                #[allow(clippy::cast_possible_truncation)]
                mac.update(&[i as u8]);
                let mut result = mac.finalize().into_bytes();

                let remaining = len - okm.len();
                let to_copy = remaining.min($hash_len);
                okm.extend_from_slice(&result[..to_copy]);

                t_prev.zeroize();
                t_prev = result.to_vec();
                result.as_mut_slice().zeroize();
            }
            t_prev.zeroize();

            Ok(ExpandedBytes::new(okm))
        }
    };
}

hkdf_expand! {
    /// HKDF-Expand-SHA512: derive `len` bytes from a master key and context.
    expand_sha512, sha2::Sha512, 64
}

hkdf_expand! {
    /// HKDF-Expand-SHA3-512: derive `len` bytes from a master key and context.
    expand_sha3_512, sha3::Sha3_512, 64
}
