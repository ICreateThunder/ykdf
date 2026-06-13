//! Argon2id passphrase stretching for cascaded extract.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Result;
use crate::error::Error;

/// Default salt for passphrase stretching when no custom salt is provided.
const DEFAULT_SALT: &[u8] = b"ykdf-v1-argon2";

/// Argon2id parameters for passphrase stretching.
///
/// Defaults follow the OWASP minimum recommendation:
/// Argon2id, m=19456 KiB (19 MiB), t=2, p=1.
#[derive(Clone)]
pub struct Argon2Params {
    /// Memory cost in KiB (default: 19456 = 19 MiB).
    pub m_cost: u32,
    /// Time cost / iterations (default: 2).
    pub t_cost: u32,
    /// Parallelism (default: 1).
    pub p_cost: u32,
    salt: Option<Vec<u8>>,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: None,
        }
    }
}

impl Argon2Params {
    /// Use a custom salt instead of the fixed default.
    #[must_use]
    pub fn with_salt(mut self, salt: Vec<u8>) -> Self {
        self.salt = Some(salt);
        self
    }

    fn salt(&self) -> &[u8] {
        self.salt.as_deref().unwrap_or(DEFAULT_SALT)
    }
}

/// Stretched passphrase output (64 bytes, matching `MasterKey` size).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StretchedPassphrase(Vec<u8>);

impl StretchedPassphrase {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Stretch a passphrase using Argon2id, producing 64 bytes.
///
/// The output is suitable for use as `additional_ikm` in `cascade()`.
///
/// # Errors
///
/// Returns `Error::PostProcessing` if Argon2id computation fails
/// (e.g., invalid parameters).
pub fn stretch_passphrase(passphrase: &[u8], params: &Argon2Params) -> Result<StretchedPassphrase> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let algo_params =
        Params::new(params.m_cost, params.t_cost, params.p_cost, Some(64)).map_err(|e| {
            Error::PostProcessing {
                detail: format!("invalid Argon2 parameters: {e}"),
            }
        })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, algo_params);
    let mut output = vec![0u8; 64];

    argon2
        .hash_password_into(passphrase, params.salt(), &mut output)
        .map_err(|e| Error::PostProcessing {
            detail: format!("Argon2id stretching failed: {e}"),
        })?;

    Ok(StretchedPassphrase(output))
}
