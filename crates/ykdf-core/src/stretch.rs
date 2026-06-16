//! Argon2id passphrase stretching for cascaded extract.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Result;
use crate::error::Error;

/// Fixed default salt for passphrase stretching when no custom salt is given.
///
/// A fixed salt is required by YKDF's stateless, deterministic design: the
/// same passphrase must stretch to the same value on every device with no
/// stored per-user salt. This is safe because the stretched passphrase is
/// never used in isolation. It is cascaded on top of the high-entropy
/// `YubiKey` secret, so a precomputed passphrase table is useless to an
/// attacker who lacks the hardware output. Callers wanting an extra personal
/// factor can supply their own salt via [`Argon2Params::with_salt`].
///
/// 16 bytes, per RFC 9106 Section 3.1 minimum.
const DEFAULT_SALT: &[u8] = b"ykdf-v1-argon2id";

/// Argon2id parameters for passphrase stretching.
///
/// Defaults are tuned for offline root-key derivation, not interactive login:
/// m=131072 KiB (128 MiB), t=3, p=1. The memory cost is deliberately capped so
/// the same passphrase stretches identically across every supported target,
/// including memory-constrained WASM and mobile environments; raising it
/// further would break cross-platform determinism. These parameters are part
/// of the derivation: changing them changes every derived key.
#[derive(Clone)]
pub struct Argon2Params {
    /// Memory cost in KiB (default: 131072 = 128 MiB).
    pub m_cost: u32,
    /// Time cost / iterations (default: 3).
    pub t_cost: u32,
    /// Parallelism (default: 1).
    pub p_cost: u32,
    salt: Option<Vec<u8>>,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 131_072,
            t_cost: 3,
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
