//! Argon2id passphrase stretching for cascaded extract.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Result;
use crate::error::Error;
use crate::extract::cascade;
use crate::pipeline::Pipeline;
use crate::types::MasterKey;

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
/// The cost parameters are fixed at a single hardened tier (m=131072 KiB
/// (128 MiB), t=3, p=1) and are not externally configurable: the only public
/// constructors are [`Argon2Params::default`] and [`Argon2Params::with_salt`].
///
/// This is deliberate. The cost is part of the derivation identity (bound via
/// the descriptor in [`cascade_passphrase`]), so letting integrators vary it
/// would both (a) allow a caller to silently weaken the KDF below a safe floor
/// and (b) break cross-device determinism, since the same passphrase would
/// stretch differently under different costs. The memory cost is additionally
/// capped at this tier so a passphrase stretches identically on
/// memory-constrained WASM and mobile targets. A future, stronger tier would
/// be added as a new named constructor (additively, via a new descriptor), not
/// by mutating these fields.
#[derive(Clone)]
pub struct Argon2Params {
    /// Memory cost in KiB. Fixed at 131072 (128 MiB) by `Default`.
    m_cost: u32,
    /// Time cost / iterations. Fixed at 3 by `Default`.
    t_cost: u32,
    /// Parallelism. Fixed at 1 by `Default`.
    p_cost: u32,
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

    /// Canonical descriptor identifying the stretch algorithm and cost
    /// parameters, e.g. `argon2id:m=131072,t=3,p=1`.
    ///
    /// Bound into the derivation by [`cascade_passphrase`] so a passphrase
    /// derivation is self-describing and a future stretch algorithm is
    /// additively domain-separated. The salt is not included: it already
    /// affects the stretched output, and a custom salt may be sensitive.
    #[must_use]
    pub fn descriptor(&self) -> Vec<u8> {
        format!(
            "argon2id:m={},t={},p={}",
            self.m_cost, self.t_cost, self.p_cost
        )
        .into_bytes()
    }
}

/// Stretched passphrase output (64 bytes, matching `MasterKey` size) together
/// with the descriptor of the algorithm that produced it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StretchedPassphrase {
    bytes: Vec<u8>,
    descriptor: Vec<u8>,
}

impl StretchedPassphrase {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The stretch descriptor (see [`Argon2Params::descriptor`]).
    #[must_use]
    pub fn descriptor(&self) -> &[u8] {
        &self.descriptor
    }
}

/// Stretch a passphrase using Argon2id, producing 64 bytes.
///
/// The output is intended to be combined into a master key with
/// [`cascade_passphrase`], which binds the stretch descriptor.
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

    Ok(StretchedPassphrase {
        bytes: output,
        descriptor: params.descriptor(),
    })
}

/// Cascade a stretched passphrase into a master key, binding the stretch
/// descriptor so the derivation is self-describing.
///
/// The cascade input is `len(descriptor) || descriptor || stretched_bytes`,
/// length-prefixed so the encoding is unambiguous. Binding the descriptor
/// domain-separates derivations by stretch algorithm and cost: changing the
/// algorithm or parameters changes the output, and a future algorithm is added
/// additively (a new descriptor) rather than by bumping the format version.
///
/// # Errors
///
/// Returns `Error::PostProcessing` if the descriptor is unexpectedly longer
/// than 255 bytes (not possible for the canonical descriptor).
pub fn cascade_passphrase(
    early_secret: &MasterKey,
    stretched: &StretchedPassphrase,
    pipeline: Pipeline,
) -> Result<MasterKey> {
    let descriptor = stretched.descriptor();
    let len = u8::try_from(descriptor.len()).map_err(|_| Error::PostProcessing {
        detail: "stretch descriptor exceeds 255 bytes".to_string(),
    })?;

    let mut ikm = Zeroizing::new(Vec::with_capacity(
        1 + descriptor.len() + stretched.bytes.len(),
    ));
    ikm.push(len);
    ikm.extend_from_slice(descriptor);
    ikm.extend_from_slice(&stretched.bytes);

    cascade(early_secret, &ikm, pipeline)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal-cost parameters so the Argon2 calls in these tests are fast; the
    /// descriptor-binding logic is independent of the cost.
    fn fast_params() -> Argon2Params {
        Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
            salt: None,
        }
    }

    #[test]
    fn descriptor_matches_canonical_form() {
        assert_eq!(
            Argon2Params::default().descriptor(),
            b"argon2id:m=131072,t=3,p=1"
        );
        assert_eq!(fast_params().descriptor(), b"argon2id:m=8,t=1,p=1");
    }

    #[test]
    fn cascade_passphrase_is_deterministic() {
        let early = MasterKey::from_bytes([7u8; 64]);
        let s1 = stretch_passphrase(b"pw", &fast_params()).unwrap();
        let s2 = stretch_passphrase(b"pw", &fast_params()).unwrap();
        let a = cascade_passphrase(&early, &s1, Pipeline::HkdfSha512).unwrap();
        let b = cascade_passphrase(&early, &s2, Pipeline::HkdfSha512).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn descriptor_binding_domain_separates() {
        // Binding the descriptor must change the result versus a plain cascade
        // of the same stretched bytes.
        let early = MasterKey::from_bytes([9u8; 64]);
        let s = stretch_passphrase(b"pw", &fast_params()).unwrap();
        let bound = cascade_passphrase(&early, &s, Pipeline::HkdfSha512).unwrap();
        let plain = cascade(&early, s.as_bytes(), Pipeline::HkdfSha512).unwrap();
        assert_ne!(bound.as_bytes(), plain.as_bytes());
    }

    #[test]
    fn different_params_change_output() {
        let early = MasterKey::from_bytes([3u8; 64]);
        let s_a = stretch_passphrase(b"pw", &fast_params()).unwrap();
        let s_b = stretch_passphrase(
            b"pw",
            &Argon2Params {
                m_cost: 16,
                t_cost: 1,
                p_cost: 1,
                salt: None,
            },
        )
        .unwrap();
        assert_ne!(s_a.descriptor(), s_b.descriptor());
        let a = cascade_passphrase(&early, &s_a, Pipeline::HkdfSha512).unwrap();
        let b = cascade_passphrase(&early, &s_b, Pipeline::HkdfSha512).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
