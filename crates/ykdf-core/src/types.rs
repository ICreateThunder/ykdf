use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Result;
use crate::error::Error;

/// Minimum accepted IKM length in bytes (128-bit entropy floor).
///
/// Accepts all real `YubiKey` sources: HMAC-SHA1 challenge-response (20),
/// PIV ECDH P-256 (32), or both combined.
pub const MIN_IKM_LEN: usize = 16;

/// Raw input key material from a `YubiKey` (PIV ECDH, HMAC, or both).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ikm(Vec<u8>);

impl Ikm {
    /// Construct input key material, enforcing a minimum length.
    ///
    /// # Errors
    ///
    /// Returns `Error::InsufficientIkm` if `bytes` is shorter than
    /// `MIN_IKM_LEN`.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < MIN_IKM_LEN {
            return Err(Error::InsufficientIkm {
                len: bytes.len(),
                min: MIN_IKM_LEN,
            });
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// 512-bit master key produced by the extract phase.
///
/// HKDF-SHA512 produces a 64-byte PRK naturally.
/// The sponge pipeline uses SHAKE256 squeezed to 64 bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 64]);

impl MasterKey {
    /// Construct a master key from raw bytes. Crate-internal: only the extract
    /// phase produces master keys, so external callers cannot fabricate one and
    /// bypass the hardware-derived guarantee.
    pub(crate) fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Raw bytes produced by the expand phase, before profile post-processing.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ExpandedBytes(Vec<u8>);

impl ExpandedBytes {
    /// Construct expanded bytes. Crate-internal: only the expand phase produces
    /// these, so external callers cannot feed arbitrary bytes into profile
    /// post-processing.
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
