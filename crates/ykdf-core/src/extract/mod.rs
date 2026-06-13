pub mod hkdf;
pub mod sponge;

use crate::Result;
use crate::pipeline::Pipeline;
use crate::types::{Ikm, MasterKey};

/// Extract a master key from input key material using the specified pipeline.
///
/// # Errors
///
/// This function is infallible but returns `Result` for API consistency.
#[must_use = "master key must not be discarded"]
pub fn extract(ikm: &Ikm, pipeline: Pipeline) -> Result<MasterKey> {
    match pipeline {
        Pipeline::HkdfSha512 => hkdf::extract_sha512(ikm),
        Pipeline::HkdfSha3 => hkdf::extract_sha3_512(ikm),
        Pipeline::Shake256 => sponge::extract(ikm),
    }
}

/// Cascade an additional entropy source into an existing master key.
///
/// Implements a TLS 1.3 style cascaded extract: the early secret is used
/// as the HMAC key (salt position) and the additional IKM is the message.
/// This produces a new master key that depends on both entropy sources.
///
/// Typical usage: combine hardware-derived entropy with a stretched
/// passphrase so that compromise of either factor alone reveals nothing.
///
/// # Errors
///
/// This function is infallible but returns `Result` for API consistency.
#[must_use = "cascaded key must not be discarded"]
pub fn cascade(
    early_secret: &MasterKey,
    additional_ikm: &[u8],
    pipeline: Pipeline,
) -> Result<MasterKey> {
    match pipeline {
        Pipeline::HkdfSha512 => hkdf::cascade_sha512(early_secret, additional_ikm),
        Pipeline::HkdfSha3 => hkdf::cascade_sha3_512(early_secret, additional_ikm),
        Pipeline::Shake256 => sponge::cascade(early_secret, additional_ikm),
    }
}
