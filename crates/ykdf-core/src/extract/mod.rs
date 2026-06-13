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
