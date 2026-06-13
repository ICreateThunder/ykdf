pub mod hkdf;
pub mod sponge;

use crate::Result;
use crate::context::Context;
use crate::pipeline::Pipeline;
use crate::types::{ExpandedBytes, MasterKey};

/// Expand a master key into derived bytes using the context's pipeline.
///
/// # Errors
///
/// Returns `Error::Hkdf` if the HKDF expand operation fails.
pub fn expand(master_key: &MasterKey, context: &Context, len: usize) -> Result<ExpandedBytes> {
    match context.pipeline() {
        Pipeline::HkdfSha512 => hkdf::expand_sha512(master_key, context, len),
        Pipeline::HkdfSha3 => hkdf::expand_sha3_512(master_key, context, len),
        Pipeline::Shake256 => sponge::expand(master_key, context, len),
    }
}
