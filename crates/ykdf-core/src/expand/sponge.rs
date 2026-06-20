use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::Result;
use crate::context::Context;
use crate::types::{ExpandedBytes, MasterKey};

/// SHAKE256 sponge expand: absorb master key and context, squeeze `len` bytes.
///
/// # Errors
///
/// This function is infallible but returns `Result` for API consistency.
#[allow(clippy::unnecessary_wraps)]
pub fn expand(master_key: &MasterKey, context: &Context, len: usize) -> Result<ExpandedBytes> {
    let mut hasher = Shake256::default();
    // Safe to concatenate without a length prefix: MasterKey is always
    // exactly 64 bytes, so the boundary with kdf_info is unambiguous.
    hasher.update(master_key.as_bytes());
    hasher.update(&context.kdf_info(len));

    let mut output = vec![0u8; len];
    hasher.finalize_xof().read(&mut output);

    Ok(ExpandedBytes::new(output))
}
