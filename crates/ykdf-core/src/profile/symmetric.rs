use crate::Result;
use crate::profile::{ProfileOutput, SecretKeyBytes, take_fixed};
use crate::types::ExpandedBytes;

/// Passthrough: 32 expanded bytes used directly as a symmetric key.
///
/// # Errors
///
/// Returns `Error::ExpandLength` if `expanded` is not 32 bytes.
pub fn post_process(expanded: &ExpandedBytes) -> Result<ProfileOutput> {
    let key = take_fixed::<32>(expanded)?;
    Ok(ProfileOutput::SecretKey(SecretKeyBytes(key)))
}
