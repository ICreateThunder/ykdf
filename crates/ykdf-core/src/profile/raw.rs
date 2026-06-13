use crate::Result;
use crate::profile::{ProfileOutput, RawBytes};
use crate::types::ExpandedBytes;

/// Passthrough: return expanded bytes as-is.
///
/// # Errors
///
/// This function is infallible but returns `Result` for API consistency.
pub fn post_process(expanded: &ExpandedBytes) -> Result<ProfileOutput> {
    Ok(ProfileOutput::Raw(RawBytes(expanded.as_bytes().to_vec())))
}
