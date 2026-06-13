use crate::Result;
use crate::profile::{ProfileOutput, SecretKeyBytes, take_fixed};
use crate::types::ExpandedBytes;

/// Apply Curve25519 clamping to 32 expanded bytes.
///
/// # Errors
///
/// Returns `Error::ExpandLength` if `expanded` is not 32 bytes.
pub fn post_process(expanded: &ExpandedBytes) -> Result<ProfileOutput> {
    let mut key = take_fixed::<32>(expanded)?;

    // Curve25519 clamping per RFC 7748
    key[0] &= 0xF8;
    key[31] &= 0x7F;
    key[31] |= 0x40;

    Ok(ProfileOutput::SecretKey(SecretKeyBytes(key)))
}
