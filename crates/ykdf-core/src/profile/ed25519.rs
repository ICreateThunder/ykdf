use crate::Result;
use crate::profile::{Ed25519SeedBytes, ProfileOutput, take_fixed};
use crate::types::ExpandedBytes;

/// Use 32 expanded bytes as an Ed25519 seed.
///
/// The seed is passed to `ed25519_dalek::SigningKey::from_bytes()` by the
/// caller to produce the full keypair.
///
/// # Errors
///
/// Returns `Error::ExpandLength` if `expanded` is not 32 bytes.
pub fn post_process(expanded: &ExpandedBytes) -> Result<ProfileOutput> {
    let seed = take_fixed::<32>(expanded)?;
    Ok(ProfileOutput::Ed25519Seed(Ed25519SeedBytes(seed)))
}
