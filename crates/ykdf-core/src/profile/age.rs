use bech32::{Bech32, Hrp};

use crate::Result;
use crate::error::Error;
use crate::profile::{AgeIdentityBytes, ProfileOutput, take_fixed};
use crate::types::ExpandedBytes;

const AGE_HRP: Hrp = Hrp::parse_unchecked("age-secret-key-");

/// Clamp as x25519 and encode as an age identity (bech32).
///
/// # Errors
///
/// Returns `Error::ExpandLength` if `expanded` is not 32 bytes.
/// Returns `Error::PostProcessing` if bech32 encoding fails.
pub fn post_process(expanded: &ExpandedBytes) -> Result<ProfileOutput> {
    let mut key = take_fixed::<32>(expanded)?;

    // Curve25519 clamping
    key[0] &= 0xF8;
    key[31] &= 0x7F;
    key[31] |= 0x40;

    let identity = bech32::encode::<Bech32>(AGE_HRP, &key).map_err(|e| Error::PostProcessing {
        detail: e.to_string(),
    })?;

    let identity = identity.to_uppercase();

    Ok(ProfileOutput::AgeIdentity(AgeIdentityBytes {
        secret_key: key,
        identity,
    }))
}
