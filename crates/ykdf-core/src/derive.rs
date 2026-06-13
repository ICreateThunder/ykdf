use crate::Result;
use crate::context::Context;
use crate::error::Error;
use crate::profile::{self, Profile, ProfileOutput};
use crate::types::MasterKey;

/// Derive a key from a master key and context.
///
/// Performs the expand phase followed by profile-specific post-processing.
/// The context determines the pipeline, profile, and domain separation.
///
/// # Errors
///
/// Returns an error if the expand or post-processing step fails.
#[must_use = "derived key must not be discarded"]
pub fn derive(master_key: &MasterKey, context: &Context) -> Result<ProfileOutput> {
    let profile = context.profile();
    let len = profile.expand_len();
    let expanded = crate::expand::expand(master_key, context, len)?;
    profile::post_process(profile, &expanded)
}

/// Derive raw bytes of a caller-specified length.
///
/// The context must use `Profile::Raw`. Unlike `derive()`, the output
/// length is not determined by the profile but by the caller.
///
/// # Errors
///
/// Returns `Error::ProfileMismatch` if the context profile is not `Raw`.
/// Returns an error if the expand step fails (e.g., length exceeds the
/// HKDF maximum of 255 * hash length).
#[must_use = "derived key must not be discarded"]
pub fn derive_raw(master_key: &MasterKey, context: &Context, len: usize) -> Result<ProfileOutput> {
    if context.profile() != Profile::Raw {
        return Err(Error::ProfileMismatch {
            expected: Profile::Raw.as_str(),
            got: context.profile().as_str(),
        });
    }
    let expanded = crate::expand::expand(master_key, context, len)?;
    profile::raw::post_process(&expanded)
}
