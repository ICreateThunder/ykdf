use crate::Result;
use crate::context::Context;
use crate::profile::{self, ProfileOutput};
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
