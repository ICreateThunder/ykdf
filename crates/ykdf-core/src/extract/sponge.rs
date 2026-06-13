use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::Result;
use crate::types::{Ikm, MasterKey};

const SALT: &[u8] = b"ykdf-v1";

/// SHAKE256 sponge extract: absorb salt and IKM, squeeze 64 bytes.
///
/// # Errors
///
/// This function is infallible but returns `Result` for API consistency.
#[must_use = "master key must not be discarded"]
pub fn extract(ikm: &Ikm) -> Result<MasterKey> {
    let mut hasher = Shake256::default();
    hasher.update(SALT);
    hasher.update(ikm.as_bytes());

    let mut key = [0u8; 64];
    hasher.finalize_xof().read(&mut key);

    Ok(MasterKey::from_bytes(key))
}
