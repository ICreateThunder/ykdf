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
// Infallible, but returns `Result` to match the fallible HKDF pipelines so
// `extract()` can dispatch over a uniform signature.
#[must_use = "master key must not be discarded"]
#[allow(clippy::unnecessary_wraps)]
pub fn extract(ikm: &Ikm) -> Result<MasterKey> {
    let mut hasher = Shake256::default();
    // Domain tag distinguishes extract (0x01) from cascade (0x02) so the
    // two operations cannot collide even if input sizes were to change.
    hasher.update(&[0x01]);
    hasher.update(SALT);
    hasher.update(ikm.as_bytes());

    let mut key = [0u8; 64];
    hasher.finalize_xof().read(&mut key);

    Ok(MasterKey::from_bytes(key))
}

/// SHAKE256 cascaded extract: absorb early secret and additional IKM, squeeze 64 bytes.
///
/// # Errors
///
/// This function is infallible but returns `Result` for API consistency.
// Infallible, but returns `Result` to match the fallible HKDF pipelines so
// `cascade()` can dispatch over a uniform signature.
#[must_use = "cascaded key must not be discarded"]
#[allow(clippy::unnecessary_wraps)]
pub fn cascade(early_secret: &MasterKey, additional_ikm: &[u8]) -> Result<MasterKey> {
    let mut hasher = Shake256::default();
    // Domain tag distinguishes cascade (0x02) from extract (0x01) so the
    // two operations cannot collide even if input sizes were to change.
    hasher.update(&[0x02]);
    hasher.update(early_secret.as_bytes());
    hasher.update(additional_ikm);

    let mut key = [0u8; 64];
    hasher.finalize_xof().read(&mut key);

    Ok(MasterKey::from_bytes(key))
}
