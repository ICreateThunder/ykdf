use ml_kem::{DecapsulationKey, KeyExport, MlKem512, MlKem768, MlKem1024, Seed};

use crate::Result;
use crate::error::Error;
use crate::profile::{MlKemKeypairBytes, ProfileOutput};
use crate::types::ExpandedBytes;

fn seed_from_expanded(expanded: &ExpandedBytes) -> Result<Seed> {
    let bytes = expanded.as_bytes();
    if bytes.len() != 64 {
        return Err(Error::ExpandLength {
            expected: 64,
            got: bytes.len(),
        });
    }
    Seed::try_from(bytes).map_err(|_| Error::PostProcessing {
        detail: "failed to construct ML-KEM seed".to_owned(),
    })
}

/// ML-KEM-512 key generation from deterministic seed.
///
/// # Errors
///
/// Returns `Error::ExpandLength` if expanded bytes are not 64 bytes.
/// Returns `Error::PostProcessing` if seed construction fails.
pub fn post_process_512(expanded: &ExpandedBytes) -> Result<ProfileOutput> {
    let seed = seed_from_expanded(expanded)?;
    let dk = DecapsulationKey::<MlKem512>::from_seed(seed);
    let ek = dk.encapsulation_key();

    Ok(ProfileOutput::MlKemKeypair(MlKemKeypairBytes {
        encapsulation_key: ek.to_bytes().to_vec(),
        decapsulation_key: dk.to_bytes().to_vec(),
    }))
}

/// ML-KEM-768 key generation from deterministic seed.
///
/// # Errors
///
/// Returns `Error::ExpandLength` if expanded bytes are not 64 bytes.
/// Returns `Error::PostProcessing` if seed construction fails.
pub fn post_process_768(expanded: &ExpandedBytes) -> Result<ProfileOutput> {
    let seed = seed_from_expanded(expanded)?;
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
    let ek = dk.encapsulation_key();

    Ok(ProfileOutput::MlKemKeypair(MlKemKeypairBytes {
        encapsulation_key: ek.to_bytes().to_vec(),
        decapsulation_key: dk.to_bytes().to_vec(),
    }))
}

/// ML-KEM-1024 key generation from deterministic seed.
///
/// # Errors
///
/// Returns `Error::ExpandLength` if expanded bytes are not 64 bytes.
/// Returns `Error::PostProcessing` if seed construction fails.
pub fn post_process_1024(expanded: &ExpandedBytes) -> Result<ProfileOutput> {
    let seed = seed_from_expanded(expanded)?;
    let dk = DecapsulationKey::<MlKem1024>::from_seed(seed);
    let ek = dk.encapsulation_key();

    Ok(ProfileOutput::MlKemKeypair(MlKemKeypairBytes {
        encapsulation_key: ek.to_bytes().to_vec(),
        decapsulation_key: dk.to_bytes().to_vec(),
    }))
}
