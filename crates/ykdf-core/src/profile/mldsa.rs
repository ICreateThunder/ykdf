use ml_dsa::{B32, Keypair, MlDsa44, MlDsa65, MlDsa87, SigningKey};

use crate::Result;
use crate::error::Error;
use crate::profile::{MlDsaKeypairBytes, ProfileOutput};
use crate::types::ExpandedBytes;

/// Build the 32-byte ML-DSA seed (xi) from the expanded bytes.
fn seed_from_expanded(expanded: &ExpandedBytes) -> Result<B32> {
    let bytes = expanded.as_bytes();
    if bytes.len() != 32 {
        return Err(Error::ExpandLength {
            expected: 32,
            got: bytes.len(),
        });
    }
    B32::try_from(bytes).map_err(|_| Error::PostProcessing {
        detail: "failed to construct ML-DSA seed".to_owned(),
    })
}

/// ML-DSA-44 key generation from a deterministic seed.
///
/// # Errors
///
/// Returns `Error::ExpandLength` if expanded bytes are not 32 bytes, or
/// `Error::PostProcessing` if seed construction fails.
pub fn post_process_44(expanded: &ExpandedBytes) -> Result<ProfileOutput> {
    let seed = seed_from_expanded(expanded)?;
    let sk = SigningKey::<MlDsa44>::from_seed(&seed);
    Ok(ProfileOutput::MlDsaKeypair(MlDsaKeypairBytes {
        verifying_key: sk.verifying_key().encode().to_vec(),
        signing_key: seed.to_vec(),
    }))
}

/// ML-DSA-65 key generation from a deterministic seed.
///
/// # Errors
///
/// Returns `Error::ExpandLength` if expanded bytes are not 32 bytes, or
/// `Error::PostProcessing` if seed construction fails.
pub fn post_process_65(expanded: &ExpandedBytes) -> Result<ProfileOutput> {
    let seed = seed_from_expanded(expanded)?;
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    Ok(ProfileOutput::MlDsaKeypair(MlDsaKeypairBytes {
        verifying_key: sk.verifying_key().encode().to_vec(),
        signing_key: seed.to_vec(),
    }))
}

/// ML-DSA-87 key generation from a deterministic seed.
///
/// # Errors
///
/// Returns `Error::ExpandLength` if expanded bytes are not 32 bytes, or
/// `Error::PostProcessing` if seed construction fails.
pub fn post_process_87(expanded: &ExpandedBytes) -> Result<ProfileOutput> {
    let seed = seed_from_expanded(expanded)?;
    let sk = SigningKey::<MlDsa87>::from_seed(&seed);
    Ok(ProfileOutput::MlDsaKeypair(MlDsaKeypairBytes {
        verifying_key: sk.verifying_key().encode().to_vec(),
        signing_key: seed.to_vec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::{MlDsa65, SigningKey, post_process_65};
    use crate::profile::ProfileOutput;
    use crate::types::ExpandedBytes;
    use ml_dsa::{
        B32, Keypair,
        signature::{Signer, Verifier},
    };

    /// Interop closer: the emitted ML-DSA-65 keypair must be a *working*
    /// keypair, not just well-sized bytes. We rebuild the signing key from the
    /// same seed, confirm the emitted verifying key is its canonical encoding,
    /// then sign a message and verify the signature. FIPS 204 conformance of the
    /// primitive is delegated to the pinned `ml-dsa` crate's own tests.
    #[test]
    fn mldsa65_emits_working_keypair() {
        let seed_bytes = [0x42u8; 32];
        let out = post_process_65(&ExpandedBytes::new(seed_bytes.to_vec())).unwrap();
        let ProfileOutput::MlDsaKeypair(kp) = &out else {
            panic!("expected MlDsaKeypair");
        };

        let seed = B32::try_from(&seed_bytes[..]).unwrap();
        let sk = SigningKey::<MlDsa65>::from_seed(&seed);
        let vk = sk.verifying_key();

        // Emitted bytes are exactly this keypair's canonical encoding.
        assert_eq!(kp.verifying_key, vk.encode().to_vec());
        assert_eq!(kp.signing_key, seed_bytes.to_vec());

        // Functional validity: a signature from the derived key verifies.
        let message = b"ykdf ml-dsa interop";
        let signature = sk.sign(message);
        assert!(vk.verify(message, &signature).is_ok());
    }

    #[test]
    fn rejects_wrong_seed_length() {
        assert!(post_process_65(&ExpandedBytes::new(vec![0u8; 31])).is_err());
        assert!(post_process_65(&ExpandedBytes::new(vec![0u8; 33])).is_err());
    }
}
