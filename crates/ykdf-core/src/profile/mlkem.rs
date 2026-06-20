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

#[cfg(test)]
mod tests {
    use super::{MlKem768, ProfileOutput, Seed, post_process_768};
    use crate::types::ExpandedBytes;
    use ml_kem::{B32, Decapsulate, DecapsulationKey, KeyExport};

    /// Interop closer: the emitted ML-KEM-768 keypair must be a *working*
    /// keypair, not just well-sized bytes. We rebuild the keypair from the same
    /// seed, confirm the emitted bytes are its canonical encoding (ek =
    /// standard 1184-byte key, dk = 64-byte seed form), then encapsulate to the
    /// encapsulation key and decapsulate with the decapsulation key and require
    /// the shared secrets to agree. FIPS 203 compliance of the primitive itself
    /// is delegated to the pinned `ml-kem` crate's own known-answer tests.
    #[test]
    fn mlkem768_emits_working_keypair() {
        let seed_bytes = [0x42u8; 64];
        let out = post_process_768(&ExpandedBytes::new(seed_bytes.to_vec())).unwrap();
        let ProfileOutput::MlKemKeypair(kp) = &out else {
            panic!("expected MlKemKeypair");
        };

        let seed = Seed::try_from(&seed_bytes[..]).unwrap();
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        let ek = dk.encapsulation_key();

        // Emitted bytes are exactly this keypair's canonical encoding.
        assert_eq!(kp.encapsulation_key, ek.to_bytes().to_vec());
        assert_eq!(kp.decapsulation_key, dk.to_bytes().to_vec());
        assert_eq!(kp.encapsulation_key.len(), 1184);
        assert_eq!(kp.decapsulation_key.len(), 64);

        // Functional validity: encaps then decaps yields the same shared secret.
        let message = B32::try_from(&[0x07u8; 32][..]).unwrap();
        let (ciphertext, shared_a) = ek.encapsulate_deterministic(&message);
        let shared_b = dk.decapsulate(&ciphertext);
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn rejects_wrong_seed_length() {
        // ML-KEM keygen needs a 64-byte seed; a wrong-length expand is rejected
        // rather than producing a malformed key.
        assert!(post_process_768(&ExpandedBytes::new(vec![0u8; 32])).is_err());
        assert!(post_process_768(&ExpandedBytes::new(vec![0u8; 65])).is_err());
    }
}
