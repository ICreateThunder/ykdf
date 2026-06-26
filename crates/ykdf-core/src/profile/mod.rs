pub mod age;
pub mod ed25519;
pub mod mldsa;
pub mod mlkem;
pub mod raw;
pub mod symmetric;
pub mod x25519;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Result;
use crate::error::Error;
use crate::pipeline::Pipeline;
use crate::types::ExpandedBytes;

/// Copy expanded bytes into a fixed-size array, validating the length first.
///
/// Profiles call this instead of `copy_from_slice` so that a wrong-length
/// `ExpandedBytes` returns `Error::ExpandLength` rather than panicking.
///
/// # Errors
///
/// Returns `Error::ExpandLength` if `expanded` is not exactly `N` bytes.
pub(crate) fn take_fixed<const N: usize>(expanded: &ExpandedBytes) -> Result<[u8; N]> {
    let bytes = expanded.as_bytes();
    if bytes.len() != N {
        return Err(Error::ExpandLength {
            expected: N,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Key profile determining output shape and post-processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// X25519 secret key (e.g. `WireGuard`), 32 bytes, clamped.
    X25519,
    /// Ed25519 signing key seed, 32 bytes.
    Ed25519,
    /// age X25519 identity (`AGE-SECRET-KEY-1...`).
    AgeX25519,
    /// Raw 32-byte symmetric key.
    Symmetric,
    /// ML-KEM-512 keypair (FIPS 203).
    MlKem512,
    /// ML-KEM-768 keypair (FIPS 203).
    MlKem768,
    /// ML-KEM-1024 keypair (FIPS 203).
    MlKem1024,
    /// ML-DSA-44 keypair (FIPS 204).
    MlDsa44,
    /// ML-DSA-65 keypair (FIPS 204).
    MlDsa65,
    /// ML-DSA-87 keypair (FIPS 204).
    MlDsa87,
    /// Raw expanded bytes of caller-chosen length.
    Raw,
}

impl Profile {
    /// The pipeline this profile selects unless overridden.
    pub const fn default_pipeline(&self) -> Pipeline {
        match self {
            Self::MlKem512
            | Self::MlKem768
            | Self::MlKem1024
            | Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87 => Pipeline::Shake256,
            Self::X25519 | Self::Ed25519 | Self::AgeX25519 | Self::Symmetric | Self::Raw => {
                Pipeline::HkdfSha512
            }
        }
    }

    /// Whether this profile may be derived with the given pipeline.
    ///
    /// Classical 32-byte profiles accept either HKDF hash. ML-KEM profiles
    /// require the SHAKE256 sponge. `Raw` accepts any pipeline.
    pub fn accepts(&self, pipeline: Pipeline) -> bool {
        match self {
            Self::MlKem512
            | Self::MlKem768
            | Self::MlKem1024
            | Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87 => pipeline == Pipeline::Shake256,
            Self::X25519 | Self::Ed25519 | Self::AgeX25519 | Self::Symmetric => {
                matches!(pipeline, Pipeline::HkdfSha512 | Pipeline::HkdfSha3)
            }
            Self::Raw => true,
        }
    }

    /// Number of bytes the expand phase must produce for this profile.
    pub const fn expand_len(&self) -> usize {
        match self {
            Self::MlKem512 | Self::MlKem768 | Self::MlKem1024 => 64,
            // ML-DSA KeyGen takes a single 32-byte seed (xi), unlike ML-KEM's 64.
            Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87
            | Self::X25519
            | Self::Ed25519
            | Self::AgeX25519
            | Self::Symmetric
            | Self::Raw => 32,
        }
    }

    /// Parses a profile from its wire-format label, returning `None` if unknown.
    pub fn from_str_label(s: &str) -> Option<Self> {
        match s {
            "x25519" => Some(Self::X25519),
            "ed25519" => Some(Self::Ed25519),
            "age-x25519" => Some(Self::AgeX25519),
            "symmetric" => Some(Self::Symmetric),
            "mlkem512" => Some(Self::MlKem512),
            "mlkem768" => Some(Self::MlKem768),
            "mlkem1024" => Some(Self::MlKem1024),
            "mldsa44" => Some(Self::MlDsa44),
            "mldsa65" => Some(Self::MlDsa65),
            "mldsa87" => Some(Self::MlDsa87),
            "raw" => Some(Self::Raw),
            _ => None,
        }
    }

    /// Returns the canonical wire-format label for this profile.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::X25519 => "x25519",
            Self::Ed25519 => "ed25519",
            Self::AgeX25519 => "age-x25519",
            Self::Symmetric => "symmetric",
            Self::MlKem512 => "mlkem512",
            Self::MlKem768 => "mlkem768",
            Self::MlKem1024 => "mlkem1024",
            Self::MlDsa44 => "mldsa44",
            Self::MlDsa65 => "mldsa65",
            Self::MlDsa87 => "mldsa87",
            Self::Raw => "raw",
        }
    }
}

impl core::fmt::Display for Profile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Output of profile post-processing.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum ProfileOutput {
    /// 32-byte secret key (x25519, symmetric).
    SecretKey(SecretKeyBytes),
    /// Ed25519 signing key (32-byte seed).
    Ed25519Seed(Ed25519SeedBytes),
    /// ML-KEM keypair as (encapsulation key, decapsulation key) bytes.
    MlKemKeypair(MlKemKeypairBytes),
    /// ML-DSA keypair as (verifying key, signing key) bytes.
    MlDsaKeypair(MlDsaKeypairBytes),
    /// age identity string.
    AgeIdentity(AgeIdentityBytes),
    /// Raw bytes of arbitrary length.
    Raw(RawBytes),
}

/// A 32-byte secret key (x25519 or symmetric).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKeyBytes(pub [u8; 32]);

/// An Ed25519 signing key, as its 32-byte seed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519SeedBytes(pub [u8; 32]);

/// An ML-KEM keypair in its canonical byte encodings.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKemKeypairBytes {
    /// Public encapsulation key.
    pub encapsulation_key: Vec<u8>,
    /// Secret decapsulation key.
    pub decapsulation_key: Vec<u8>,
}

/// An ML-DSA keypair in its canonical byte encodings.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlDsaKeypairBytes {
    /// Public verifying key.
    pub verifying_key: Vec<u8>,
    /// Secret signing key, as its 32-byte seed.
    pub signing_key: Vec<u8>,
}

/// An age X25519 identity: the raw key plus its encoded form.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AgeIdentityBytes {
    /// Raw 32-byte X25519 secret key.
    pub secret_key: [u8; 32],
    /// Bech32-encoded identity string (`AGE-SECRET-KEY-1...`).
    pub identity: String,
}

/// Raw expanded bytes of caller-chosen length.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RawBytes(pub Vec<u8>);

/// Apply profile-specific post-processing to expanded bytes.
///
/// # Errors
///
/// Returns an error if the profile's post-processing step fails.
pub fn post_process(profile: Profile, expanded: &ExpandedBytes) -> Result<ProfileOutput> {
    match profile {
        Profile::X25519 => x25519::post_process(expanded),
        Profile::Ed25519 => ed25519::post_process(expanded),
        Profile::AgeX25519 => age::post_process(expanded),
        Profile::Symmetric => symmetric::post_process(expanded),
        Profile::MlKem512 => mlkem::post_process_512(expanded),
        Profile::MlKem768 => mlkem::post_process_768(expanded),
        Profile::MlKem1024 => mlkem::post_process_1024(expanded),
        Profile::MlDsa44 => mldsa::post_process_44(expanded),
        Profile::MlDsa65 => mldsa::post_process_65(expanded),
        Profile::MlDsa87 => mldsa::post_process_87(expanded),
        Profile::Raw => raw::post_process(expanded),
    }
}

#[cfg(test)]
mod tests {
    use super::take_fixed;
    use crate::types::ExpandedBytes;

    #[test]
    fn take_fixed_enforces_exact_length() {
        // The length guard rejects anything that is not exactly N bytes, so a
        // wrong-length expand can never silently produce a truncated key.
        assert!(take_fixed::<32>(&ExpandedBytes::new(vec![0u8; 31])).is_err());
        assert!(take_fixed::<32>(&ExpandedBytes::new(vec![0u8; 33])).is_err());
        assert!(take_fixed::<32>(&ExpandedBytes::new(vec![0u8; 32])).is_ok());
    }
}
