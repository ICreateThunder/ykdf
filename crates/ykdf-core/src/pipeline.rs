use core::fmt;

/// KDF pipeline selection.
///
/// Determines which algorithms are used for both extract and expand phases.
/// Encoded in the context string for unambiguous, self-describing derivations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pipeline {
    /// HKDF-Extract/Expand with SHA-512.
    /// Classical NIST KDF for fixed-length keys.
    HkdfSha512,
    /// HKDF-Extract/Expand with SHA3-512.
    /// Classical NIST KDF using the Keccak permutation.
    HkdfSha3,
    /// SHAKE256 sponge for both extract and expand.
    /// Native XOF for variable-length and post-quantum profiles.
    Shake256,
}

impl Pipeline {
    /// Canonical wire-format label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::HkdfSha512 => "hkdf-sha512",
            Self::HkdfSha3 => "hkdf-sha3-512",
            Self::Shake256 => "shake256",
        }
    }

    /// Parses a pipeline from its wire-format label, returning `None` if unknown.
    pub fn from_str_label(s: &str) -> Option<Self> {
        match s {
            "hkdf-sha512" => Some(Self::HkdfSha512),
            "hkdf-sha3-512" => Some(Self::HkdfSha3),
            "shake256" => Some(Self::Shake256),
            _ => None,
        }
    }
}

impl fmt::Display for Pipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
