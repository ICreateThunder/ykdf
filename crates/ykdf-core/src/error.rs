/// Specialized [`Result`](core::result::Result) for `ykdf-core` operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors from context parsing, key derivation, and profile post-processing.
#[derive(Debug)]
pub enum Error {
    /// Context string is malformed or has the wrong number of fields.
    InvalidContext {
        /// The malformed context string.
        input: String,
    },
    /// Purpose field contains invalid characters or length.
    InvalidPurpose {
        /// The rejected purpose value.
        purpose: String,
    },
    /// Profile string not recognized.
    InvalidProfile {
        /// The unrecognized profile label.
        profile: String,
    },
    /// Pipeline string not recognized.
    InvalidPipeline {
        /// The unrecognized pipeline label.
        pipeline: String,
    },
    /// Index field is not a valid `u32`.
    InvalidIndex {
        /// The value that failed to parse.
        index: String,
    },
    /// Input key material is shorter than the minimum allowed length.
    InsufficientIkm {
        /// Supplied length, in bytes.
        len: usize,
        /// Minimum required length, in bytes.
        min: usize,
    },
    /// Profile does not accept the specified pipeline.
    PipelineMismatch {
        /// The profile that rejected the pipeline.
        profile: &'static str,
        /// The pipeline the profile does not accept.
        pipeline: &'static str,
    },
    /// Requested expand output exceeds the maximum for the hash (255 * hash length).
    ExpandOutputTooLong {
        /// Requested length, in bytes.
        requested: usize,
        /// Maximum length the hash allows, in bytes.
        max: usize,
    },
    /// PRK length does not match the hash output size.
    InvalidPrkLength {
        /// Supplied PRK length, in bytes.
        len: usize,
        /// Expected length for the hash, in bytes.
        expected: usize,
    },
    /// Function requires a specific profile but a different one was provided.
    ProfileMismatch {
        /// The required profile.
        expected: &'static str,
        /// The profile that was provided.
        got: &'static str,
    },
    /// Requested output length is zero.
    ZeroLengthOutput,
    /// Expand produced the wrong number of bytes.
    ExpandLength {
        /// Expected length, in bytes.
        expected: usize,
        /// Produced length, in bytes.
        got: usize,
    },
    /// Profile post-processing failed.
    PostProcessing {
        /// Description of the failure.
        detail: String,
    },
    /// A signing operation was requested for a profile that has no signing key.
    SigningUnsupported {
        /// The profile that cannot sign.
        profile: &'static str,
    },
    /// A detached signature could not be parsed.
    MalformedSignature {
        /// What was wrong with the signature.
        detail: String,
    },
    /// A supplied public key could not be parsed.
    MalformedPublicKey {
        /// What was wrong with the public key.
        detail: String,
    },
    /// The signature's namespace does not match the expected one.
    NamespaceMismatch {
        /// The namespace the verifier expected.
        expected: String,
        /// The namespace found in the signature.
        got: String,
    },
    /// A signature is well-formed but not valid for this key and message.
    SignatureVerificationFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        match self {
            Error::InvalidContext { input } => {
                write!(fmt, "invalid context string: {input:?}")
            }
            Error::InvalidPurpose { purpose } => write!(
                fmt,
                "purpose must be 1 to 64 characters of a-z, 0-9 or '-' (got {purpose:?})"
            ),
            Error::InvalidProfile { profile } => write!(fmt, "unknown profile: {profile:?}"),
            Error::InvalidPipeline { pipeline } => write!(fmt, "unknown pipeline: {pipeline:?}"),
            Error::InvalidIndex { index } => {
                write!(
                    fmt,
                    "index must be an unsigned 32-bit integer (got {index:?})"
                )
            }
            Error::InsufficientIkm { len, min } => {
                write!(
                    fmt,
                    "input key material is {len} bytes, need at least {min}"
                )
            }
            Error::PipelineMismatch { profile, pipeline } => {
                write!(
                    fmt,
                    "profile {profile} does not accept the {pipeline} pipeline"
                )
            }
            Error::ExpandOutputTooLong { requested, max } => write!(
                fmt,
                "requested output of {requested} bytes exceeds the maximum of {max} for this hash"
            ),
            Error::InvalidPrkLength { len, expected } => {
                write!(fmt, "pseudorandom key is {len} bytes, expected {expected}")
            }
            Error::ProfileMismatch { expected, got } => {
                write!(fmt, "expected the {expected} profile, got {got}")
            }
            Error::ZeroLengthOutput => write!(fmt, "requested output length is zero"),
            Error::ExpandLength { expected, got } => {
                write!(fmt, "expand produced {got} bytes, expected {expected}")
            }
            Error::PostProcessing { detail } => {
                write!(fmt, "profile post-processing failed: {detail}")
            }
            Error::SigningUnsupported { profile } => {
                write!(fmt, "the {profile} profile has no signing key")
            }
            Error::MalformedSignature { detail } => {
                write!(fmt, "malformed signature: {detail}")
            }
            Error::MalformedPublicKey { detail } => {
                write!(fmt, "malformed public key: {detail}")
            }
            Error::NamespaceMismatch { expected, got } => {
                write!(fmt, "signature namespace is {got:?}, expected {expected:?}")
            }
            Error::SignatureVerificationFailed => {
                write!(fmt, "signature verification failed")
            }
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn display_is_non_empty_and_carries_detail() {
        // Every kind must render a non-empty, human-readable message that
        // includes the variant's data, so the text the CLI and app surface is
        // useful rather than a raw struct dump.
        let cases = [
            Error::InvalidContext {
                input: "bad".to_string(),
            },
            Error::InvalidPurpose {
                purpose: "UPPER".to_string(),
            },
            Error::InvalidProfile {
                profile: "kyber".to_string(),
            },
            Error::InvalidPipeline {
                pipeline: "hkdf-sha256".to_string(),
            },
            Error::InvalidIndex {
                index: "abc".to_string(),
            },
            Error::InsufficientIkm { len: 8, min: 16 },
            Error::PipelineMismatch {
                profile: "x25519",
                pipeline: "shake256",
            },
            Error::ExpandOutputTooLong {
                requested: 99_999,
                max: 16_320,
            },
            Error::InvalidPrkLength {
                len: 32,
                expected: 64,
            },
            Error::ProfileMismatch {
                expected: "raw",
                got: "x25519",
            },
            Error::ZeroLengthOutput,
            Error::ExpandLength {
                expected: 32,
                got: 31,
            },
            Error::PostProcessing {
                detail: "boom".to_string(),
            },
            Error::SigningUnsupported { profile: "x25519" },
            Error::MalformedSignature {
                detail: "bad magic".to_string(),
            },
            Error::MalformedPublicKey {
                detail: "not ssh-ed25519".to_string(),
            },
            Error::NamespaceMismatch {
                expected: "file".to_string(),
                got: "email".to_string(),
            },
            Error::SignatureVerificationFailed,
        ];
        for case in &cases {
            let message = case.to_string();
            assert!(!message.is_empty());
            // Guard against Display regressing to the `{self:?}` struct dump:
            // a human message never contains a `Variant { field: ... }` brace.
            assert!(
                !message.contains('{'),
                "error Display looks like a Debug dump: {message}"
            );
        }

        assert!(
            Error::InvalidPurpose {
                purpose: "UPPER".to_string()
            }
            .to_string()
            .contains("UPPER")
        );
        assert!(
            Error::InsufficientIkm { len: 8, min: 16 }
                .to_string()
                .contains("16")
        );
    }

    #[test]
    fn is_a_std_error() {
        let err = Error::ZeroLengthOutput;
        let _: &dyn core::error::Error = &err;
    }
}
