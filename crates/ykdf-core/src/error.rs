pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// Context string is malformed or has wrong number of fields.
    InvalidContext { input: String },
    /// Purpose field contains invalid characters or length.
    InvalidPurpose { purpose: String },
    /// Profile string not recognized.
    InvalidProfile { profile: String },
    /// Pipeline string not recognized.
    InvalidPipeline { pipeline: String },
    /// Index field is not a valid u32.
    InvalidIndex { index: String },
    /// Input key material is shorter than the minimum allowed length.
    InsufficientIkm { len: usize, min: usize },
    /// Profile does not accept the specified pipeline.
    PipelineMismatch {
        profile: &'static str,
        pipeline: &'static str,
    },
    /// Requested expand output exceeds the maximum for the hash (255 * hash length).
    ExpandOutputTooLong { requested: usize, max: usize },
    /// PRK length does not match the hash output size.
    InvalidPrkLength { len: usize, expected: usize },
    /// Function requires a specific profile but a different one was provided.
    ProfileMismatch {
        expected: &'static str,
        got: &'static str,
    },
    /// Requested output length is zero.
    ZeroLengthOutput,
    /// Expand produced wrong number of bytes.
    ExpandLength { expected: usize, got: usize },
    /// Profile post-processing failed.
    PostProcessing { detail: String },
}

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(fmt, "{self:?}")
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn display_is_non_empty_and_carries_detail() {
        // Display delegates to Debug; confirm every kind renders a non-empty
        // message that includes the variant's data, so error output is useful.
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
        ];
        for case in &cases {
            assert!(!case.to_string().is_empty());
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
