use derive_more::From;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, From)]
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
    /// HKDF operation failed.
    #[from]
    Hkdf(hkdf::InvalidLength),
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

impl std::error::Error for Error {}
