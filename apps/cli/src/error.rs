use std::path::PathBuf;

pub enum CliError {
    /// Error from ykdf-core.
    Core(ykdf_core::Error),
    /// Failed to read IKM file.
    IkmRead {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Output format is not valid for this profile.
    InvalidFormat {
        profile: &'static str,
        format: &'static str,
    },
    /// Profile does not have a public key.
    NoPubkey { profile: &'static str },
    /// Failed to read passphrase from terminal.
    PassphraseRead(std::io::Error),
    /// Failed to write output.
    OutputWrite(std::io::Error),
    /// --length is only valid with --profile raw.
    LengthRequiresRaw,
    /// --length is required with --profile raw and `derive_raw`.
    RawRequiresLength,
    /// `YubiKey` operation failed.
    YubiKey(ykdf_yubikey::Error),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidFormat { .. }
            | Self::NoPubkey { .. }
            | Self::LengthRequiresRaw
            | Self::RawRequiresLength => 2,
            _ => 1,
        }
    }
}

impl From<ykdf_core::Error> for CliError {
    fn from(e: ykdf_core::Error) -> Self {
        Self::Core(e)
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(e) => write!(f, "{e}"),
            Self::IkmRead { path, source } => {
                write!(f, "failed to read IKM from {}: {source}", path.display())
            }
            Self::InvalidFormat { profile, format } => {
                write!(f, "{format} format is not valid for the {profile} profile")
            }
            Self::NoPubkey { profile } => {
                write!(f, "{profile} profile does not have a public key")
            }
            Self::PassphraseRead(e) => write!(f, "failed to read passphrase: {e}"),
            Self::OutputWrite(e) => write!(f, "failed to write output: {e}"),
            Self::LengthRequiresRaw => write!(f, "--length is only valid with --profile raw"),
            Self::RawRequiresLength => write!(f, "--length is required with --profile raw"),
            Self::YubiKey(e) => write!(f, "{e}"),
        }
    }
}
