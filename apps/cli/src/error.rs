use std::path::PathBuf;

#[derive(Debug)]
pub enum CliError {
    /// Error from ykdf-core.
    Core(ykdf_core::Error),
    /// Error loading, parsing, or resolving a recipe from the config file.
    Config(ykdf_config::ConfigError),
    /// No profile given: needed when no recipe supplies one.
    MissingProfile,
    /// No purpose given: needed when no recipe supplies one.
    MissingPurpose,
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
    /// PIV slot 9d already holds a key; refuse to overwrite without --force.
    SlotOccupied,
    /// --hmac-secret is not 40 hex characters (20 bytes).
    InvalidHmacSecret,
    /// --mgmt-key is not 48 hex characters (24 bytes).
    InvalidMgmtKey,
    /// --import is not 64 hex characters (32 bytes).
    InvalidImportKey,
    /// Failed to read a secret from a --*-file path (or stdin).
    SecretFileRead {
        path: PathBuf,
        source: std::io::Error,
    },
    /// More than one secret was requested from stdin (`-`).
    MultipleStdinSecrets,
    /// `clone` reserves stdin for device prompts, so secret files cannot use `-`.
    CloneStdinUnsupported { flag: &'static str },
    /// `wg` needs an x25519 key, but the named recipe derives another profile.
    WgProfileMismatch { profile: &'static str },
    /// `wg config` has no interface address from a flag or the recipe's `[wg]`.
    WgMissingAddress,
    /// `wg peer` has no allowed-ips from a flag or the recipe's `[wg].address`.
    WgMissingAllowedIps,
    /// Failed to write the wg config to a `--output` path.
    OutputFile {
        path: PathBuf,
        source: std::io::Error,
    },
    /// `sign` needs a signing profile, but the recipe/flags give another.
    SignProfileMismatch { profile: &'static str },
    /// Failed to read a sign/verify input (message, signature, or public key).
    InputRead(std::io::Error),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidFormat { .. }
            | Self::NoPubkey { .. }
            | Self::LengthRequiresRaw
            | Self::RawRequiresLength
            | Self::InvalidHmacSecret
            | Self::InvalidMgmtKey
            | Self::InvalidImportKey
            | Self::MultipleStdinSecrets
            | Self::MissingProfile
            | Self::MissingPurpose
            | Self::WgProfileMismatch { .. }
            | Self::WgMissingAddress
            | Self::WgMissingAllowedIps
            | Self::SignProfileMismatch { .. }
            | Self::CloneStdinUnsupported { .. } => 2,
            _ => 1,
        }
    }
}

impl From<ykdf_core::Error> for CliError {
    fn from(e: ykdf_core::Error) -> Self {
        Self::Core(e)
    }
}

impl From<ykdf_config::ConfigError> for CliError {
    fn from(e: ykdf_config::ConfigError) -> Self {
        Self::Config(e)
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(e) => write!(f, "{e}"),
            Self::Config(e) => write!(f, "{e}"),
            Self::MissingProfile => write!(
                f,
                "no profile given: pass --profile, or name a recipe that sets one"
            ),
            Self::MissingPurpose => write!(
                f,
                "no purpose given: pass --purpose, or name a recipe that sets one"
            ),
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
            Self::SlotOccupied => write!(
                f,
                "PIV slot 9d already holds a key; provisioning would change the \
                 derivation root and orphan existing derived keys. Re-run with \
                 --force to overwrite."
            ),
            Self::InvalidHmacSecret => {
                write!(f, "--hmac-secret must be 40 hex characters (20 bytes)")
            }
            Self::InvalidMgmtKey => {
                write!(f, "--mgmt-key must be 48 hex characters (24 bytes)")
            }
            Self::InvalidImportKey => {
                write!(f, "--import must be 64 hex characters (32 bytes)")
            }
            Self::SecretFileRead { path, source } => {
                write!(f, "failed to read secret from {}: {source}", path.display())
            }
            Self::MultipleStdinSecrets => {
                write!(f, "only one secret can be read from stdin (`-`)")
            }
            Self::CloneStdinUnsupported { flag } => write!(
                f,
                "clone reads the per-device prompts from stdin, so {flag} cannot \
                 use `-` (stdin); pass a real file path"
            ),
            Self::WgProfileMismatch { profile } => write!(
                f,
                "wg needs an x25519 key, but this recipe derives {profile}; \
                 use an x25519 recipe or drop the recipe and pass flags"
            ),
            Self::WgMissingAddress => write!(
                f,
                "wg config needs an interface address: pass --address, or name a \
                 recipe whose [wg] section sets one"
            ),
            Self::WgMissingAllowedIps => write!(
                f,
                "wg peer needs allowed-ips: pass --allowed-ips, or name a recipe \
                 whose [wg] section sets an address"
            ),
            Self::OutputFile { path, source } => {
                write!(f, "failed to write config to {}: {source}", path.display())
            }
            Self::SignProfileMismatch { profile } => write!(
                f,
                "sign needs an ed25519 key, but this derives {profile}; \
                 use an ed25519 recipe or pass --profile ed25519"
            ),
            Self::InputRead(e) => write!(f, "failed to read input: {e}"),
        }
    }
}
