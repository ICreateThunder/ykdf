use clap::{Parser, Subcommand, ValueEnum};
use ykdf_core::{Pipeline, Profile};

/// YKDF: `YubiKey` key derivation framework
#[derive(Parser)]
#[command(name = "ykdf", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Derive a key from hardware entropy
    Derive(DeriveArgs),
    /// Show the public key for a derivation
    Pubkey(PubkeyArgs),
}

#[derive(clap::Args)]
pub struct DeriveArgs {
    /// Key profile
    #[arg(long)]
    pub profile: ProfileArg,

    /// Derivation purpose (lowercase alphanumeric + hyphens, 1-64 chars)
    #[arg(long)]
    pub purpose: String,

    /// KDF pipeline override
    #[arg(long)]
    pub pipeline: Option<PipelineArg>,

    /// Key rotation index
    #[arg(long, default_value_t = 0)]
    pub index: u32,

    /// Output format override
    #[arg(long)]
    pub format: Option<OutputFormat>,

    /// Read IKM from file instead of `YubiKey` (testing)
    #[arg(long, value_name = "PATH")]
    pub ikm_file: Option<std::path::PathBuf>,

    /// Use layered mode (PIV + HMAC)
    #[arg(long)]
    pub layered: bool,

    /// Prompt for passphrase as additional entropy factor
    #[arg(long)]
    pub passphrase: bool,

    /// Output length in bytes (only valid with --profile raw)
    #[arg(long)]
    pub length: Option<usize>,
}

#[derive(clap::Args)]
pub struct PubkeyArgs {
    /// Key profile
    #[arg(long)]
    pub profile: ProfileArg,

    /// Derivation purpose (lowercase alphanumeric + hyphens, 1-64 chars)
    #[arg(long)]
    pub purpose: String,

    /// KDF pipeline override
    #[arg(long)]
    pub pipeline: Option<PipelineArg>,

    /// Key rotation index
    #[arg(long, default_value_t = 0)]
    pub index: u32,

    /// Read IKM from file instead of `YubiKey` (testing)
    #[arg(long, value_name = "PATH")]
    pub ikm_file: Option<std::path::PathBuf>,

    /// Use layered mode (PIV + HMAC)
    #[arg(long)]
    pub layered: bool,

    /// Prompt for passphrase as additional entropy factor
    #[arg(long)]
    pub passphrase: bool,
}

#[derive(Clone, ValueEnum)]
pub enum ProfileArg {
    X25519,
    Ed25519,
    #[value(name = "age-x25519")]
    AgeX25519,
    Symmetric,
    Mlkem512,
    Mlkem768,
    Mlkem1024,
    Raw,
}

impl From<ProfileArg> for Profile {
    fn from(arg: ProfileArg) -> Self {
        match arg {
            ProfileArg::X25519 => Self::X25519,
            ProfileArg::Ed25519 => Self::Ed25519,
            ProfileArg::AgeX25519 => Self::AgeX25519,
            ProfileArg::Symmetric => Self::Symmetric,
            ProfileArg::Mlkem512 => Self::MlKem512,
            ProfileArg::Mlkem768 => Self::MlKem768,
            ProfileArg::Mlkem1024 => Self::MlKem1024,
            ProfileArg::Raw => Self::Raw,
        }
    }
}

#[derive(Clone, ValueEnum)]
pub enum PipelineArg {
    #[value(name = "hkdf-sha512")]
    HkdfSha512,
    #[value(name = "hkdf-sha3-512")]
    HkdfSha3512,
    Shake256,
}

impl From<PipelineArg> for Pipeline {
    fn from(arg: PipelineArg) -> Self {
        match arg {
            PipelineArg::HkdfSha512 => Self::HkdfSha512,
            PipelineArg::HkdfSha3512 => Self::HkdfSha3,
            PipelineArg::Shake256 => Self::Shake256,
        }
    }
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Base64,
    Hex,
    Openssh,
    Age,
    Binary,
}
