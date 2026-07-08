use clap::{Parser, Subcommand, ValueEnum};
use ykdf_core::{Pipeline, Profile};

/// YKDF: `YubiKey` key derivation framework
#[derive(Parser)]
#[command(name = "ykdf", version, about)]
pub struct Cli {
    /// Path to the recipe config file (default: `$XDG_CONFIG_HOME/ykdf/config.toml`
    /// or `$HOME/.config/ykdf/config.toml`; overrides `YKDF_CONFIG`)
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<std::path::PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Derive a key from hardware entropy
    Derive(DeriveArgs),
    /// Show the public key for a derivation
    Pubkey(PubkeyArgs),
    /// Provision a `YubiKey` for use with YKDF
    Init(InitArgs),
    /// Clone one root to several keys in a single swap-session (the secret
    /// stays in host RAM and is wiped on exit; never displayed or written)
    Clone(CloneArgs),
    /// List or show named recipes from the config file
    Recipe(RecipeArgs),
    /// Derive `WireGuard` keys and assemble configs (x25519)
    Wg(WgArgs),
}

#[derive(clap::Args)]
pub struct WgArgs {
    #[command(subcommand)]
    pub command: WgCommand,
}

#[derive(Subcommand)]
pub enum WgCommand {
    /// Print the derived `WireGuard` private key (base64)
    Key(WgDerive),
    /// Print the derived `WireGuard` public key (base64)
    Pubkey(WgDerive),
    /// Print a `[Peer]` stanza for this device, to paste into the other end's
    /// config
    Peer(WgPeerArgs),
    /// Assemble a full `[Interface]` config (with an optional `[Peer]`)
    Config(WgConfigArgs),
}

/// The derivation surface shared by every `wg` subcommand. The profile is always
/// x25519 (the `WireGuard` key type), so there is no `--profile` flag.
#[derive(clap::Args)]
pub struct WgDerive {
    /// Named recipe to derive (its profile must be x25519; explicit flags still
    /// override). Omit to specify everything with flags
    #[arg(value_name = "RECIPE")]
    pub recipe: Option<String>,

    /// Derivation purpose (lowercase alphanumeric + hyphens, 1-64 chars;
    /// required unless a recipe supplies it)
    #[arg(long)]
    pub purpose: Option<String>,

    /// KDF pipeline override
    #[arg(long)]
    pub pipeline: Option<PipelineArg>,

    /// Key rotation index
    #[arg(long)]
    pub index: Option<u32>,

    /// Read IKM from file instead of `YubiKey` (testing)
    #[arg(long, value_name = "PATH")]
    pub ikm_file: Option<std::path::PathBuf>,

    /// Use layered mode (PIV + HMAC)
    #[arg(long)]
    pub layered: bool,

    /// Prompt for passphrase as additional entropy factor
    #[arg(long)]
    pub passphrase: bool,

    /// Smartcard transport for the PIV factor
    #[arg(long, default_value = "auto")]
    pub transport: TransportArg,
}

#[derive(clap::Args)]
pub struct WgPeerArgs {
    #[command(flatten)]
    pub derive: WgDerive,

    /// IP ranges the other end should route to this device (CIDR; repeatable).
    /// Defaults to the recipe's `[wg].address` when a recipe supplies one
    #[arg(long, value_name = "CIDR")]
    pub allowed_ips: Vec<String>,

    /// Endpoint to advertise for this device (host:port)
    #[arg(long, value_name = "HOST:PORT")]
    pub endpoint: Option<String>,
}

#[derive(clap::Args)]
pub struct WgConfigArgs {
    #[command(flatten)]
    pub derive: WgDerive,

    /// Interface address (CIDR; repeatable). Required unless a recipe's
    /// `[wg].address` supplies one
    #[arg(long, value_name = "CIDR")]
    pub address: Vec<String>,

    /// UDP port to listen on
    #[arg(long, value_name = "PORT")]
    pub listen_port: Option<u16>,

    /// DNS server for the interface (repeatable)
    #[arg(long, value_name = "IP")]
    pub dns: Vec<String>,

    /// Interface MTU
    #[arg(long, value_name = "N")]
    pub mtu: Option<u32>,

    /// Peer public key (base64); gates the `[Peer]` block
    #[arg(long, value_name = "BASE64")]
    pub peer_pubkey: Option<String>,

    /// Peer endpoint (host:port)
    #[arg(long, value_name = "HOST:PORT", requires = "peer_pubkey")]
    pub endpoint: Option<String>,

    /// IP ranges to route to the peer (CIDR; repeatable)
    #[arg(long, value_name = "CIDR", requires = "peer_pubkey")]
    pub allowed_ips: Vec<String>,

    /// Keepalive interval for the peer, in seconds
    #[arg(long, value_name = "SECS", requires = "peer_pubkey")]
    pub keepalive: Option<u16>,

    /// Write the config to PATH (mode 0600) instead of stdout
    #[arg(long, short = 'o', value_name = "PATH")]
    pub output: Option<std::path::PathBuf>,
}

#[derive(clap::Args)]
pub struct RecipeArgs {
    #[command(subcommand)]
    pub command: RecipeCommand,
}

#[derive(Subcommand)]
pub enum RecipeCommand {
    /// List the configured recipes
    List,
    /// Show a recipe's fully resolved derivation parameters
    Show {
        /// Recipe name
        name: String,
    },
}

#[derive(clap::Args)]
pub struct InitArgs {
    /// Also program HMAC-SHA1 on OTP slot 2 (layered mode)
    #[arg(long)]
    pub layered: bool,

    /// Generate the slot 9d key on the host and display it once for backup
    /// (importable to another device), instead of non-extractable on-device
    /// generation
    #[arg(long, conflicts_with = "import")]
    pub exportable: bool,

    /// Import a host-held P-256 private key (64 hex chars) into slot 9d, e.g.
    /// to provision a backup device with the same key. Exposed in the process
    /// table; prefer --import-file
    #[arg(long, value_name = "HEX")]
    pub import: Option<String>,

    /// Read the --import scalar (64 hex chars) from a file instead of the
    /// command line, keeping it out of the process table. Use `-` for stdin
    #[arg(long, value_name = "PATH", conflicts_with_all = ["import", "exportable"])]
    pub import_file: Option<std::path::PathBuf>,

    /// Use an exact 20-byte HMAC secret (40 hex chars) instead of a random one.
    /// Exposed in the process table; prefer --hmac-secret-file
    #[arg(long, value_name = "HEX", requires = "layered")]
    pub hmac_secret: Option<String>,

    /// Read the --hmac-secret value (40 hex chars) from a file instead of the
    /// command line, keeping it out of the process table. Use `-` for stdin
    #[arg(
        long,
        value_name = "PATH",
        requires = "layered",
        conflicts_with = "hmac_secret"
    )]
    pub hmac_secret_file: Option<std::path::PathBuf>,

    /// PIV management key: 48 hex chars, or `protected`/`derived` to read a
    /// key stored on the device; defaults to auto-detect (factory, then
    /// PIN-protected, then PIN-derived). An explicit hex key is exposed in the
    /// process table; prefer --mgmt-key-file
    #[arg(long, value_name = "HEX|protected|derived")]
    pub mgmt_key: Option<String>,

    /// Read an explicit PIV management key (48 hex chars) from a file instead
    /// of the command line, keeping it out of the process table. Use `-` for
    /// stdin. For the `protected`/`derived` keywords use --mgmt-key
    #[arg(long, value_name = "PATH", conflicts_with = "mgmt_key")]
    pub mgmt_key_file: Option<std::path::PathBuf>,

    /// Overwrite an already-provisioned slot 9d / slot 2 without prompting
    #[arg(long)]
    pub force: bool,

    /// PIN policy for the generated slot 9d key
    #[arg(long, default_value = "once")]
    pub pin_policy: PinPolicyArg,

    /// Touch policy for the generated slot 9d key
    #[arg(long, default_value = "always")]
    pub touch_policy: TouchPolicyArg,
}

#[derive(clap::Args)]
pub struct CloneArgs {
    /// Also program a single shared HMAC-SHA1 secret on OTP slot 2 of every
    /// device (layered mode)
    #[arg(long)]
    pub layered: bool,

    /// Clone an existing slot 9d scalar (64 hex chars) read from a file, instead
    /// of generating a fresh root. Use a real path, not `-` (stdin is reserved
    /// for the per-device prompts)
    #[arg(long, value_name = "PATH")]
    pub import_file: Option<std::path::PathBuf>,

    /// With --layered, read the shared 20-byte HMAC secret (40 hex chars) from a
    /// file instead of generating one. Use a real path, not `-`
    #[arg(long, value_name = "PATH", requires = "layered")]
    pub hmac_secret_file: Option<std::path::PathBuf>,

    /// After cloning, print the in-RAM root secret once on stderr. This defeats
    /// the RAM-only property; for a saved copy prefer `init --exportable`
    #[arg(long)]
    pub show: bool,

    /// PIV management key: 48 hex chars, or `protected`/`derived` to read a key
    /// stored on each device; defaults to auto-detect (factory, then
    /// PIN-protected, then PIN-derived). An explicit hex key is exposed in the
    /// process table; prefer --mgmt-key-file
    #[arg(long, value_name = "HEX|protected|derived")]
    pub mgmt_key: Option<String>,

    /// Read an explicit PIV management key (48 hex chars) from a file instead of
    /// the command line. Use a real path, not `-`
    #[arg(long, value_name = "PATH", conflicts_with = "mgmt_key")]
    pub mgmt_key_file: Option<std::path::PathBuf>,

    /// Overwrite an occupied slot 9d / slot 2 on every device without prompting
    #[arg(long)]
    pub force: bool,

    /// PIN policy for the imported slot 9d key
    #[arg(long, default_value = "once")]
    pub pin_policy: PinPolicyArg,

    /// Touch policy for the imported slot 9d key
    #[arg(long, default_value = "always")]
    pub touch_policy: TouchPolicyArg,
}

#[derive(Clone, ValueEnum)]
pub enum PinPolicyArg {
    Once,
    Always,
    Never,
}

#[derive(Clone, ValueEnum)]
pub enum TouchPolicyArg {
    Always,
    Cached,
    Never,
}

impl From<PinPolicyArg> for ykdf_yubikey::PinPolicy {
    fn from(arg: PinPolicyArg) -> Self {
        match arg {
            PinPolicyArg::Once => Self::Once,
            PinPolicyArg::Always => Self::Always,
            PinPolicyArg::Never => Self::Never,
        }
    }
}

impl From<TouchPolicyArg> for ykdf_yubikey::TouchPolicy {
    fn from(arg: TouchPolicyArg) -> Self {
        match arg {
            TouchPolicyArg::Always => Self::Always,
            TouchPolicyArg::Cached => Self::Cached,
            TouchPolicyArg::Never => Self::Never,
        }
    }
}

#[derive(clap::Args)]
pub struct DeriveArgs {
    /// Named recipe to derive (fills profile/purpose/etc.; explicit flags still
    /// override). Omit to specify everything with flags
    #[arg(value_name = "RECIPE")]
    pub recipe: Option<String>,

    /// Key profile (required unless a recipe supplies it)
    #[arg(long)]
    pub profile: Option<ProfileArg>,

    /// Derivation purpose (lowercase alphanumeric + hyphens, 1-64 chars;
    /// required unless a recipe supplies it)
    #[arg(long)]
    pub purpose: Option<String>,

    /// KDF pipeline override
    #[arg(long)]
    pub pipeline: Option<PipelineArg>,

    /// Key rotation index
    #[arg(long)]
    pub index: Option<u32>,

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

    /// Smartcard transport for the PIV factor
    #[arg(long, default_value = "auto")]
    pub transport: TransportArg,
}

#[derive(clap::Args)]
pub struct PubkeyArgs {
    /// Named recipe to show the public key for (fills profile/purpose/etc.;
    /// explicit flags still override). Omit to specify everything with flags
    #[arg(value_name = "RECIPE")]
    pub recipe: Option<String>,

    /// Key profile (required unless a recipe supplies it)
    #[arg(long)]
    pub profile: Option<ProfileArg>,

    /// Derivation purpose (lowercase alphanumeric + hyphens, 1-64 chars;
    /// required unless a recipe supplies it)
    #[arg(long)]
    pub purpose: Option<String>,

    /// KDF pipeline override
    #[arg(long)]
    pub pipeline: Option<PipelineArg>,

    /// Key rotation index
    #[arg(long)]
    pub index: Option<u32>,

    /// Read IKM from file instead of `YubiKey` (testing)
    #[arg(long, value_name = "PATH")]
    pub ikm_file: Option<std::path::PathBuf>,

    /// Use layered mode (PIV + HMAC)
    #[arg(long)]
    pub layered: bool,

    /// Prompt for passphrase as additional entropy factor
    #[arg(long)]
    pub passphrase: bool,

    /// Smartcard transport for the PIV factor
    #[arg(long, default_value = "auto")]
    pub transport: TransportArg,
}

/// Selects how the PIV factor reaches the smartcard.
#[derive(Clone, Copy, ValueEnum)]
pub enum TransportArg {
    /// Auto-detect: direct PC/SC, falling back to gpg-agent's scdaemon when the
    /// card is held by gpg
    Auto,
    /// Force the direct PC/SC path (no gpg involvement)
    Pcsc,
    /// Route through gpg-agent's scdaemon (coexist with gpg without releasing
    /// the card)
    Scdaemon,
}

impl TransportArg {
    /// Map to an explicit transport override, or `None` for auto-detection.
    pub fn to_override(self) -> Option<ykdf_yubikey::Transport> {
        match self {
            Self::Auto => None,
            Self::Pcsc => Some(ykdf_yubikey::Transport::Pcsc),
            Self::Scdaemon => Some(ykdf_yubikey::Transport::Scdaemon),
        }
    }
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
    Mldsa44,
    Mldsa65,
    Mldsa87,
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
            ProfileArg::Mldsa44 => Self::MlDsa44,
            ProfileArg::Mldsa65 => Self::MlDsa65,
            ProfileArg::Mldsa87 => Self::MlDsa87,
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
