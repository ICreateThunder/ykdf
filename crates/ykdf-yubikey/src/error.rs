/// Specialized [`Result`](core::result::Result) for `ykdf-yubikey` operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors from `YubiKey` PIV, HMAC, and provisioning operations.
#[derive(Debug)]
pub enum Error {
    /// No `YubiKey` device found.
    DeviceNotFound,
    /// The `YubiKey` smartcard (PC/SC) is held exclusively by another
    /// application, commonly `gpg-agent`'s `scdaemon`.
    SmartcardBusy,
    /// PIV PIN verification failed.
    WrongPin {
        /// Remaining PIN attempts.
        retries: u8,
    },
    /// PIV PIN is locked (too many failed attempts).
    PinLocked,
    /// No certificate in PIV slot 9d.
    NoCertificate,
    /// Certificate does not contain a valid P-256 public key.
    InvalidPublicKey {
        /// Description of the failure.
        detail: String,
    },
    /// PIV ECDH key agreement failed.
    EcdhFailed {
        /// Description of the failure.
        detail: String,
    },
    /// HMAC-SHA1 challenge-response failed.
    HmacFailed {
        /// Description of the failure.
        detail: String,
    },
    /// PIV management key authentication failed.
    MgmtAuthFailed,
    /// The PIN-protected or PIN-derived management key could not be read.
    MgmtKeyUnavailable,
    /// PIV provisioning (key generation or certificate write) failed.
    ProvisionFailed {
        /// Description of the failure.
        detail: String,
    },
    /// A supplied private scalar is not a valid P-256 key.
    InvalidScalar {
        /// Description of the failure.
        detail: String,
    },
    /// Programming the HMAC-SHA1 secret onto OTP slot 2 failed.
    HmacProgramFailed {
        /// Description of the failure.
        detail: String,
    },
    /// `YubiKey` PIV operation error.
    Piv(String),
    /// Error talking to gpg-agent's scdaemon (the passthrough transport).
    Scd(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::DeviceNotFound => write!(f, "no YubiKey device found"),
            Self::SmartcardBusy => write!(
                f,
                "the YubiKey smartcard is in use by another application (e.g. \
                 gpg-agent's scdaemon, Yubico Authenticator, ykman, or a browser/SSH \
                 PKCS#11 module); close it and retry. For gpg, run `gpgconf --kill scdaemon`"
            ),
            Self::WrongPin { retries } => {
                write!(f, "wrong PIN ({retries} attempts remaining)")
            }
            Self::PinLocked => write!(f, "PIN is locked (too many failed attempts)"),
            Self::NoCertificate => {
                write!(f, "no certificate in PIV slot 9d (Key Management)")
            }
            Self::InvalidPublicKey { detail } => {
                write!(f, "invalid public key in certificate: {detail}")
            }
            Self::EcdhFailed { detail } => write!(f, "ECDH key agreement failed: {detail}"),
            Self::HmacFailed { detail } => write!(f, "HMAC challenge-response failed: {detail}"),
            Self::MgmtAuthFailed => write!(
                f,
                "PIV management key authentication failed (wrong key; pass --mgmt-key <hex>, \
                 or 'protected'/'derived' if the key is stored on the device)"
            ),
            Self::MgmtKeyUnavailable => write!(
                f,
                "could not read the PIN-protected or PIN-derived management key from this YubiKey"
            ),
            Self::ProvisionFailed { detail } => write!(f, "PIV provisioning failed: {detail}"),
            Self::InvalidScalar { detail } => write!(f, "invalid P-256 private key: {detail}"),
            Self::HmacProgramFailed { detail } => {
                write!(f, "programming HMAC slot 2 failed: {detail}")
            }
            Self::Piv(detail) => write!(f, "PIV operation failed: {detail}"),
            Self::Scd(detail) => write!(f, "gpg-agent/scdaemon transport failed: {detail}"),
        }
    }
}

impl std::error::Error for Error {}
