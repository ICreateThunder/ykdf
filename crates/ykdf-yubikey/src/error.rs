pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// No `YubiKey` device found.
    DeviceNotFound,
    /// PIV PIN verification failed.
    WrongPin { retries: u8 },
    /// PIV PIN is locked (too many failed attempts).
    PinLocked,
    /// No certificate in PIV slot 9d.
    NoCertificate,
    /// Certificate does not contain a valid P-256 public key.
    InvalidPublicKey { detail: String },
    /// PIV ECDH key agreement failed.
    EcdhFailed { detail: String },
    /// HMAC-SHA1 challenge-response failed.
    HmacFailed { detail: String },
    /// `YubiKey` PIV operation error.
    Piv(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::DeviceNotFound => write!(f, "no YubiKey device found"),
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
            Self::Piv(detail) => write!(f, "PIV operation failed: {detail}"),
        }
    }
}

impl std::error::Error for Error {}
