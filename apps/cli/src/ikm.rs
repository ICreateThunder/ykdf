use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::error::CliError;

pub enum IkmSource {
    File(PathBuf),
    YubiKey { layered: bool },
}

impl IkmSource {
    pub fn load(&self) -> Result<ykdf_core::Ikm, CliError> {
        match self {
            Self::File(path) => {
                let bytes = std::fs::read(path).map_err(|e| CliError::IkmRead {
                    path: path.clone(),
                    source: e,
                })?;
                ykdf_core::Ikm::new(bytes).map_err(CliError::Core)
            }
            Self::YubiKey { layered } => {
                let mode = if *layered {
                    ykdf_yubikey::IkmMode::Layered
                } else {
                    ykdf_yubikey::IkmMode::Standard
                };

                let pin = Zeroizing::new(
                    rpassword::prompt_password("PIV PIN: ").map_err(CliError::PassphraseRead)?,
                );

                ykdf_yubikey::derive_ikm(mode, pin.as_bytes()).map_err(CliError::YubiKey)
            }
        }
    }
}
