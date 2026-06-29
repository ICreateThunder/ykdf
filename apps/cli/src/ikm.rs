use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::error::CliError;

pub enum IkmSource {
    File(PathBuf),
    YubiKey {
        layered: bool,
        transport: Option<ykdf_yubikey::Transport>,
    },
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
            Self::YubiKey { layered, transport } => {
                let mode = if *layered {
                    ykdf_yubikey::IkmMode::Layered
                } else {
                    ykdf_yubikey::IkmMode::Standard
                };

                // Choose the transport before prompting for the PIN: this fails
                // fast on a missing device and, when the card is held by gpg's
                // scdaemon, routes through it instead of erroring. An explicit
                // --transport overrides the YKDF_TRANSPORT env var and auto-detect.
                let chosen = ykdf_yubikey::select_transport_override(*transport)
                    .map_err(CliError::YubiKey)?;
                if chosen == ykdf_yubikey::Transport::Scdaemon {
                    eprintln!("Using gpg-agent's scdaemon for the smartcard (PIV).");
                }

                let pin = Zeroizing::new(
                    rpassword::prompt_password("PIV PIN: ").map_err(CliError::PassphraseRead)?,
                );

                // Cue the operator to touch on each blink. Layered mode reads
                // the OTP/HMAC factor first, then the PIV signature: that is two
                // blinks if slot 2 was programmed with a touch requirement, or
                // one (PIV only) if it was not. Either way, "touch on each blink"
                // is the correct instruction.
                if *layered {
                    eprintln!(
                        "Touch the YubiKey on each blink: the OTP/HMAC factor (only if slot 2 \
                         requires touch), then the PIV signature."
                    );
                } else {
                    eprintln!("Touch the YubiKey when it blinks (PIV signature).");
                }

                ykdf_yubikey::derive_ikm_with(chosen, mode, pin.as_bytes())
                    .map_err(CliError::YubiKey)
            }
        }
    }
}
