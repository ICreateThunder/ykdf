//! HMAC-SHA1 challenge-response on `YubiKey` OTP slot 2.

use yubikey_hmac_otp::Yubico;
use yubikey_hmac_otp::config::{Command, Config, Mode, Slot};
use zeroize::Zeroizing;

use crate::error::Error;

/// Fixed challenge for HMAC-SHA1. Domain separation happens in the
/// expand phase via the context string, so the HMAC output is the
/// same regardless of which key is being derived.
const CHALLENGE: &[u8] = b"ykdf-v1";

/// Perform HMAC-SHA1 challenge-response on OTP slot 2.
///
/// Returns the 20-byte HMAC response. May require touch.
///
/// # Errors
///
/// Returns `Error::HmacFailed` if the device is not found or the
/// challenge-response operation fails.
pub fn challenge_response() -> crate::Result<Zeroizing<Vec<u8>>> {
    let mut yubico = Yubico::new();
    let device = yubico.find_yubikey().map_err(|e| Error::HmacFailed {
        detail: e.to_string(),
    })?;

    let config = Config::new_from(device)
        .set_slot(Slot::Slot2)
        .set_mode(Mode::Sha1)
        .set_command(Command::ChallengeHmac2);

    let hmac_result = yubico
        .challenge_response_hmac(CHALLENGE, config)
        .map_err(|e| Error::HmacFailed {
            detail: e.to_string(),
        })?;

    Ok(Zeroizing::new(hmac_result.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::CHALLENGE;

    /// Frozen v1 invariant: the HMAC-SHA1 challenge is fixed. Changing it
    /// re-namespaces every layered-mode derivation, so it is part of the v1
    /// format. The golden vectors run over `--ikm-file` and never touch this
    /// hardware path, so this is the only guard against a silent change.
    #[test]
    fn challenge_is_frozen() {
        assert_eq!(CHALLENGE, b"ykdf-v1");
    }
}
