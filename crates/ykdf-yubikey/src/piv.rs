//! PIV ECDH operations on `YubiKey` slot 9d (Key Management).

use p256::elliptic_curve::sec1::ToEncodedPoint;
use yubikey::YubiKey;
use yubikey::certificate::Certificate;
use yubikey::piv::{self, AlgorithmId, SlotId};
use zeroize::Zeroizing;

use crate::error::Error;

/// Read the P-256 public key from the certificate in PIV slot 9d.
///
/// Returns the uncompressed SEC1 encoding (0x04 || x || y, 65 bytes).
///
/// # Errors
///
/// Returns `Error::NoCertificate` if slot 9d has no certificate, or
/// `Error::InvalidPublicKey` if the certificate does not contain a
/// valid P-256 key.
pub fn read_public_key(yubikey: &mut YubiKey) -> crate::Result<Vec<u8>> {
    let cert = Certificate::read(yubikey, SlotId::KeyManagement).map_err(|e| {
        if matches!(e, yubikey::Error::NotFound) {
            Error::NoCertificate
        } else {
            Error::Piv(e.to_string())
        }
    })?;

    let spki = cert.subject_pki();
    let public_key = p256::PublicKey::try_from(spki).map_err(|e| Error::InvalidPublicKey {
        detail: e.to_string(),
    })?;

    Ok(public_key.to_encoded_point(false).as_bytes().to_vec())
}

/// Perform ECDH key agreement on slot 9d using the given peer public point.
///
/// The peer point must be in uncompressed SEC1 form (0x04 || x || y, 65 bytes).
/// Returns the 32-byte ECDH shared secret (x-coordinate).
///
/// This operation requires PIN verification and may require touch.
///
/// # Errors
///
/// Returns `Error::EcdhFailed` if the ECDH operation fails or the
/// result is not exactly 32 bytes.
pub fn ecdh(yubikey: &mut YubiKey, peer_point: &[u8]) -> crate::Result<Zeroizing<Vec<u8>>> {
    let result = piv::decrypt_data(
        yubikey,
        peer_point,
        AlgorithmId::EccP256,
        SlotId::KeyManagement,
    )
    .map_err(|e| Error::EcdhFailed {
        detail: e.to_string(),
    })?;

    if result.len() != 32 {
        return Err(Error::EcdhFailed {
            detail: format!(
                "unexpected ECDH output length: {} (expected 32)",
                result.len()
            ),
        });
    }

    Ok(Zeroizing::new(result.to_vec()))
}

/// Verify the PIV PIN.
///
/// # Errors
///
/// Returns `Error::WrongPin` with remaining retries, or
/// `Error::PinLocked` if the PIN is blocked.
pub fn verify_pin(yubikey: &mut YubiKey, pin: &[u8]) -> crate::Result<()> {
    yubikey.verify_pin(pin).map_err(|e| match e {
        yubikey::Error::WrongPin { tries } => Error::WrongPin { retries: tries },
        yubikey::Error::PinLocked => Error::PinLocked,
        other => Error::Piv(other.to_string()),
    })
}
