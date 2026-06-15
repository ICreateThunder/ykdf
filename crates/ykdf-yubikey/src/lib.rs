mod error;
pub mod hmac;
pub mod piv;

pub use self::error::{Error, Result};

/// IKM derivation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkmMode {
    /// PIV ECDH only (32 bytes).
    Standard,
    /// PIV ECDH (32 bytes) + HMAC-SHA1 (20 bytes) = 52 bytes.
    Layered,
}

/// Derive input key material from a connected `YubiKey`.
///
/// Opens the first available `YubiKey`, verifies the PIV PIN, reads the
/// P-256 public key from the slot 9d certificate, and performs self-ECDH
/// (using the key's own public key as the peer point). In layered mode,
/// also performs HMAC-SHA1 challenge-response on OTP slot 2 and
/// concatenates the result.
///
/// # Errors
///
/// Returns an error if no `YubiKey` is found, PIN is wrong, the
/// certificate is missing, or the cryptographic operation fails.
pub fn derive_ikm(mode: IkmMode, pin: &[u8]) -> Result<ykdf_core::Ikm> {
    // Open YubiKey via PC/SC.
    let mut yubikey = yubikey::YubiKey::open().map_err(|_| Error::DeviceNotFound)?;

    // Verify PIN (required for PIV key operations).
    piv::verify_pin(&mut yubikey, pin)?;

    // Read own public key from the certificate in slot 9d.
    let peer_point = piv::read_public_key(&mut yubikey)?;

    // Print touch prompt to stderr (touch is required for ECDH).
    eprintln!("Touch your YubiKey...");

    // Perform self-ECDH: ECDH(private_key, own_public_key).
    let ecdh_secret = piv::ecdh(&mut yubikey, &peer_point)?;

    // Drop the PC/SC connection before opening USB HID for HMAC.
    drop(yubikey);

    // Move the ECDH secret directly (no extra copy).
    let mut ikm = ecdh_secret;

    if mode == IkmMode::Layered {
        eprintln!("Touch your YubiKey again for HMAC...");
        let hmac_response = hmac::challenge_response()?;
        ikm.extend_from_slice(&hmac_response);
    }

    // Move the inner Vec out of Zeroizing to pass to Ikm::new.
    let inner = std::mem::take(&mut *ikm);
    ykdf_core::Ikm::new(inner).map_err(|e| Error::EcdhFailed {
        detail: e.to_string(),
    })
}
