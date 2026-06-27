//! `YubiKey` transport for YKDF: PIV ECDH, HMAC-SHA1 challenge-response, and
//! provisioning.
//!
//! Reads the hardware secret from a `YubiKey` over PC/SC (PIV) and USB HID
//! (OTP/HMAC) and turns it into input key material for `ykdf-core`. This crate
//! is desktop-only (it needs a PC/SC stack); other platforms supply their own
//! transport.

#![deny(missing_docs)]

mod error;
pub mod hmac;
pub mod piv;
pub mod provision;

pub use self::error::{Error, Result};

// Re-exported so the CLI can build provisioning policies without depending on
// the `yubikey` crate directly.
pub use yubikey::{MgmKey, PinPolicy, TouchPolicy};

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
    // The YubiKey serializes operations across its interfaces and is briefly
    // unavailable on the OTP HID interface right after a touch-triggered PIV
    // operation on CCID. So read the HMAC factor (HID) first, before the ECDH
    // touch; the IKM is ECDH || HMAC regardless of the order we read them in.
    let hmac_response = if mode == IkmMode::Layered {
        Some(hmac::challenge_response()?)
    } else {
        None
    };

    // Open YubiKey via PC/SC for the PIV operations.
    let mut yubikey = yubikey::YubiKey::open().map_err(|_| Error::DeviceNotFound)?;

    // Verify PIN (required for PIV key operations).
    piv::verify_pin(&mut yubikey, pin)?;

    // Read own public key from the certificate in slot 9d.
    let peer_point = piv::read_public_key(&mut yubikey)?;

    // Print touch prompt to stderr (touch is required for ECDH).
    eprintln!("Touch your YubiKey...");

    // Perform self-ECDH: ECDH(private_key, own_public_key).
    let ecdh_secret = piv::ecdh(&mut yubikey, &peer_point)?;

    // Drop the PC/SC connection.
    drop(yubikey);

    // Assemble IKM = ECDH || HMAC (no extra copy of the ECDH secret).
    let mut ikm = ecdh_secret;
    if let Some(hmac_response) = hmac_response {
        ikm.extend_from_slice(&hmac_response);
    }

    // Move the inner Vec out of Zeroizing to pass to Ikm::new.
    let inner = std::mem::take(&mut *ikm);
    ykdf_core::Ikm::new(inner).map_err(|e| Error::EcdhFailed {
        detail: e.to_string(),
    })
}
