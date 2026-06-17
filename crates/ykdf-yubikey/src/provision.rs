//! Provisioning for `ykdf init`: on-device PIV key generation on slot 9d and
//! HMAC-SHA1 programming on OTP slot 2.
//!
//! The slot 9d key is generated on-device (non-extractable). A self-signed
//! certificate is written to the slot because the derive path reads the public
//! key back from that certificate (see [`crate::piv::read_public_key`]); the
//! certificate is only a public-key carrier.

use std::str::FromStr;
use std::time::Duration;

use p256::SecretKey;
use rand_core::OsRng;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use yubikey::YubiKey;
use yubikey::certificate::Certificate;
use yubikey::piv::{self, AlgorithmId, SlotId};
use yubikey::{MgmKey, PinPolicy, TouchPolicy};
use yubikey_hmac_otp::Yubico;
use yubikey_hmac_otp::config::{Command, Config, Mode, Slot};
use yubikey_hmac_otp::configure::DeviceModeConfig;
use yubikey_hmac_otp::hmacmode::HmacKey;
use zeroize::Zeroizing;

use crate::error::Error;

/// Subject distinguished name for the slot 9d carrier certificate.
const CERT_SUBJECT: &str = "CN=ykdf-key-management";

/// Certificate validity window in seconds (~20 years). The certificate is only
/// a carrier for the public key, so a long window avoids spurious expiry.
const CERT_VALIDITY_SECS: u64 = 630_720_000;

/// Length of an HMAC-SHA1 secret, in bytes.
pub const HMAC_SECRET_LEN: usize = 20;

/// PIN and touch policies applied to the generated slot 9d key.
#[derive(Clone, Copy)]
pub struct PivPolicy {
    pub pin_policy: PinPolicy,
    pub touch_policy: TouchPolicy,
}

impl Default for PivPolicy {
    /// Verify PIN once per session, require touch for every ECDH. Matches the
    /// derive flow, which prompts for the PIN and then touch.
    fn default() -> Self {
        Self {
            pin_policy: PinPolicy::Once,
            touch_policy: TouchPolicy::Always,
        }
    }
}

/// Open the first connected `YubiKey` over PC/SC for provisioning.
///
/// # Errors
///
/// Returns `Error::DeviceNotFound` if no `YubiKey` is present.
pub fn open() -> crate::Result<YubiKey> {
    YubiKey::open().map_err(|_| Error::DeviceNotFound)
}

/// Report whether PIV slot 9d already holds a key or certificate.
///
/// Uses `piv::metadata` (firmware 5.2.3+) and falls back to reading the
/// certificate, so an occupied slot is detected on older firmware too. A best
/// effort guard: callers must still honour an explicit overwrite flag.
pub fn slot9d_occupied(yubikey: &mut YubiKey) -> bool {
    piv::metadata(yubikey, SlotId::KeyManagement).is_ok()
        || Certificate::read(yubikey, SlotId::KeyManagement).is_ok()
}

/// Generate a P-256 key on slot 9d and write a self-signed carrier certificate.
///
/// Requires the PIV PIN (the certificate is signed by the freshly generated
/// key, so its PIN/touch policy applies) and the management key. Returns the
/// generated public key in uncompressed SEC1 form (65 bytes).
///
/// # Errors
///
/// Returns `Error::WrongPin`/`Error::PinLocked` on PIN failure,
/// `Error::MgmtAuthFailed` if management key authentication fails, or
/// `Error::ProvisionFailed` if key generation or certificate writing fails.
pub fn provision_piv(
    yubikey: &mut YubiKey,
    pin: &[u8],
    mgmt: MgmKey,
    policy: PivPolicy,
) -> crate::Result<Vec<u8>> {
    crate::piv::verify_pin(yubikey, pin)?;
    yubikey
        .authenticate(mgmt)
        .map_err(|_| Error::MgmtAuthFailed)?;

    let public = piv::generate(
        yubikey,
        SlotId::KeyManagement,
        AlgorithmId::EccP256,
        policy.pin_policy,
        policy.touch_policy,
    )
    .map_err(|e| Error::ProvisionFailed {
        detail: e.to_string(),
    })?;

    write_carrier_cert(yubikey, public)?;
    crate::piv::read_public_key(yubikey)
}

/// Generate a P-256 private scalar using the OS CSPRNG.
///
/// `OsRng` draws from the operating system's cryptographically secure RNG (the
/// `getrandom(2)` syscall on Linux, i.e. the same kernel CSPRNG as
/// `/dev/urandom`). `SecretKey::random` samples uniformly from the scalar
/// field. The returned bytes are the raw 32-byte big-endian scalar.
#[must_use]
pub fn generate_p256_scalar() -> Zeroizing<[u8; 32]> {
    let secret = SecretKey::random(&mut OsRng);
    let mut scalar = Zeroizing::new([0u8; 32]);
    scalar.copy_from_slice(secret.to_bytes().as_slice());
    scalar
}

/// Import an externally generated P-256 scalar into slot 9d and write the
/// carrier certificate for its derived public key.
///
/// Unlike [`provision_piv`], the private key is supplied by the host, so it can
/// be imported into more than one device for backup. Returns the public key in
/// uncompressed SEC1 form (65 bytes).
///
/// # Errors
///
/// Returns `Error::InvalidScalar` if the scalar is not a valid P-256 key,
/// `Error::WrongPin`/`Error::PinLocked` on PIN failure, `Error::MgmtAuthFailed`
/// if management key authentication fails, or `Error::ProvisionFailed` if the
/// import or certificate write fails.
pub fn provision_piv_import(
    yubikey: &mut YubiKey,
    pin: &[u8],
    mgmt: MgmKey,
    policy: PivPolicy,
    scalar: &[u8; 32],
) -> crate::Result<Vec<u8>> {
    // Validate the scalar and derive its public key on the host before touching
    // the device, so bad input fails early.
    let secret = SecretKey::from_slice(scalar).map_err(|e| Error::InvalidScalar {
        detail: e.to_string(),
    })?;
    let spki = SubjectPublicKeyInfoOwned::from_key(secret.public_key()).map_err(|e| {
        Error::ProvisionFailed {
            detail: e.to_string(),
        }
    })?;

    crate::piv::verify_pin(yubikey, pin)?;
    yubikey
        .authenticate(mgmt)
        .map_err(|_| Error::MgmtAuthFailed)?;

    // NOTE: import_ecc_key takes (.., touch_policy, pin_policy) -- the REVERSE
    // of piv::generate's (pin_policy, touch_policy) argument order.
    piv::import_ecc_key(
        yubikey,
        SlotId::KeyManagement,
        AlgorithmId::EccP256,
        scalar,
        policy.touch_policy,
        policy.pin_policy,
    )
    .map_err(|e| Error::ProvisionFailed {
        detail: e.to_string(),
    })?;

    write_carrier_cert(yubikey, spki)?;
    crate::piv::read_public_key(yubikey)
}

/// Build and write the slot 9d carrier certificate for `spki`.
///
/// The certificate carries the public key the derive path reads back; it is
/// self-signed by the slot key, which may require a touch.
fn write_carrier_cert(yubikey: &mut YubiKey, spki: SubjectPublicKeyInfoOwned) -> crate::Result<()> {
    // 19 bytes keeps the serial positive (a high MSB would be read as a sign).
    let mut serial_bytes = [0u8; 19];
    getrandom::getrandom(&mut serial_bytes).map_err(|e| Error::ProvisionFailed {
        detail: format!("serial generation failed: {e}"),
    })?;
    let serial = SerialNumber::new(&serial_bytes).map_err(|e| Error::ProvisionFailed {
        detail: e.to_string(),
    })?;
    let validity = Validity::from_now(Duration::from_secs(CERT_VALIDITY_SECS)).map_err(|e| {
        Error::ProvisionFailed {
            detail: e.to_string(),
        }
    })?;
    let subject = Name::from_str(CERT_SUBJECT).map_err(|e| Error::ProvisionFailed {
        detail: e.to_string(),
    })?;

    Certificate::generate_self_signed::<_, p256::NistP256>(
        yubikey,
        SlotId::KeyManagement,
        serial,
        validity,
        subject,
        spki,
        |_builder| Ok(()),
    )
    .map_err(|e| Error::ProvisionFailed {
        detail: e.to_string(),
    })?;
    Ok(())
}

/// Generate a random HMAC-SHA1 secret.
///
/// # Errors
///
/// Returns `Error::HmacProgramFailed` if the system RNG fails.
pub fn random_hmac_secret() -> crate::Result<Zeroizing<[u8; HMAC_SECRET_LEN]>> {
    let mut secret = Zeroizing::new([0u8; HMAC_SECRET_LEN]);
    getrandom::getrandom(secret.as_mut()).map_err(|e| Error::HmacProgramFailed {
        detail: format!("secret generation failed: {e}"),
    })?;
    Ok(secret)
}

/// Program a 20-byte HMAC-SHA1 secret onto OTP slot 2 for challenge-response.
///
/// This overwrites any existing slot 2 configuration. `require_touch` sets the
/// button-press policy for each challenge-response.
///
/// # Errors
///
/// Returns `Error::HmacProgramFailed` if the device is not found or the write
/// fails.
pub fn program_hmac_slot2(
    secret: &[u8; HMAC_SECRET_LEN],
    require_touch: bool,
) -> crate::Result<()> {
    let mut yubico = Yubico::new();
    let device = yubico
        .find_yubikey()
        .map_err(|e| Error::HmacProgramFailed {
            detail: e.to_string(),
        })?;

    let config = Config::new_from(device)
        .set_slot(Slot::Slot2)
        .set_mode(Mode::Sha1)
        .set_command(Command::Configuration2);

    let mut device_config = DeviceModeConfig::default();
    let hmac_key = HmacKey::from_slice(secret);
    device_config.challenge_response_hmac(&hmac_key, false, require_touch);

    yubico
        .write_config(config, &mut device_config)
        .map_err(|e| Error::HmacProgramFailed {
            detail: e.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::generate_p256_scalar;

    #[test]
    fn generated_scalar_is_a_valid_p256_key() {
        let scalar = generate_p256_scalar();
        assert_eq!(scalar.len(), 32);
        // The bytes must round-trip into a valid (non-zero, in-range) key.
        assert!(p256::SecretKey::from_slice(&scalar[..]).is_ok());
    }

    #[test]
    fn generated_scalars_differ() {
        let a = generate_p256_scalar();
        let b = generate_p256_scalar();
        assert_ne!(&a[..], &b[..], "two random scalars must not collide");
    }
}
