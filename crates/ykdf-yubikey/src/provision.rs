//! Provisioning for `ykdf init`: on-device PIV key generation on slot 9d and
//! HMAC-SHA1 programming on OTP slot 2.
//!
//! The slot 9d key is generated on-device (non-extractable). A self-signed
//! certificate is written to the slot because the derive path reads the public
//! key back from that certificate (see [`crate::piv::read_public_key`]); the
//! certificate is only a public-key carrier.

use std::str::FromStr;
use std::time::Duration;

use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
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

    // Signing the certificate uses the slot key, so this may require a touch.
    Certificate::generate_self_signed::<_, p256::NistP256>(
        yubikey,
        SlotId::KeyManagement,
        serial,
        validity,
        subject,
        public,
        |_builder| Ok(()),
    )
    .map_err(|e| Error::ProvisionFailed {
        detail: e.to_string(),
    })?;

    crate::piv::read_public_key(yubikey)
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
