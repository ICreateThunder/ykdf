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
#[cfg(unix)]
mod scd;

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

/// Open the first connected `YubiKey` over PC/SC, distinguishing a reader held
/// by another application from a genuinely absent device.
///
/// `YubiKey::open()` silently skips any reader it cannot connect to, so a card
/// held exclusively (e.g. by `gpg-agent`'s `scdaemon`) collapses into
/// `NotFound`. When the open fails we re-probe the readers: if one reports a
/// PC/SC sharing violation, surface [`Error::SmartcardBusy`] (which names the
/// remedy) instead of the misleading [`Error::DeviceNotFound`].
pub(crate) fn open_yubikey() -> Result<yubikey::YubiKey> {
    match yubikey::YubiKey::open() {
        Ok(yubikey) => Ok(yubikey),
        Err(_) if smartcard_busy() => Err(Error::SmartcardBusy),
        Err(_) => Err(Error::DeviceNotFound),
    }
}

/// Report whether a PC/SC reader is present but held exclusively by another
/// application (a sharing violation), which is how `scdaemon` contention
/// appears. Best effort: any probing failure is treated as "not busy" so the
/// caller falls back to [`Error::DeviceNotFound`].
fn smartcard_busy() -> bool {
    let Ok(mut readers) = yubikey::reader::Context::open() else {
        return false;
    };
    let Ok(iter) = readers.iter() else {
        return false;
    };
    iter.into_iter().any(|reader| {
        matches!(
            reader.open(),
            Err(yubikey::Error::PcscError {
                inner: Some(pcsc::Error::SharingViolation),
            })
        )
    })
}

/// Check that a usable `YubiKey` smartcard is reachable, without performing any
/// operation on it.
///
/// Callers use this to fail fast before prompting for a PIN: it surfaces
/// [`Error::DeviceNotFound`] or [`Error::SmartcardBusy`] up front, so the user
/// is not asked for a PIN that cannot be used. The connection is opened and
/// immediately dropped.
///
/// # Errors
///
/// Returns [`Error::DeviceNotFound`] if no `YubiKey` is present, or
/// [`Error::SmartcardBusy`] if a reader is held by another application.
pub fn ensure_available() -> Result<()> {
    open_yubikey().map(drop)
}

/// Which desktop transport carries the PIV (and HMAC) factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Open the `YubiKey` smartcard directly over PC/SC (and HMAC over HID). The
    /// default; needs no gpg.
    Pcsc,
    /// Route APDUs through gpg-agent's scdaemon, so `ykdf` coexists with gpg
    /// without releasing the card. Unix only.
    Scdaemon,
}

/// Choose the transport, honouring the `YKDF_TRANSPORT` override and otherwise
/// auto-selecting: use PC/SC if the card is reachable, fall back to scdaemon if
/// the card is held by another application (i.e. gpg's scdaemon).
///
/// Running this before prompting for a PIN both fails fast on a missing device
/// and decides the transport up front.
///
/// # Errors
///
/// Returns [`Error::DeviceNotFound`] if no `YubiKey` is present (and no override
/// forces scdaemon), or an error if an explicit override is unsupported.
pub fn select_transport() -> Result<Transport> {
    select_transport_override(None)
}

/// Resolve the transport given an explicit override (e.g. a `--transport` flag).
///
/// Precedence: an explicit `forced` choice, then the `YKDF_TRANSPORT` env var,
/// then auto-detection. A forced choice still validates availability up front, so
/// it fails before the PIN prompt rather than after it.
///
/// # Errors
///
/// Returns [`Error::DeviceNotFound`]/[`Error::SmartcardBusy`] or an scdaemon
/// error if the resolved transport is not usable.
pub fn select_transport_override(forced: Option<Transport>) -> Result<Transport> {
    let chosen = match forced {
        Some(t) => Some(t),
        None => transport_from_env(std::env::var("YKDF_TRANSPORT").ok().as_deref())?,
    };
    match chosen {
        Some(t) => validate_forced(t),
        None => auto_select(),
    }
}

/// Validate that an explicitly chosen transport is usable.
fn validate_forced(transport: Transport) -> Result<Transport> {
    match transport {
        Transport::Pcsc => {
            open_yubikey().map(drop)?;
            Ok(Transport::Pcsc)
        }
        Transport::Scdaemon => ensure_scdaemon(),
    }
}

/// Auto-detect: PC/SC if the card is reachable, scdaemon if it is busy and
/// scdaemon holds it, else the underlying error.
fn auto_select() -> Result<Transport> {
    match open_yubikey() {
        Ok(_) => Ok(Transport::Pcsc),
        Err(Error::SmartcardBusy) => busy_transport(),
        Err(e) => Err(e),
    }
}

/// Parse the `YKDF_TRANSPORT` override. `None`/empty/`auto` mean auto-select.
fn transport_from_env(value: Option<&str>) -> Result<Option<Transport>> {
    match value {
        None | Some("" | "auto") => Ok(None),
        Some("pcsc") => Ok(Some(Transport::Pcsc)),
        Some("scdaemon") => Ok(Some(Transport::Scdaemon)),
        Some(other) => Err(Error::Scd(format!(
            "unknown YKDF_TRANSPORT={other:?} (expected auto|pcsc|scdaemon)"
        ))),
    }
}

/// Decide the transport when the smartcard is busy: route through scdaemon only
/// if it actually holds the card, otherwise surface the busy error rather than
/// misattributing another application's lock to scdaemon.
fn busy_transport() -> Result<Transport> {
    #[cfg(unix)]
    {
        if scd::scdaemon_holds_card() {
            Ok(Transport::Scdaemon)
        } else {
            Err(Error::SmartcardBusy)
        }
    }
    #[cfg(not(unix))]
    {
        Err(Error::SmartcardBusy)
    }
}

/// Validate that the scdaemon transport is usable (gpg-agent reachable and
/// scdaemon can open the card) before committing to it.
fn ensure_scdaemon() -> Result<Transport> {
    #[cfg(unix)]
    {
        if scd::scdaemon_holds_card() {
            Ok(Transport::Scdaemon)
        } else {
            Err(Error::Scd(
                "scdaemon transport requested but gpg-agent/scdaemon could not reach the card \
                 (is gpg installed and the YubiKey inserted?)"
                    .to_owned(),
            ))
        }
    }
    #[cfg(not(unix))]
    {
        Err(Error::Scd(
            "the scdaemon transport is only available on Unix".to_owned(),
        ))
    }
}

/// Derive input key material from a connected `YubiKey` over the chosen transport.
///
/// # Errors
///
/// Returns an error if no `YubiKey` is found, PIN is wrong, the certificate is
/// missing, or the cryptographic operation fails.
pub fn derive_ikm_with(transport: Transport, mode: IkmMode, pin: &[u8]) -> Result<ykdf_core::Ikm> {
    match transport {
        Transport::Pcsc => derive_ikm_pcsc(mode, pin),
        #[cfg(unix)]
        Transport::Scdaemon => scd::derive_ikm(mode, pin),
        #[cfg(not(unix))]
        Transport::Scdaemon => Err(Error::Scd(
            "the scdaemon transport is only available on Unix".to_owned(),
        )),
    }
}

/// Derive input key material from a connected `YubiKey`, auto-selecting the
/// transport (see [`select_transport`]).
///
/// # Errors
///
/// Returns an error if no `YubiKey` is found, PIN is wrong, the
/// certificate is missing, or the cryptographic operation fails.
pub fn derive_ikm(mode: IkmMode, pin: &[u8]) -> Result<ykdf_core::Ikm> {
    derive_ikm_with(select_transport()?, mode, pin)
}

/// Derive IKM over the direct PC/SC + HID transport.
fn derive_ikm_pcsc(mode: IkmMode, pin: &[u8]) -> Result<ykdf_core::Ikm> {
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
    let mut yubikey = open_yubikey()?;

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

#[cfg(test)]
mod tests {
    use super::{Transport, transport_from_env};

    #[test]
    fn env_override_parsing() {
        assert_eq!(transport_from_env(None).unwrap(), None);
        assert_eq!(transport_from_env(Some("")).unwrap(), None);
        assert_eq!(transport_from_env(Some("auto")).unwrap(), None);
        assert_eq!(
            transport_from_env(Some("pcsc")).unwrap(),
            Some(Transport::Pcsc)
        );
        assert_eq!(
            transport_from_env(Some("scdaemon")).unwrap(),
            Some(Transport::Scdaemon)
        );
        assert!(transport_from_env(Some("nonsense")).is_err());
    }
}
