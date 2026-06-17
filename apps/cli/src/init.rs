use std::io::Write;

use zeroize::Zeroizing;

use crate::cli::InitArgs;
use crate::error::CliError;
use ykdf_yubikey::provision::{self, HMAC_SECRET_LEN, PivPolicy};

/// Provision a `YubiKey` for YKDF: generate the slot 9d key on-device and,
/// optionally, program HMAC-SHA1 on OTP slot 2.
pub fn run_init(args: InitArgs) -> Result<(), CliError> {
    // Resolve the management key (factory default unless overridden).
    let mgmt = match &args.mgmt_key {
        Some(hex) => {
            let bytes = decode_hex(hex, 24).ok_or(CliError::InvalidMgmtKey)?;
            ykdf_yubikey::MgmKey::from_bytes(&bytes[..]).map_err(|_| CliError::InvalidMgmtKey)?
        }
        None => ykdf_yubikey::MgmKey::default(),
    };

    // Resolve the HMAC secret up front so bad input fails before touching
    // hardware. The bool records whether we generated it (and must display it).
    let hmac_secret: Option<(Zeroizing<[u8; HMAC_SECRET_LEN]>, bool)> = if args.layered {
        Some(match &args.hmac_secret {
            Some(hex) => {
                let bytes = decode_hex(hex, HMAC_SECRET_LEN).ok_or(CliError::InvalidHmacSecret)?;
                let mut secret = Zeroizing::new([0u8; HMAC_SECRET_LEN]);
                secret.copy_from_slice(&bytes);
                (secret, false)
            }
            None => (
                provision::random_hmac_secret().map_err(CliError::YubiKey)?,
                true,
            ),
        })
    } else {
        None
    };

    let policy = PivPolicy {
        pin_policy: args.pin_policy.into(),
        touch_policy: args.touch_policy.into(),
    };

    // Open the device and guard against clobbering an occupied slot 9d.
    let mut yubikey = provision::open().map_err(CliError::YubiKey)?;
    if provision::slot9d_occupied(&mut yubikey) && !args.force {
        return Err(CliError::SlotOccupied);
    }

    eprintln!("Provisioning PIV slot 9d (on-device P-256, non-extractable).");
    eprintln!(
        "WARNING: an on-device key cannot be backed up. If this YubiKey is lost, \
         keys derived from the PIV factor are unrecoverable. Back up the derived \
         outputs you rely on."
    );

    let pin =
        Zeroizing::new(rpassword::prompt_password("PIV PIN: ").map_err(CliError::PassphraseRead)?);
    eprintln!("Touch your YubiKey to sign the slot 9d certificate...");

    let public = provision::provision_piv(&mut yubikey, pin.as_bytes(), mgmt, policy)
        .map_err(CliError::YubiKey)?;

    // Release the PC/SC handle before the HMAC slot uses USB HID.
    drop(yubikey);

    println!(
        "Provisioned slot 9d. Public key (SEC1): {}",
        hex::encode(&public)
    );

    if let Some((secret, generated)) = hmac_secret {
        if args.force || confirm_slot2_overwrite() {
            provision::program_hmac_slot2(&secret, true).map_err(CliError::YubiKey)?;
            println!("Programmed HMAC-SHA1 on OTP slot 2.");
            if generated {
                // Print the secret to stderr so piping stdout (e.g. to a log)
                // does not capture it alongside the non-secret output.
                eprintln!(
                    "Generated HMAC secret (save this to reprogram another slot/device): {}",
                    hex::encode(&secret[..])
                );
            }
        } else {
            eprintln!("Skipped HMAC slot 2 programming.");
        }
    }

    println!();
    println!(
        "Done. Try: ykdf derive --profile x25519 --purpose example{}",
        if args.layered { " --layered" } else { "" }
    );

    Ok(())
}

/// Decode a hex string, returning the bytes only if they match `expected_len`.
fn decode_hex(input: &str, expected_len: usize) -> Option<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(hex::decode(input).ok()?);
    (bytes.len() == expected_len).then_some(bytes)
}

/// Prompt before overwriting OTP slot 2. Slot 2 configuration cannot be read
/// back, so we cannot auto-detect an existing secret; default to not
/// overwriting on any read failure.
fn confirm_slot2_overwrite() -> bool {
    eprint!(
        "Programming OTP slot 2 overwrites any existing configuration there \
         (OTP or challenge-response). Continue? [y/N] "
    );
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::decode_hex;

    #[test]
    fn decodes_exact_length() {
        let hmac = "00112233445566778899aabbccddeeff00112233"; // 20 bytes
        let bytes = decode_hex(hmac, 20).expect("valid 20-byte hex");
        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[19], 0x33);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(decode_hex("deadbeef", 20).is_none());
        let too_long = "00".repeat(21);
        assert!(decode_hex(&too_long, 20).is_none());
    }

    #[test]
    fn rejects_non_hex() {
        let not_hex = "zz".repeat(20);
        assert!(decode_hex(&not_hex, 20).is_none());
        // Odd number of hex digits is also invalid.
        assert!(decode_hex("abc", 20).is_none());
    }

    #[test]
    fn accepts_management_key_length() {
        let mgmt = "00".repeat(24); // 24 bytes
        assert_eq!(decode_hex(&mgmt, 24).expect("valid 24-byte hex").len(), 24);
    }
}
