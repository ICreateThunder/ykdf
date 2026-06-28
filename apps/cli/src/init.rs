use std::io::{Read, Write};
use std::path::Path;

use zeroize::{Zeroize, Zeroizing};

use crate::cli::InitArgs;
use crate::error::CliError;
use ykdf_yubikey::provision::{self, HMAC_SECRET_LEN, PivPolicy};

/// How the slot 9d key is created.
enum PivMode {
    /// Generate on-device (non-extractable, no backup). Default.
    OnDevice,
    /// Generate on the host and display once (importable to a backup device).
    Exportable,
    /// Import a host-supplied scalar (e.g. to provision a backup device).
    Import(Zeroizing<[u8; 32]>),
}

/// Provision a `YubiKey` for YKDF: generate (or import) the slot 9d key and,
/// optionally, program HMAC-SHA1 on OTP slot 2.
pub fn run_init(args: InitArgs) -> Result<(), CliError> {
    // At most one secret may come from stdin: it can only be read once.
    let stdin_sources = [
        &args.import_file,
        &args.hmac_secret_file,
        &args.mgmt_key_file,
    ]
    .into_iter()
    .filter(|p| p.as_deref() == Some(Path::new("-")))
    .count();
    if stdin_sources > 1 {
        return Err(CliError::MultipleStdinSecrets);
    }

    // Resolve all inputs up front so bad arguments fail before touching hardware.
    let mgm = resolve_mgm_source(&args)?;
    let hmac_secret = resolve_hmac_secret(&args)?;
    let piv_mode = resolve_piv_mode(&args)?;

    let policy = PivPolicy {
        pin_policy: args.pin_policy.into(),
        touch_policy: args.touch_policy.into(),
    };

    // Open the device and guard against clobbering an occupied slot 9d.
    let mut yubikey = provision::open().map_err(CliError::YubiKey)?;
    if provision::slot9d_occupied(&mut yubikey) && !args.force {
        return Err(CliError::SlotOccupied);
    }

    match &piv_mode {
        PivMode::OnDevice => {
            eprintln!("Provisioning PIV slot 9d (on-device P-256, non-extractable).");
            eprintln!(
                "WARNING: an on-device key cannot be backed up. If this YubiKey is lost, \
                 keys derived from the PIV factor are unrecoverable. Back up the derived \
                 outputs you rely on."
            );
        }
        PivMode::Exportable => {
            eprintln!("Provisioning PIV slot 9d (host-generated P-256, EXPORTABLE for backup).");
        }
        PivMode::Import(_) => {
            eprintln!("Provisioning PIV slot 9d (importing the supplied P-256 key).");
        }
    }

    let pin =
        Zeroizing::new(rpassword::prompt_password("PIV PIN: ").map_err(CliError::PassphraseRead)?);
    eprintln!("Touch your YubiKey to sign the slot 9d certificate...");

    // `exported` carries the host-generated scalar in --exportable mode so it
    // can be displayed once after a successful import.
    let (public, exported) = match piv_mode {
        PivMode::OnDevice => (
            provision::provision_piv(&mut yubikey, pin.as_bytes(), mgm, policy)
                .map_err(CliError::YubiKey)?,
            None,
        ),
        PivMode::Exportable => {
            let scalar = provision::generate_p256_scalar();
            let public =
                provision::provision_piv_import(&mut yubikey, pin.as_bytes(), mgm, policy, &scalar)
                    .map_err(CliError::YubiKey)?;
            (public, Some(scalar))
        }
        PivMode::Import(scalar) => (
            provision::provision_piv_import(&mut yubikey, pin.as_bytes(), mgm, policy, &scalar)
                .map_err(CliError::YubiKey)?,
            None,
        ),
    };

    // Release the PC/SC handle before the HMAC slot uses USB HID.
    drop(yubikey);

    println!(
        "Provisioned slot 9d. Public key (SEC1): {}",
        hex::encode(&public)
    );

    if let Some(scalar) = exported {
        // Display the private key once, on stderr, so piping stdout does not
        // capture it. This is the only copy.
        eprintln!();
        eprintln!(
            "SAVE THIS VALUE. It is the slot 9d private key and the only copy; the \
             YubiKey will not export it again. Without it you cannot provision a backup \
             device or recover this key (the certificate can be regenerated from it, the \
             key cannot)."
        );
        let mut scalar_hex = hex::encode(&scalar[..]);
        eprintln!("slot 9d private key (hex): {scalar_hex}");
        scalar_hex.zeroize();
    }

    if let Some((secret, generated)) = hmac_secret {
        if args.force || confirm_slot2_overwrite() {
            provision::program_hmac_slot2(&secret, true).map_err(CliError::YubiKey)?;
            println!("Programmed HMAC-SHA1 on OTP slot 2.");
            if generated {
                // Print the secret to stderr so piping stdout (e.g. to a log)
                // does not capture it alongside the non-secret output.
                let mut secret_hex = hex::encode(&secret[..]);
                eprintln!(
                    "Generated HMAC secret (save this to reprogram another slot/device): {secret_hex}"
                );
                secret_hex.zeroize();
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

/// Resolve where the PIV management key comes from. `--mgmt-key-file` reads an
/// explicit hex key from a path; `--mgmt-key` accepts the keywords `protected`
/// or `derived` (read the key from the device) or a 48-hex explicit key, or is
/// absent for the factory default.
fn resolve_mgm_source(args: &InitArgs) -> Result<provision::MgmKeySource, CliError> {
    use provision::MgmKeySource;
    if let Some(path) = &args.mgmt_key_file {
        let hex = read_secret_hex(path)?;
        return explicit_mgm_key(&hex).map(MgmKeySource::Explicit);
    }
    match args.mgmt_key.as_deref() {
        None => Ok(MgmKeySource::Default),
        Some("protected") => Ok(MgmKeySource::Protected),
        Some("derived") => Ok(MgmKeySource::Derived),
        Some(hex) => {
            warn_process_table("--mgmt-key <hex>", "--mgmt-key-file");
            explicit_mgm_key(hex).map(MgmKeySource::Explicit)
        }
    }
}

/// Build an explicit management key from a 48-hex string.
pub(crate) fn explicit_mgm_key(hex: &str) -> Result<ykdf_yubikey::MgmKey, CliError> {
    let bytes = decode_hex(hex, 24).ok_or(CliError::InvalidMgmtKey)?;
    ykdf_yubikey::MgmKey::from_bytes(&bytes[..]).map_err(|_| CliError::InvalidMgmtKey)
}

/// Resolve the HMAC slot 2 secret for `--layered`. The bool records whether we
/// generated it (and so must display it once).
#[allow(clippy::type_complexity)]
fn resolve_hmac_secret(
    args: &InitArgs,
) -> Result<Option<(Zeroizing<[u8; HMAC_SECRET_LEN]>, bool)>, CliError> {
    if !args.layered {
        return Ok(None);
    }
    let secret = if let Some(path) = &args.hmac_secret_file {
        let hex = read_secret_hex(path)?;
        (fixed_hmac_secret(&hex)?, false)
    } else if let Some(hex) = &args.hmac_secret {
        warn_process_table("--hmac-secret", "--hmac-secret-file");
        (fixed_hmac_secret(hex)?, false)
    } else {
        (
            provision::random_hmac_secret().map_err(CliError::YubiKey)?,
            true,
        )
    };
    Ok(Some(secret))
}

/// Parse a 40-hex HMAC secret into the fixed-size buffer.
pub(crate) fn fixed_hmac_secret(hex: &str) -> Result<Zeroizing<[u8; HMAC_SECRET_LEN]>, CliError> {
    let bytes = decode_hex(hex, HMAC_SECRET_LEN).ok_or(CliError::InvalidHmacSecret)?;
    let mut secret = Zeroizing::new([0u8; HMAC_SECRET_LEN]);
    secret.copy_from_slice(&bytes);
    Ok(secret)
}

/// Resolve how the slot 9d key is created from the CLI flags.
fn resolve_piv_mode(args: &InitArgs) -> Result<PivMode, CliError> {
    if let Some(path) = &args.import_file {
        let hex = read_secret_hex(path)?;
        return Ok(PivMode::Import(import_scalar(&hex)?));
    }
    match &args.import {
        Some(hex) => {
            warn_process_table("--import", "--import-file");
            Ok(PivMode::Import(import_scalar(hex)?))
        }
        None if args.exportable => Ok(PivMode::Exportable),
        None => Ok(PivMode::OnDevice),
    }
}

/// Parse a 64-hex P-256 scalar into the fixed-size buffer.
pub(crate) fn import_scalar(hex: &str) -> Result<Zeroizing<[u8; 32]>, CliError> {
    let bytes = decode_hex(hex, 32).ok_or(CliError::InvalidImportKey)?;
    let mut scalar = Zeroizing::new([0u8; 32]);
    scalar.copy_from_slice(&bytes);
    Ok(scalar)
}

/// Read a secret hex string from a file path, or from stdin when the path is
/// `-`. Surrounding whitespace (e.g. a trailing newline) is trimmed. Keeping the
/// value off the command line keeps it out of the process table; a path of
/// `/dev/fd/N` reads a file descriptor.
pub(crate) fn read_secret_hex(path: &Path) -> Result<Zeroizing<String>, CliError> {
    let read_err = |source| CliError::SecretFileRead {
        path: path.to_path_buf(),
        source,
    };
    let bytes = if path == Path::new("-") {
        let mut buf = Zeroizing::new(Vec::new());
        std::io::stdin().read_to_end(&mut buf).map_err(read_err)?;
        buf
    } else {
        Zeroizing::new(std::fs::read(path).map_err(read_err)?)
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        read_err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "secret file is not valid UTF-8",
        ))
    })?;
    Ok(Zeroizing::new(text.trim().to_string()))
}

/// Warn that a secret passed inline is visible in the process table.
pub(crate) fn warn_process_table(flag: &str, file_flag: &str) {
    eprintln!(
        "warning: {flag} exposes the secret in the process table (visible to `ps`); \
         prefer {file_flag} <PATH> (or `-` for stdin)."
    );
}

/// Decode a hex string, returning the bytes only if they match `expected_len`.
pub(crate) fn decode_hex(input: &str, expected_len: usize) -> Option<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(hex::decode(input).ok()?);
    (bytes.len() == expected_len).then_some(bytes)
}

/// Prompt before overwriting OTP slot 2. Slot 2 configuration cannot be read
/// back, so we cannot auto-detect an existing secret; default to not
/// overwriting on any read failure.
pub(crate) fn confirm_slot2_overwrite() -> bool {
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
    use super::{decode_hex, read_secret_hex};
    use std::path::PathBuf;

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

    #[test]
    fn accepts_import_scalar_length() {
        let scalar = "11".repeat(32); // 32 bytes
        assert_eq!(
            decode_hex(&scalar, 32).expect("valid 32-byte hex").len(),
            32
        );
        // A 31- or 33-byte value is rejected.
        assert!(decode_hex(&"11".repeat(31), 32).is_none());
        assert!(decode_hex(&"11".repeat(33), 32).is_none());
    }

    /// A unique scratch path under the temp dir for a single test.
    fn scratch_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("ykdf-init-test-{}-{tag}", std::process::id()));
        p
    }

    #[test]
    fn reads_and_trims_secret_file() {
        let path = scratch_path("hmac");
        // A trailing newline (as a `printf`/editor would leave) must be trimmed
        // so the value still decodes to the exact byte length.
        std::fs::write(&path, format!("{}\n", "ab".repeat(20))).expect("write temp");
        let hex = read_secret_hex(&path).expect("read secret");
        assert_eq!(&*hex, &"ab".repeat(20));
        assert_eq!(decode_hex(&hex, 20).expect("valid").len(), 20);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_secret_file_errors() {
        let path = scratch_path("missing");
        let _ = std::fs::remove_file(&path);
        assert!(read_secret_hex(&path).is_err());
    }
}
