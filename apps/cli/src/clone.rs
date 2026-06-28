//! `ykdf clone`: provision several `YubiKeys` from a single root in one
//! swap-session.
//!
//! The root secret (the slot 9d P-256 scalar, and for `--layered` the slot 2
//! HMAC secret) is generated or read once, held in host RAM for the whole
//! session, pushed to each device in turn, and wiped on exit. Unlike
//! `init --exportable`, the secret is never displayed, clipboarded, or written
//! (unless `--show` is given): it exists only between generation and the final
//! `Zeroizing` drop. One physical port is enough: insert a device, provision,
//! swap, repeat.

use std::io::{self, Write};
use std::path::Path;

use zeroize::{Zeroize, Zeroizing};

use crate::cli::CloneArgs;
use crate::error::CliError;
use crate::init::{
    confirm_slot2_overwrite, explicit_mgm_key, fixed_hmac_secret, import_scalar, read_secret_hex,
    warn_process_table,
};
use ykdf_yubikey::provision::{self, HMAC_SECRET_LEN, MgmKeySource, PivPolicy};

/// Run the clone swap-session: build the root in RAM, then loop over devices.
pub fn run_clone(args: &CloneArgs) -> Result<(), CliError> {
    reject_stdin_files(args)?;

    // Build the root secret once. It now lives only in these `Zeroizing` buffers
    // until they drop at the end of this function.
    let scalar = match &args.import_file {
        Some(path) => import_scalar(&read_secret_hex(path)?)?,
        None => provision::generate_p256_scalar(),
    };
    let hmac = if args.layered {
        Some(match &args.hmac_secret_file {
            Some(path) => fixed_hmac_secret(&read_secret_hex(path)?)?,
            None => provision::random_hmac_secret().map_err(CliError::YubiKey)?,
        })
    } else {
        None
    };

    let policy = PivPolicy {
        pin_policy: args.pin_policy.clone().into(),
        touch_policy: args.touch_policy.clone().into(),
    };

    // Warn once (not per device) if the management key was passed inline.
    if matches!(args.mgmt_key.as_deref(), Some(k) if k != "protected" && k != "derived") {
        warn_process_table("--mgmt-key <hex>", "--mgmt-key-file");
    }

    eprintln!(
        "Cloning one root to multiple YubiKeys. The root secret stays in host RAM \
         and is wiped when this command exits.{}",
        if args.layered {
            " Each device also gets the same OTP slot 2 HMAC secret."
        } else {
            ""
        }
    );
    eprintln!("Insert one device at a time; each is prompted for its own PIN and touch.");

    let mut publics: Vec<Vec<u8>> = Vec::new();
    loop {
        let prompt = if publics.is_empty() {
            "Insert the first device, then press Enter (or 'q' to abort): ".to_string()
        } else {
            format!(
                "Cloned {} device(s). Insert the next device and press Enter, or 'q' to finish: ",
                publics.len()
            )
        };
        if !prompt_continue(&prompt) {
            break;
        }

        match clone_one_device(args, &scalar, hmac.as_deref(), policy) {
            Ok(public) => {
                println!(
                    "Device #{} cloned. slot 9d public key (SEC1): {}",
                    publics.len() + 1,
                    hex::encode(&public)
                );
                publics.push(public);
            }
            Err(e) => {
                crate::term::warn(&format!("device #{} failed: {e}", publics.len() + 1));
                eprintln!("Not counted. Fix the issue and retry, or 'q' to finish.");
            }
        }
    }

    report_outcome(args, &publics, &scalar, hmac.as_deref());
    Ok(())
}

/// Provision the single device currently inserted. Returns its slot 9d public
/// key (SEC1) so the caller can confirm every clone matches.
fn clone_one_device(
    args: &CloneArgs,
    scalar: &[u8; 32],
    hmac: Option<&[u8; HMAC_SECRET_LEN]>,
    policy: PivPolicy,
) -> Result<Vec<u8>, CliError> {
    let mut yubikey = provision::open().map_err(CliError::YubiKey)?;
    if provision::slot9d_occupied(&mut yubikey) && !args.force && !confirm_overwrite_slot9d() {
        return Err(CliError::SlotOccupied);
    }

    // Resolve the management key per device: `protected`/`derived` read PIN-gated
    // data from the device currently inserted, so each device resolves its own.
    let mgm = resolve_mgm(args)?;
    let pin =
        Zeroizing::new(rpassword::prompt_password("PIV PIN: ").map_err(CliError::PassphraseRead)?);
    eprintln!("Touch your YubiKey to sign the slot 9d certificate...");
    let public = provision::provision_piv_import(&mut yubikey, pin.as_bytes(), mgm, policy, scalar)
        .map_err(CliError::YubiKey)?;

    // Release the PC/SC handle before the HMAC slot uses USB HID.
    drop(yubikey);

    if let Some(secret) = hmac {
        if args.force || confirm_slot2_overwrite() {
            provision::program_hmac_slot2(secret, true).map_err(CliError::YubiKey)?;
            eprintln!("Programmed HMAC-SHA1 on OTP slot 2.");
        } else {
            eprintln!("Skipped HMAC slot 2 programming for this device.");
        }
    }

    Ok(public)
}

/// Print the session summary and, with `--show`, the root secret.
fn report_outcome(
    args: &CloneArgs,
    publics: &[Vec<u8>],
    scalar: &[u8; 32],
    hmac: Option<&[u8; HMAC_SECRET_LEN]>,
) {
    if publics.is_empty() {
        eprintln!("No devices were cloned.");
        return;
    }

    println!();
    if publics.iter().all(|p| p == &publics[0]) {
        println!(
            "Cloned the root to {} device(s). All share slot 9d public key {} and \
             derive byte-identical keys.",
            publics.len(),
            hex::encode(&publics[0])
        );
    } else {
        // Should be impossible: every device imported the same scalar.
        crate::term::warn(
            "WARNING: the cloned public keys differ across devices, so the import did \
             not reproduce. Do NOT rely on these as interchangeable backups; \
             investigate before use.",
        );
    }

    if args.show {
        eprintln!();
        eprintln!(
            "--show requested: the root secret is printed below. It is the value just \
             written to every device; treat it as the only persistent copy."
        );
        let mut scalar_hex = hex::encode(&scalar[..]);
        eprintln!("slot 9d private key (hex): {scalar_hex}");
        scalar_hex.zeroize();
        if let Some(secret) = hmac {
            let mut hmac_hex = hex::encode(&secret[..]);
            eprintln!("OTP slot 2 HMAC secret (hex): {hmac_hex}");
            hmac_hex.zeroize();
        }
    }
}

/// Resolve the PIV management key source from the clone flags. Called per device
/// so `protected`/`derived` read from the device currently inserted.
fn resolve_mgm(args: &CloneArgs) -> Result<MgmKeySource, CliError> {
    if let Some(path) = &args.mgmt_key_file {
        let hex = read_secret_hex(path)?;
        return explicit_mgm_key(&hex).map(MgmKeySource::Explicit);
    }
    match args.mgmt_key.as_deref() {
        None => Ok(MgmKeySource::Auto),
        Some("protected") => Ok(MgmKeySource::Protected),
        Some("derived") => Ok(MgmKeySource::Derived),
        Some(hex) => explicit_mgm_key(hex).map(MgmKeySource::Explicit),
    }
}

/// Reject `-` (stdin) for any secret file: clone reads its device prompts from
/// stdin, so a secret cannot also come from there.
fn reject_stdin_files(args: &CloneArgs) -> Result<(), CliError> {
    let files = [
        ("--import-file", &args.import_file),
        ("--hmac-secret-file", &args.hmac_secret_file),
        ("--mgmt-key-file", &args.mgmt_key_file),
    ];
    for (flag, path) in files {
        if path.as_deref() == Some(Path::new("-")) {
            return Err(CliError::CloneStdinUnsupported { flag });
        }
    }
    Ok(())
}

/// Prompt before overwriting an occupied slot 9d on a device. Destructive, so
/// require a deliberate `YES`; defaults to no.
fn confirm_overwrite_slot9d() -> bool {
    crate::term::confirm_destructive(
        "This device's slot 9d already holds a key; cloning overwrites it (the \
         existing key is lost). Type YES to continue: ",
    )
}

/// Print a prompt and read one line. Returns `false` on `q`/`quit` or EOF
/// (finish the session), `true` on Enter or any other input (continue).
fn prompt_continue(prompt: &str) -> bool {
    eprint!("{prompt}");
    let _ = io::stderr().flush();
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(0) | Err(_) => false, // EOF or read error: finish the session
        Ok(_) => !matches!(input.trim().to_ascii_lowercase().as_str(), "q" | "quit"),
    }
}

#[cfg(test)]
mod tests {
    use super::reject_stdin_files;
    use crate::cli::{CloneArgs, PinPolicyArg, TouchPolicyArg};
    use crate::error::CliError;
    use std::path::PathBuf;

    fn base_args() -> CloneArgs {
        CloneArgs {
            layered: false,
            import_file: None,
            hmac_secret_file: None,
            show: false,
            mgmt_key: None,
            mgmt_key_file: None,
            force: false,
            pin_policy: PinPolicyArg::Once,
            touch_policy: TouchPolicyArg::Always,
        }
    }

    #[test]
    fn allows_real_paths_and_no_files() {
        assert!(reject_stdin_files(&base_args()).is_ok());
        let mut args = base_args();
        args.import_file = Some(PathBuf::from("scalar.hex"));
        args.mgmt_key_file = Some(PathBuf::from("mgmt.hex"));
        assert!(reject_stdin_files(&args).is_ok());
    }

    #[test]
    fn rejects_stdin_for_each_secret_file() {
        for set in [
            |a: &mut CloneArgs| a.import_file = Some(PathBuf::from("-")),
            |a: &mut CloneArgs| a.hmac_secret_file = Some(PathBuf::from("-")),
            |a: &mut CloneArgs| a.mgmt_key_file = Some(PathBuf::from("-")),
        ] {
            let mut args = base_args();
            set(&mut args);
            assert!(matches!(
                reject_stdin_files(&args),
                Err(CliError::CloneStdinUnsupported { .. })
            ));
        }
    }
}
