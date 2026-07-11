use std::io::{Read, Write};
use std::path::Path;

use ykdf_core::Profile;

use crate::cli::{HashArg, SignArgs, VerifyArgs};
use crate::error::CliError;

/// Profiles that `sign` can use: ed25519 (OpenSSH SSHSIG) and the ML-DSA
/// profiles (`ykdf-sig:v1`).
fn is_signing_profile(profile: Profile) -> bool {
    matches!(
        profile,
        Profile::Ed25519 | Profile::MlDsa44 | Profile::MlDsa65 | Profile::MlDsa87
    )
}

fn is_mldsa(profile: Profile) -> bool {
    matches!(
        profile,
        Profile::MlDsa44 | Profile::MlDsa65 | Profile::MlDsa87
    )
}

pub fn run_sign(args: SignArgs, config: Option<&Path>) -> Result<(), CliError> {
    let params = crate::derive::resolve_params(
        args.recipe.as_deref(),
        config,
        args.profile,
        args.purpose,
        args.pipeline,
        args.index,
        args.layered,
    )?;

    if !is_signing_profile(params.profile) {
        return Err(CliError::SignProfileMismatch {
            profile: params.profile.as_str(),
        });
    }
    // ML-DSA (ykdf-sig:v1) fixes SHA-512; --hash only selects the SSHSIG digest.
    if is_mldsa(params.profile) && matches!(args.hash, HashArg::Sha256) {
        return Err(CliError::MlDsaHashFixed);
    }

    // Read the message before touching the YubiKey, so a bad path fails fast.
    let message = read_input(args.input.as_deref())?;

    let context = crate::derive::build_context(
        params.profile,
        params.pipeline,
        &params.purpose,
        params.index,
    )?;
    let mut master_key = crate::derive::extract_ikm(
        args.ikm_file.as_ref(),
        params.layered,
        args.transport.to_override(),
        params.pipeline,
    )?;
    if args.passphrase {
        master_key = crate::derive::apply_passphrase(&master_key, params.pipeline)?;
    }

    let output = ykdf_core::derive(&master_key, &context)?;
    let signature = ykdf_core::sign_message(
        &output,
        params.profile,
        &args.namespace,
        args.hash.into(),
        &message,
    )?;

    write_output(args.output.as_deref(), signature.as_bytes())
}

pub fn run_verify(args: &VerifyArgs) -> Result<(), CliError> {
    let public_key = read_public_key(&args.public_key)?;
    let signature = std::fs::read_to_string(&args.signature).map_err(CliError::InputRead)?;
    let message = read_input(args.input.as_deref())?;

    ykdf_core::verify_message(&signature, &public_key, &args.namespace, &message)?;
    eprintln!("Good signature");
    Ok(())
}

/// Read an input from a file, or from stdin when the path is absent or `-`.
fn read_input(path: Option<&Path>) -> Result<Vec<u8>, CliError> {
    let from_stdin = match path {
        None => true,
        Some(p) => p.as_os_str() == "-",
    };
    if from_stdin {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(CliError::InputRead)?;
        Ok(buf)
    } else {
        std::fs::read(path.expect("checked non-stdin path")).map_err(CliError::InputRead)
    }
}

/// A public key given literally, or read from a file when prefixed with `@`.
fn read_public_key(value: &str) -> Result<String, CliError> {
    if let Some(path) = value.strip_prefix('@') {
        std::fs::read_to_string(path).map_err(CliError::InputRead)
    } else {
        Ok(value.to_owned())
    }
}

/// Write the signature to a file, or to stdout when the path is absent.
fn write_output(path: Option<&Path>, data: &[u8]) -> Result<(), CliError> {
    match path {
        None => std::io::stdout()
            .write_all(data)
            .map_err(CliError::OutputWrite),
        Some(p) => std::fs::write(p, data).map_err(|source| CliError::OutputFile {
            path: p.to_path_buf(),
            source,
        }),
    }
}
