use std::io::Write;

use ykdf_core::{
    Argon2Params, Context, Pipeline, Profile, cascade, derive, derive_raw, extract,
    stretch_passphrase,
};
use zeroize::Zeroizing;

use crate::cli::{DeriveArgs, PubkeyArgs};
use crate::error::CliError;
use crate::format;
use crate::ikm::IkmSource;

pub fn run_derive(args: DeriveArgs) -> Result<(), CliError> {
    let profile: Profile = args.profile.into();
    let pipeline: Pipeline = args
        .pipeline
        .map_or_else(|| profile.default_pipeline(), Into::into);

    if args.layered {
        return Err(CliError::LayeredNotSupported);
    }
    if args.length.is_some() && profile != Profile::Raw {
        return Err(CliError::LengthRequiresRaw);
    }
    if profile == Profile::Raw && args.length.is_none() {
        return Err(CliError::RawRequiresLength);
    }

    let context = build_context(profile, pipeline, &args.purpose, args.index)?;
    let mut master_key = extract_ikm(args.ikm_file.as_ref(), pipeline)?;

    if args.passphrase {
        master_key = apply_passphrase(&master_key, pipeline)?;
    }

    let output = if let Some(len) = args.length {
        derive_raw(&master_key, &context, len)?
    } else {
        derive(&master_key, &context)?
    };

    let formatted = Zeroizing::new(format::format_output(
        &output,
        profile,
        args.format.as_ref(),
    )?);
    std::io::stdout()
        .write_all(&formatted)
        .map_err(CliError::OutputWrite)
}

pub fn run_pubkey(args: PubkeyArgs) -> Result<(), CliError> {
    let profile: Profile = args.profile.into();
    let pipeline: Pipeline = args
        .pipeline
        .map_or_else(|| profile.default_pipeline(), Into::into);

    if args.layered {
        return Err(CliError::LayeredNotSupported);
    }

    let context = build_context(profile, pipeline, &args.purpose, args.index)?;
    let mut master_key = extract_ikm(args.ikm_file.as_ref(), pipeline)?;

    if args.passphrase {
        master_key = apply_passphrase(&master_key, pipeline)?;
    }

    let output = derive(&master_key, &context)?;
    let formatted = Zeroizing::new(format::format_pubkey(&output, profile)?);
    std::io::stdout()
        .write_all(&formatted)
        .map_err(CliError::OutputWrite)
}

fn build_context(
    profile: Profile,
    pipeline: Pipeline,
    purpose: &str,
    index: u32,
) -> Result<Context, CliError> {
    Context::with_pipeline(profile, pipeline, purpose, index).map_err(CliError::Core)
}

fn extract_ikm(
    ikm_file: Option<&std::path::PathBuf>,
    pipeline: Pipeline,
) -> Result<ykdf_core::MasterKey, CliError> {
    let source = ikm_file
        .map(|p| IkmSource::File(p.clone()))
        .ok_or(CliError::NoIkmSource)?;
    let ikm = source.load()?;
    extract(&ikm, pipeline).map_err(CliError::Core)
}

fn apply_passphrase(
    master_key: &ykdf_core::MasterKey,
    pipeline: Pipeline,
) -> Result<ykdf_core::MasterKey, CliError> {
    let pass = Zeroizing::new(
        rpassword::prompt_password("Passphrase: ").map_err(CliError::PassphraseRead)?,
    );
    let stretched = stretch_passphrase(pass.as_bytes(), &Argon2Params::default())?;
    cascade(master_key, stretched.as_bytes(), pipeline).map_err(CliError::Core)
}
