use std::io::Write;
use std::path::Path;

use ykdf_core::{
    Argon2Params, Context, Pipeline, Profile, cascade_passphrase, derive, derive_raw, extract,
    stretch_passphrase,
};
use zeroize::Zeroizing;

use crate::cli::{DeriveArgs, PipelineArg, ProfileArg, PubkeyArgs};
use crate::error::CliError;
use crate::format;
use crate::ikm::IkmSource;

/// Derivation parameters after merging a recipe (if any) with explicit flags.
struct Params {
    profile: Profile,
    pipeline: Pipeline,
    purpose: String,
    index: u32,
    layered: bool,
}

/// Merge an optional named recipe with explicit flags, applying SSH-style
/// precedence: explicit flag > recipe field > `[defaults]` > profile default.
///
/// `--layered` is additive (a flag or a recipe can turn it on; there is no CLI
/// way to force it off for a recipe that sets it).
fn resolve_params(
    recipe: Option<&str>,
    config: Option<&Path>,
    profile: Option<ProfileArg>,
    purpose: Option<String>,
    pipeline: Option<PipelineArg>,
    index: Option<u32>,
    layered_flag: bool,
) -> Result<Params, CliError> {
    let recipe = match recipe {
        Some(name) => Some(ykdf_config::Catalogue::load(config)?.resolve(name)?),
        None => None,
    };

    let profile: Profile = match profile {
        Some(p) => p.into(),
        None => recipe
            .as_ref()
            .map(|r| r.profile)
            .ok_or(CliError::MissingProfile)?,
    };
    let purpose: String = match purpose {
        Some(p) => p,
        None => recipe
            .as_ref()
            .map(|r| r.purpose.clone())
            .ok_or(CliError::MissingPurpose)?,
    };
    let pipeline: Pipeline = pipeline
        .map(Into::into)
        .or_else(|| recipe.as_ref().and_then(|r| r.pipeline))
        .unwrap_or_else(|| profile.default_pipeline());
    let index = index
        .or_else(|| recipe.as_ref().map(|r| r.index))
        .unwrap_or(0);
    let layered = layered_flag || recipe.as_ref().is_some_and(|r| r.layered);

    Ok(Params {
        profile,
        pipeline,
        purpose,
        index,
        layered,
    })
}

pub fn run_derive(args: DeriveArgs, config: Option<&Path>) -> Result<(), CliError> {
    let params = resolve_params(
        args.recipe.as_deref(),
        config,
        args.profile,
        args.purpose,
        args.pipeline,
        args.index,
        args.layered,
    )?;

    if args.length.is_some() && params.profile != Profile::Raw {
        return Err(CliError::LengthRequiresRaw);
    }
    if params.profile == Profile::Raw && args.length.is_none() {
        return Err(CliError::RawRequiresLength);
    }

    let context = build_context(
        params.profile,
        params.pipeline,
        &params.purpose,
        params.index,
    )?;
    let mut master_key = extract_ikm(
        args.ikm_file.as_ref(),
        params.layered,
        args.transport.to_override(),
        params.pipeline,
    )?;

    if args.passphrase {
        master_key = apply_passphrase(&master_key, params.pipeline)?;
    }

    let output = if let Some(len) = args.length {
        derive_raw(&master_key, &context, len)?
    } else {
        derive(&master_key, &context)?
    };

    let formatted = Zeroizing::new(format::format_output(
        &output,
        params.profile,
        args.format.as_ref(),
    )?);
    std::io::stdout()
        .write_all(&formatted)
        .map_err(CliError::OutputWrite)
}

pub fn run_pubkey(args: PubkeyArgs, config: Option<&Path>) -> Result<(), CliError> {
    let params = resolve_params(
        args.recipe.as_deref(),
        config,
        args.profile,
        args.purpose,
        args.pipeline,
        args.index,
        args.layered,
    )?;

    let context = build_context(
        params.profile,
        params.pipeline,
        &params.purpose,
        params.index,
    )?;
    let mut master_key = extract_ikm(
        args.ikm_file.as_ref(),
        params.layered,
        args.transport.to_override(),
        params.pipeline,
    )?;

    if args.passphrase {
        master_key = apply_passphrase(&master_key, params.pipeline)?;
    }

    let output = derive(&master_key, &context)?;
    let formatted = Zeroizing::new(format::format_pubkey(&output, params.profile)?);
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
    layered: bool,
    transport: Option<ykdf_yubikey::Transport>,
    pipeline: Pipeline,
) -> Result<ykdf_core::MasterKey, CliError> {
    let source = match ikm_file {
        Some(p) => IkmSource::File(p.clone()),
        None => IkmSource::YubiKey { layered, transport },
    };
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
    cascade_passphrase(master_key, &stretched, pipeline).map_err(CliError::Core)
}
