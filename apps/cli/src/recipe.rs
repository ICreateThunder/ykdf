use std::path::Path;

use ykdf_config::Catalogue;

use crate::cli::RecipeCommand;
use crate::error::CliError;

pub fn run_recipe(command: RecipeCommand, config: Option<&Path>) -> Result<(), CliError> {
    let catalogue = Catalogue::load(config)?;
    match command {
        RecipeCommand::List => {
            list(&catalogue);
            Ok(())
        }
        RecipeCommand::Show { name } => show(&catalogue, &name),
    }
}

/// Print one recipe per line as `name<TAB>description`, so the output is easy to
/// eyeball and to pipe into other tools.
fn list(catalogue: &Catalogue) {
    let mut any = false;
    for (name, description) in catalogue.recipes() {
        any = true;
        match description {
            Some(desc) => println!("{name}\t{desc}"),
            None => println!("{name}"),
        }
    }
    if !any {
        eprintln!("no recipes configured");
    }
}

/// Print a recipe's fully resolved parameters, so a user can audit exactly what
/// a derivation would run before touching a `YubiKey`. The pipeline is shown
/// resolved to the concrete one that would be used (the profile default when the
/// recipe leaves it unset).
fn show(catalogue: &Catalogue, name: &str) -> Result<(), CliError> {
    let recipe = catalogue.resolve(name)?;
    let pipeline = recipe
        .pipeline
        .unwrap_or_else(|| recipe.profile.default_pipeline());
    println!("profile   {}", recipe.profile.as_str());
    println!("purpose   {}", recipe.purpose);
    println!("pipeline  {}", pipeline.as_str());
    println!("index     {}", recipe.index);
    println!("layered   {}", recipe.layered);
    if let Some(description) = &recipe.description {
        println!("about     {description}");
    }
    if let Some(wg) = &recipe.wg {
        show_wg(wg);
    }
    Ok(())
}

/// Print the resolved `[wg]` extension, so a user can audit the `WireGuard`
/// config a recipe would assemble before deriving.
fn show_wg(wg: &ykdf_config::WgConfig) {
    if !wg.address.is_empty() {
        println!("wg.address      {}", wg.address.join(", "));
    }
    if let Some(port) = wg.listen_port {
        println!("wg.listen-port  {port}");
    }
    if !wg.dns.is_empty() {
        println!("wg.dns          {}", wg.dns.join(", "));
    }
    if let Some(mtu) = wg.mtu {
        println!("wg.mtu          {mtu}");
    }
    for (i, peer) in wg.peers.iter().enumerate() {
        println!("wg.peer[{i}].public-key   {}", peer.public_key);
        if let Some(endpoint) = &peer.endpoint {
            println!("wg.peer[{i}].endpoint     {endpoint}");
        }
        if !peer.allowed_ips.is_empty() {
            println!("wg.peer[{i}].allowed-ips  {}", peer.allowed_ips.join(", "));
        }
        if let Some(keepalive) = peer.keepalive {
            println!("wg.peer[{i}].keepalive    {keepalive}");
        }
    }
}
