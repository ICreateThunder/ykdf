mod cli;
mod clone;
mod derive;
mod error;
mod format;
mod ikm;
mod init;
mod recipe;
mod term;
mod wg;

use clap::Parser;
use cli::{Cli, Commands};
use error::CliError;

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(e.exit_code());
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    let config = cli.config.as_deref();
    match cli.command {
        Commands::Derive(args) => derive::run_derive(args, config),
        Commands::Pubkey(args) => derive::run_pubkey(args, config),
        Commands::Init(args) => init::run_init(args),
        Commands::Clone(args) => clone::run_clone(&args),
        Commands::Recipe(args) => recipe::run_recipe(args.command, config),
        Commands::Wg(args) => wg::run_wg(args.command, config),
    }
}
