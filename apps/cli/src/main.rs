mod cli;
mod clone;
mod derive;
mod error;
mod format;
mod ikm;
mod init;
mod term;

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
    match cli.command {
        Commands::Derive(args) => derive::run_derive(args),
        Commands::Pubkey(args) => derive::run_pubkey(args),
        Commands::Init(args) => init::run_init(args),
        Commands::Clone(args) => clone::run_clone(&args),
    }
}
