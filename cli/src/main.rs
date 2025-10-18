use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::commands::show::command_show;

mod commands;

#[derive(Parser)]
#[command(version, about, arg_required_else_help(true))]
struct Cli {
    #[command(subcommand)]
    commands: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Show {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
}

fn main() {
    env_logger::init();

    let cli = Cli::parse();

    let result = match &cli.commands {
        Some(Commands::Show { paths }) => command_show(paths),
        None => Ok(()),
    };

    if let Err(err) = result {
        eprintln!("{:#}", err);
    }
}
