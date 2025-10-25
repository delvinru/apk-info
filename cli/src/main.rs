use std::path::PathBuf;

use clap::{Parser, Subcommand};

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

        #[arg(
            short,
            long,
            default_value_t = false,
            help = "show information about signatures"
        )]
        sigs: bool,
    },
}

fn main() {
    env_logger::init();

    let cli = Cli::parse();

    let result = match &cli.commands {
        Some(Commands::Show { paths, sigs }) => command_show(paths, sigs),
        None => Ok(()),
    };

    if let Err(err) = result {
        eprintln!("{:#}", err);
    }
}
