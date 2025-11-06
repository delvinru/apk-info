use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::commands::{command_arsc, command_axml, command_extract, command_show};

mod commands;

#[derive(Parser)]
#[command(version, about, arg_required_else_help(true))]
struct Cli {
    #[command(subcommand)]
    commands: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Show basic information about apk file
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
    /// Unpack apk files as zip archive
    Extract {
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        #[arg(short, long, help = "Output folder")]
        output: Option<PathBuf>,
    },
    /// Extract and parse arsc information from given file
    Arsc {
        #[arg(required = true)]
        path: PathBuf,
    },
    /// Read binary `AndroidManifest.xml` and pretty print
    Axml {
        #[arg(required = true)]
        path: PathBuf,
    },
}

fn main() {
    env_logger::init();

    let cli = Cli::parse();

    let result = match &cli.commands {
        Some(Commands::Show { paths, sigs }) => command_show(paths, sigs),
        Some(Commands::Extract { paths, output }) => command_extract(paths, output),
        Some(Commands::Arsc { path }) => command_arsc(path),
        Some(Commands::Axml { path }) => command_axml(path),
        None => Ok(()),
    };

    if let Err(err) = result {
        eprintln!("{:#}", err);
    }
}
