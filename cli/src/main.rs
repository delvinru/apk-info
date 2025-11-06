use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::commands::{command_axml, command_extract, command_show};

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
        /// One or more paths to APK files to inspect
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Show information about signatures
        #[arg(
            short,
            long,
            default_value_t = false,
            help = "Show information about signatures"
        )]
        sigs: bool,
    },
    /// Unpack apk files as zip archive
    #[command(visible_alias = "x")]
    Extract {
        /// One or more paths to APK files to extract
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Output folder (default: <filename>.unp)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Read and pretty-print binary AndroidManifest.xml
    Axml {
        /// Path to the AndroidManifest.xml file or APK containing it
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
        Some(Commands::Axml { path }) => command_axml(path),
        None => Ok(()),
    };

    if let Err(err) = result {
        eprintln!("{:#}", err);
    }
}
