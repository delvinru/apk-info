use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};

use crate::commands::{command_axml, command_extract, command_repack, command_show};

#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod commands;

#[derive(Parser)]
#[command(version, about, arg_required_else_help(true))]
struct Cli {
    #[command(subcommand)]
    commands: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Show basic information about the APK file
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

        #[arg(short, long, default_value_t = false, help = "Show output as jsonl")]
        json: bool,
    },
    /// Unpack apk files as zip archive
    #[command(visible_alias = "x")]
    Extract {
        /// One or more paths to APK files to extract
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Output folder (default: ./<filename>.unp)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// A regular expressions for extracting specific files inside zip archive
        ///
        /// example: -f AndroidManifest.xml -f classes\d+.dex
        #[arg(short, long)]
        files: Vec<String>,

        /// Print progress for every extracted file
        #[arg(short, long, default_value_t = false)]
        verbose: bool,

        /// Decode resources apktool-style: binary XML resources and the manifest
        /// become readable XML, and resources.arsc is decoded into res/values*
        ///
        /// For split/container APKs (xapk/apkm) the resources of the inner base
        /// AND every config split are decoded into the same res/ tree, so all
        /// locale/configuration string variations are available in one place.
        #[arg(short, long, default_value_t = false)]
        resources: bool,

        /// List archive contents (sizes, compression method, tampered entries)
        /// instead of extracting
        #[arg(short, long, default_value_t = false)]
        list: bool,
    },
    /// Read and pretty-print binary AndroidManifest.xml
    Axml {
        /// Path to the AndroidManifest.xml file or APK containing it
        #[arg(required = true)]
        path: PathBuf,
    },
    /// Repack a BadPack-damaged APK into a clean, well-formed zip archive
    ///
    /// Malware sometimes tampers with zip headers (BadPack) so `unzip`/`7z`
    /// fail or drop entries; this rebuilds the archive from decoded data.
    /// The result is unsigned.
    Repack {
        /// One or more paths to APK files to repack
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Output file; a bare file name can be combined with `-d`
        /// (default: `<name>.repacked.apk` next to the source file)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output directory (default: same directory as the source file)
        #[arg(short = 'd', long, value_name = "DIR")]
        output_dir: Option<PathBuf>,
    },
    /// Generate shell completion
    Completion {
        /// The shell to generate completion for
        #[arg(value_enum)]
        shell: Shell,
    },
}

fn main() {
    env_logger::init();

    let cli = Cli::parse();

    let result = match &cli.commands {
        Some(Commands::Show { paths, sigs, json }) => command_show(paths, sigs, json),
        Some(Commands::Extract {
            paths,
            output,
            files,
            verbose,
            resources,
            list,
        }) => command_extract(paths, output, files, *verbose, *resources, *list),
        Some(Commands::Axml { path }) => command_axml(path),
        Some(Commands::Repack {
            paths,
            output,
            output_dir,
        }) => command_repack(paths, output, output_dir),
        Some(Commands::Completion { shell }) => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            generate(*shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
        None => Ok(()),
    };

    if let Err(err) = result {
        eprintln!("{:#}", err);
        std::process::exit(1);
    }
}
