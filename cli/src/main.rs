use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};

use crate::commands::{command_axml, command_extract, command_repack, command_show};

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
    },
    /// Read and pretty-print binary AndroidManifest.xml
    Axml {
        /// Path to the AndroidManifest.xml file or APK containing it
        #[arg(required = true)]
        path: PathBuf,
    },
    /// Unpack and repack a BadPack-damaged APK into a standard, well-formed zip archive
    ///
    /// Some malware tampers with zip headers (the BadPack technique) so that
    /// standard tools like `unzip` and `7z` fail to open the archive or silently
    /// drop entries (e.g. the AndroidManifest.xml). This command decodes every
    /// entry the way apk-info does, and writes the data back into a clean zip
    /// archive with correct compression headers.
    ///
    /// NOTE: the resulting archive is NOT signed - v1 signature files (META-INF)
    /// and the APK Signature Block (v2/v3) are not reproduced.
    Repack {
        /// One or more paths to APK files to repack
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Output directory (default: same directory as the source file)
        #[arg(short, long)]
        output: Option<PathBuf>,
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
        }) => command_extract(paths, output, files, *verbose),
        Some(Commands::Axml { path }) => command_axml(path),
        Some(Commands::Repack { paths, output }) => command_repack(paths, output),
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
    }
}
