use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use apk_info::FileCompressionType;
use apk_info_zip::ZipEntry;
use colored::Colorize;
use log::warn;
use md5::{Digest, Md5};
use regex::Regex;

use crate::commands::path_helpers::get_all_files;

/// Maximum length (in bytes) of a single path component on most filesystems.
const MAX_COMPONENT_LEN: usize = 255;

/// Conservative maximum length (in bytes) of the full output path
const MAX_PATH_LEN: usize = 1024;

pub(crate) fn command_extract(
    paths: &[PathBuf],
    output: &Option<PathBuf>,
    files: &[String],
    verbose: bool,
) -> Result<()> {
    let all_files = get_all_files(paths);

    all_files.into_iter().try_for_each(|path| {
        let out_dir = make_output_dir(&path, output);
        extract(&path, &out_dir, files, verbose)
    })
}

fn make_output_dir(path: &Path, output: &Option<PathBuf>) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|n| {
            let mut s = n.to_os_string();
            s.push(".unp");
            s
        })
        .unwrap_or_else(|| "unknown.unp".into());

    match output {
        Some(out) => {
            // ./<output>/<file_name>.unp
            let mut p = PathBuf::from(out);
            p.push(file_name);
            p
        }
        None => {
            // ./<file_name>.unp
            PathBuf::from(file_name)
        }
    }
}

/// Resolves where an entry should be written inside `out_dir`.
///
/// Returns `None` for traversal or directory entries that must never be written.
/// Returns `Some((path, renamed))`, where `renamed` is `true` when the original
/// name was a malicious/broken path (a component or the full path is too long for
/// the filesystem) designed to break extraction tools - in that case the data is
/// saved under an md5 hash of the original name.
fn resolve_output_path(out_dir: &Path, file_name: &str) -> Option<(PathBuf, bool)> {
    if file_name.ends_with('/')
        || file_name.is_empty()
        || file_name.starts_with("..")
        || file_name.starts_with("/")
    {
        return None;
    }

    let direct = out_dir.join(file_name);
    let too_long = file_name.split('/').any(|c| c.len() > MAX_COMPONENT_LEN)
        || direct.as_os_str().len() > MAX_PATH_LEN;

    if too_long {
        let mut hasher = Md5::new();
        hasher.update(file_name.as_bytes());
        let hash = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        eprintln!(
            "[-] malicious/broken filename (too long for the filesystem) - saving \"{}\" as \"{}\"",
            file_name.yellow(),
            hash.bold()
        );
        Some((out_dir.join(hash), true))
    } else {
        Some((direct, false))
    }
}

fn extract(path: &PathBuf, out_dir: &PathBuf, files: &[String], verbose: bool) -> Result<()> {
    let buf = std::fs::read(path).with_context(|| format!("can't open file: {:?}", path))?;
    let zip = ZipEntry::new(buf)?;

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("can't create output directory {:?}", out_dir))?;

    let regexes: Vec<Regex> = files
        .iter()
        .map(|file| Regex::new(file).with_context(|| format!("invalid regex: {:?}", file)))
        .collect::<Result<Vec<_>>>()?;

    for file_name in zip.namelist() {
        if !regexes.is_empty() && !regexes.iter().any(|re| re.is_match(file_name)) {
            continue;
        }

        let Some((file_path, renamed)) = resolve_output_path(out_dir, file_name) else {
            warn!("got bad filename: {:?}, skipped", file_name);
            continue;
        };

        if let Some(parent) = file_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            println!(
                "[-] can't create parent dirs for {:?} - {}",
                file_name,
                e.to_string().red()
            );
            continue;
        }

        let (data, compression) = match zip.read(file_name) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "[-] can't extract file from archive - {:?} - {}",
                    file_name,
                    e.to_string().red().bold(),
                );
                continue;
            }
        };

        let mut f = match std::fs::File::create(&file_path) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "[-] can't create file - {:?} - {}",
                    file_name,
                    e.to_string().red()
                );
                continue;
            }
        };

        f.write_all(data.as_slice())
            .with_context(|| format!("can't write to {:?}", file_path))?;

        // show interesting files (manifest, resources, native libs) and tampered
        // entries always; everything else only in verbose mode
        let display_name = if renamed {
            file_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
        } else {
            None
        };

        let is_tampered = matches!(
            compression,
            FileCompressionType::StoredTampered | FileCompressionType::DeflatedTampered
        );
        let show_line = verbose
            || is_tampered
            || file_name == "AndroidManifest.xml"
            || file_name == "resources.arsc"
            || file_name.ends_with(".so");

        if show_line {
            // highligt interesting files
            if file_name == "AndroidManifest.xml" || file_name == "resources.arsc" {
                print!(
                    "[*] extracted \"{}\" ",
                    display_name.as_deref().unwrap_or(file_name).green().bold()
                );
            } else if file_name.ends_with(".so") {
                print!(
                    "[*] extracted \"{}\" ",
                    display_name
                        .as_deref()
                        .unwrap_or(file_name)
                        .magenta()
                        .bold()
                );
            } else {
                print!(
                    "[~] extracted \"{}\" ",
                    display_name.as_deref().unwrap_or(file_name)
                );
            }

            if is_tampered {
                println!("({})", format!("{:?}", compression).bold().red());
            } else {
                println!("({:?})", compression);
            }
        }
    }

    Ok(())
}
