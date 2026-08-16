use std::collections::BTreeSet;
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
use crate::commands::resdecode::{decode_resources, decode_resources_split};

/// Maximum length (in bytes) of a single path component on most filesystems.
const MAX_COMPONENT_LEN: usize = 255;

/// Conservative maximum length (in bytes) of the full output path
const MAX_PATH_LEN: usize = 1024;

pub(crate) fn command_extract(
    paths: &[PathBuf],
    output: &Option<PathBuf>,
    files: &[String],
    verbose: bool,
    resources: bool,
) -> Result<()> {
    let all_files = get_all_files(paths);

    all_files.into_iter().try_for_each(|path| {
        let out_dir = make_output_dir(&path, output);
        extract(&path, &out_dir, files, verbose, resources)
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

/// Locates and parses the base inner APK of a `xapk`/`apkm` container, if any.
fn container_base_apk(zip: &ZipEntry) -> Option<ZipEntry> {
    // xapk: manifest.json declares package_name -> <package_name>.apk
    if let Ok((m, _)) = zip.read("manifest.json")
        && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&m)
        && let Some(pkg) = v.get("package_name").and_then(|s| s.as_str())
        && let Ok((data, _)) = zip.read(&format!("{pkg}.apk"))
    {
        return ZipEntry::new(data).ok();
    }
    // apkm: contains a single base.apk
    if let Ok((data, _)) = zip.read("base.apk") {
        return ZipEntry::new(data).ok();
    }
    None
}

/// Enumerates the config/other split inner APKs of a `xapk`/`apkm` container
/// (everything that is *not* the base).
///
/// Each carries its own `resources.arsc` with locale/configuration string variations that complement the base's.
fn container_split_apks(zip: &ZipEntry) -> Vec<(String, ZipEntry)> {
    let mut names: BTreeSet<String> = BTreeSet::new();

    // xapk: manifest.json split_apks -> file names (skip the id == "base" module)
    if let Ok((m, _)) = zip.read("manifest.json")
        && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&m)
        && let Some(arr) = v.get("split_apks").and_then(|s| s.as_array())
    {
        for sp in arr {
            let file = sp.get("file").and_then(|s| s.as_str()).unwrap_or("");
            let id = sp.get("id").and_then(|s| s.as_str()).unwrap_or("");
            if file.ends_with(".apk") && !id.is_empty() && id != "base" {
                names.insert(file.to_string());
            }
        }
    }

    // heuristic fallback (apkm / manifestless containers): config.*/split_* APKs
    for name in zip.namelist() {
        if name.ends_with(".apk") && (name.starts_with("config.") || name.starts_with("split_")) {
            names.insert(name.to_string());
        }
    }

    names
        .into_iter()
        .filter_map(|name| {
            zip.read(&name)
                .ok()
                .and_then(|(d, _)| ZipEntry::new(d).ok())
                .map(|inner| (name, inner))
        })
        .collect()
}

fn write_bytes(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        println!(
            "[-] can't create parent dirs for {:?} - {}",
            path,
            e.to_string().red()
        );
        return Ok(());
    }

    let mut f =
        std::fs::File::create(path).with_context(|| format!("can't create file {:?}", path))?;
    f.write_all(contents)
        .with_context(|| format!("can't write to {:?}", path))
}

/// `resources` toggles apktool-style decoding: the manifest, binary XML resources
/// and `resources.arsc` are decoded arsc-driven (see [`decode_resources`]); every
/// non-resource entry (dex, libs, assets, ...) is still copied as-is.
fn extract(
    path: &PathBuf,
    out_dir: &PathBuf,
    files: &[String],
    verbose: bool,
    resources: bool,
) -> Result<()> {
    let buf = std::fs::read(path).with_context(|| format!("can't open file: {:?}", path))?;
    let zip = ZipEntry::new(buf)?;

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("can't create output directory {:?}", out_dir))?;

    let regexes: Vec<Regex> = files
        .iter()
        .map(|file| Regex::new(file).with_context(|| format!("invalid regex: {:?}", file)))
        .collect::<Result<Vec<_>>>()?;

    if resources && let Err(e) = decode_resources(out_dir, &zip) {
        println!("[-] can't decode resources - {}", e.to_string().red());
    }

    for file_name in zip.namelist() {
        if !regexes.is_empty() && !regexes.iter().any(|re| re.is_match(file_name)) {
            continue;
        }

        let Some((file_path, renamed)) = resolve_output_path(out_dir, file_name) else {
            warn!("got bad filename: {:?}, skipped", file_name);
            continue;
        };

        if resources
            && (file_name == "AndroidManifest.xml"
                || file_name == "resources.arsc"
                || file_name.starts_with("res/"))
        {
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

        write_bytes(&file_path, &data)?;

        // show interesting files (native libs) and tampered entries
        let display_name = if renamed {
            file_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
        } else {
            None
        };
        let shown = display_name.as_deref().unwrap_or(file_name);

        let is_tampered = matches!(
            compression,
            FileCompressionType::StoredTampered | FileCompressionType::DeflatedTampered
        );
        if verbose || is_tampered || file_name.ends_with(".so") {
            if file_name.ends_with(".so") {
                print!("[*] extracted \"{}\" ", shown.magenta().bold());
            } else {
                print!("[~] extracted \"{}\" ", shown);
            }
            if is_tampered {
                println!("({})", format!("{:?}", compression).bold().red());
            } else {
                println!("({:?})", compression);
            }
        }
    }

    if resources {
        if let Some(inner) = container_base_apk(&zip) {
            println!("[*] decoding resources of the base inner apk");
            if let Err(e) = decode_resources(out_dir, &inner) {
                println!("[-] can't decode inner resources - {}", e.to_string().red());
            }
        }
        for (name, split) in container_split_apks(&zip) {
            println!("[*] decoding resources of split apk \"{name}\"");
            if let Err(e) = decode_resources_split(out_dir, &split) {
                println!(
                    "[-] can't decode split \"{name}\" resources - {}",
                    e.to_string().red()
                );
            }
        }
    }

    Ok(())
}
