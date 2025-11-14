use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use apk_info_zip::ZipEntry;
use colored::Colorize;
use log::warn;
use regex::Regex;

use crate::commands::path_helpers::get_all_files;

pub(crate) fn command_extract(
    paths: &[PathBuf],
    output: &Option<PathBuf>,
    files: &[String],
) -> Result<()> {
    let all_files = get_all_files(paths);

    all_files.into_iter().try_for_each(|path| {
        let out_dir = make_output_dir(&path, output);
        extract(&path, &out_dir, files)
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

fn extract(path: &PathBuf, out_dir: &PathBuf, files: &[String]) -> Result<()> {
    let buf = std::fs::read(path).with_context(|| format!("can't open file: {:?}", path))?;
    let zip = ZipEntry::new(buf)?;

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("can't create output directory {:?}", out_dir))?;

    let regexes: Vec<Regex> = files
        .iter()
        .map(|file| Regex::new(file).with_context(|| format!("invalid regex: {:?}", file)))
        .collect::<Result<Vec<_>>>()?;

    for file_name in zip.namelist() {
        if file_name.ends_with('/') {
            continue;
        }

        if file_name.starts_with("..") {
            warn!("attempt to path traversal: {:?}", file_name);
            continue;
        }

        if !regexes.is_empty() && !regexes.iter().any(|re| re.is_match(file_name)) {
            continue;
        }

        let file_path = out_dir.join(file_name);

        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("can't create parent dirs for {:?}", parent))?;
        }

        let (data, _) = zip
            .read(file_name)
            .with_context(|| format!("can't read file {:?} from archive", file_name))?;

        let mut f = std::fs::File::create(&file_path)
            .with_context(|| format!("can't create file {:?}", file_path))?;
        f.write_all(data.as_slice())
            .with_context(|| format!("can't write to {:?}", file_path))?;

        // highligt interesting files
        if file_name == "AndroidManifest.xml" || file_name == "resources.arsc" {
            println!("[*] extracted \"{}\"", file_name.green().bold());
        } else if file_name.ends_with(".so") {
            println!("[*] extracted \"{}\"", file_name.magenta().bold());
        } else {
            println!("[~] extracted \"{}\"", file_name);
        }
    }

    Ok(())
}
