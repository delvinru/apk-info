use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use apk_info_zip::ZipEntry;
use log::warn;

use crate::commands::path_helpers::get_all_files;

pub(crate) fn command_extract(paths: &[PathBuf], output: &Option<PathBuf>) -> Result<()> {
    let all_files: Vec<PathBuf> = get_all_files(paths, &["apk", "zip", "jar"]).collect();

    let multiple_files = all_files.len() > 1;

    all_files.into_iter().try_for_each(|path| {
        let out_dir = make_output_dir(&path, output, multiple_files);
        extract(&path, &out_dir)
    })
}

fn make_output_dir(path: &Path, output: &Option<PathBuf>, multiple: bool) -> PathBuf {
    match output {
        Some(out) if multiple => {
            let mut sub = out.clone();
            let name = path
                .file_name()
                .map(|n| {
                    let mut s = n.to_os_string();
                    s.push(".unp");
                    s
                })
                .unwrap_or_else(|| "unknown.unp".into());
            sub.push(name);
            sub
        }
        Some(out) => out.clone(),
        None => {
            let mut d = path.to_path_buf();
            let new_name = d
                .file_name()
                .map(|n| {
                    let mut s = n.to_os_string();
                    s.push(".unp");
                    s
                })
                .unwrap_or_else(|| "output.unp".into());
            d.set_file_name(new_name);
            d
        }
    }
}

fn extract(path: &PathBuf, out_dir: &PathBuf) -> Result<()> {
    let buf = std::fs::read(path).with_context(|| format!("can't open file: {:?}", path))?;
    let zip = ZipEntry::new(buf)?;

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("can't create output directory {:?}", out_dir))?;

    for file_name in zip.namelist() {
        if file_name.ends_with('/') {
            continue;
        }

        if file_name.starts_with("..") {
            warn!("attempt to path traversal: {:?}", file_name);
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
    }

    Ok(())
}
