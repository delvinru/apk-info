use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use apk_info::FileCompressionType;
use apk_info_zip::ZipEntry;
use colored::Colorize;

use crate::commands::path_helpers::get_all_files;

pub(crate) fn command_repack(paths: &[PathBuf], output: &Option<PathBuf>) -> Result<()> {
    let all_files = get_all_files(paths);

    all_files.into_iter().try_for_each(|path| {
        let out_path = make_output_path(&path, output);
        repack(&path, &out_path)
    })
}

fn make_output_path(path: &Path, output: &Option<PathBuf>) -> PathBuf {
    let file_name = path
        .file_stem()
        .map(|n| {
            let mut s = n.to_os_string();
            s.push(".repacked.apk");
            s
        })
        .unwrap_or_else(|| "unknown.repacked.apk".into());

    match output {
        // ./<output>/<name>.repacked.apk
        Some(out) => out.join(file_name),
        // ./<source_dir>/<name>.repacked.apk
        None => path.with_file_name(file_name),
    }
}

fn repack(path: &PathBuf, out_path: &PathBuf) -> Result<()> {
    let buf = std::fs::read(path).with_context(|| format!("can't open file: {:?}", path))?;
    let zip = ZipEntry::new(buf)?;

    let mut tampered = 0usize;
    for name in zip.namelist() {
        if let Ok((_, compression)) = zip.read(name)
            && matches!(
                compression,
                FileCompressionType::StoredTampered | FileCompressionType::DeflatedTampered
            )
        {
            tampered += 1;
        }
    }

    let out_bytes = zip
        .repack()
        .with_context(|| format!("can't repack file: {:?}", path))?;

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("can't create output directory {:?}", parent))?;
    }

    let mut f = std::fs::File::create(out_path)
        .with_context(|| format!("can't create file {:?}", out_path))?;
    f.write_all(&out_bytes)
        .with_context(|| format!("can't write to {:?}", out_path))?;

    if tampered > 0 {
        println!(
            "[*] repacked \"{}\" - fixed {} tampered entry{} -> \"{}\"",
            path.display().to_string().green().bold(),
            tampered,
            if tampered == 1 { "" } else { "s" },
            out_path.display().to_string().bold()
        );
    } else {
        println!(
            "[~] repacked \"{}\" -> \"{}\"",
            path.display().to_string().green(),
            out_path.display().to_string().bold()
        );
    }

    Ok(())
}
