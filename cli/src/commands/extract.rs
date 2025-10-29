use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use apk_info_zip::entry::ZipEntry;
use walkdir::WalkDir;

pub(crate) fn command_extract(paths: &[PathBuf], output: &Option<PathBuf>) -> Result<()> {
    let mut all_files = Vec::new();
    for path in paths {
        if path.is_dir() {
            for entry in WalkDir::new(path)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.path().is_file())
                .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("apk"))
            {
                all_files.push(entry.path().to_path_buf());
            }
        } else if path.is_file() {
            all_files.push(path.clone());
        }
    }

    let multiple_files = all_files.len() > 1;

    for path in all_files {
        let out_dir = if let Some(out) = output {
            if multiple_files {
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
            } else {
                out.clone()
            }
        } else {
            let mut d = path.clone();
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
        };

        extract(&path, &out_dir)?;
    }

    Ok(())
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
            // TODO: show warning about path traversal
            continue;
        }

        let file_path = out_dir.join(&file_name);

        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("can't create parent dirs for {:?}", parent))?;
        }

        let (data, _) = zip
            .read(&file_name)
            .with_context(|| format!("can't read file {:?} from archive", file_name))?;

        let mut f = std::fs::File::create(&file_path)
            .with_context(|| format!("can't create file {:?}", file_path))?;
        f.write_all(data.as_slice())
            .with_context(|| format!("can't write to {:?}", file_path))?;
    }

    Ok(())
}
