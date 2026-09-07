use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use apk_info::FileCompressionType;
use apk_info_zip::ZipEntry;
use colored::Colorize;

use crate::commands::path_helpers::get_all_files;

pub(crate) fn command_repack(
    paths: &[PathBuf],
    output: &Option<PathBuf>,
    output_dir: &Option<PathBuf>,
) -> Result<()> {
    let all_files = get_all_files(paths);

    // a single explicit file name cannot cover several inputs
    if output.is_some() && all_files.len() > 1 {
        bail!(
            "--output can only be used with a single input file, use --output-dir for multiple inputs"
        );
    }

    all_files.into_iter().try_for_each(|path| {
        let out_path = make_output_path(&path, output, output_dir)?;
        repack(&path, &out_path)
    })
}

/// `<source stem>.repacked.apk`
fn default_output_name(path: &Path) -> PathBuf {
    path.file_stem()
        .map(|n| {
            let mut s = n.to_os_string();
            s.push(".repacked.apk");
            s.into()
        })
        .unwrap_or_else(|| "unknown.repacked.apk".into())
}

/// Resolves the output path from the `-o/--output` and `-d/--output-dir` options:
///
/// - `-o FILE`: the output path as given (bare relative names resolve against
///   the working directory, unix-style)
/// - `-d DIR`: the directory for `<name>.repacked.apk`
/// - both: `DIR/FILE`; FILE must then be a bare name
/// - neither: next to the source file
fn make_output_path(
    path: &Path,
    output: &Option<PathBuf>,
    output_dir: &Option<PathBuf>,
) -> Result<PathBuf> {
    match (output, output_dir) {
        (Some(file), Some(dir)) => {
            if file.parent().is_some_and(|p| !p.as_os_str().is_empty()) {
                bail!("--output must be a bare file name when combined with --output-dir");
            }
            Ok(dir.join(file))
        }
        (Some(file), None) => Ok(file.clone()),
        (None, Some(dir)) => Ok(dir.join(default_output_name(path))),
        (None, None) => Ok(path.with_file_name(default_output_name(path))),
    }
}

fn repack(path: &PathBuf, out_path: &PathBuf) -> Result<()> {
    // the archive is opened lazily, without reading the whole file into memory
    let zip = ZipEntry::open(path).with_context(|| format!("can't open file: {:?}", path))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn opt(p: &str) -> Option<PathBuf> {
        Some(PathBuf::from(p))
    }

    #[test]
    fn no_options_lands_next_to_source() {
        let out = make_output_path(Path::new("/a/b/game.apk"), &None, &None).unwrap();
        assert_eq!(out, PathBuf::from("/a/b/game.repacked.apk"));
    }

    #[test]
    fn output_dir_gets_default_name() {
        let out = make_output_path(Path::new("/a/b/game.apk"), &None, &opt("/tmp/out")).unwrap();
        assert_eq!(out, PathBuf::from("/tmp/out/game.repacked.apk"));
    }

    #[test]
    fn output_is_used_as_full_path() {
        let out = make_output_path(Path::new("/a/b/game.apk"), &opt("fixed.apk"), &None).unwrap();
        assert_eq!(out, PathBuf::from("fixed.apk"));
    }

    #[test]
    fn output_with_dir_part_is_a_full_path_too() {
        let out =
            make_output_path(Path::new("/a/b/game.apk"), &opt("out/fixed.apk"), &None).unwrap();
        assert_eq!(out, PathBuf::from("out/fixed.apk"));
    }

    #[test]
    fn bare_output_joins_output_dir() {
        let out =
            make_output_path(Path::new("/a/b/game.apk"), &opt("fixed.apk"), &opt("/tmp")).unwrap();
        assert_eq!(out, PathBuf::from("/tmp/fixed.apk"));
    }

    #[test]
    fn output_with_dir_part_rejects_output_dir() {
        let err = make_output_path(
            Path::new("/a/game.apk"),
            &opt("sub/fixed.apk"),
            &opt("/tmp"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("--output"),
            "unexpected error: {err}"
        );
    }
}
