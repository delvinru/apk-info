//! Processing a folder of APKs in parallel, tolerating broken files.
//!
//! Usage: `cargo run --example batch -- <folder>`

use std::path::{Path, PathBuf};

use apk_info::Apk;

const EXTENSIONS: &[&str] = &["apk", "xapk", "apkm", "apks"];

fn collect(dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, files)?;
        } else if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
        {
            files.push(path);
        }
    }
    Ok(())
}

// --8<-- [start:batch]
fn triage(path: &Path) -> serde_json::Value {
    match Apk::new(path) {
        Ok(apk) => serde_json::json!({
            "file": path,
            "package": apk.get_package_name(),
            "version": apk.get_version_name(),
            "min_sdk": apk.get_min_sdk_version(),
            "permissions": apk.get_permissions().collect::<Vec<_>>(),
        }),
        Err(e) => serde_json::json!({ "file": path, "error": e.to_string() }),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::args().nth(1).ok_or("usage: batch <folder>")?;
    let mut files = Vec::new();
    collect(Path::new(&dir), &mut files)?;

    // `Apk` only reads, so each thread can parse its own files independently
    let workers = std::thread::available_parallelism()?.get();
    let chunk = files.len().div_ceil(workers).max(1);
    std::thread::scope(|scope| {
        for part in files.chunks(chunk) {
            scope.spawn(move || {
                for path in part {
                    println!("{}", triage(path));
                }
            });
        }
    });

    Ok(())
}
// --8<-- [end:batch]
