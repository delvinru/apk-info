use std::path::PathBuf;

use walkdir::WalkDir;

/// Returns an iterator over all files in `paths` that have one of the allowed extensions.
pub(crate) fn get_all_files(
    paths: &[PathBuf],
    allowed_exts: &[&str],
) -> impl Iterator<Item = PathBuf> {
    paths.iter().flat_map(move |path| {
        if path.is_dir() {
            WalkDir::new(path)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.path().is_file())
                .filter(move |e| {
                    e.path()
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|ext| allowed_exts.iter().any(|a| a == &ext.to_lowercase()))
                        .unwrap_or(false)
                })
                .map(|e| e.path().to_path_buf())
                .collect::<Vec<_>>() // intermediate vec because of closure capture
                .into_iter()
        } else if path.is_file() {
            if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                if allowed_exts.iter().any(|a| a == &ext.to_lowercase()) {
                    std::iter::once(path.clone())
                        .collect::<Vec<_>>()
                        .into_iter()
                } else {
                    Vec::new().into_iter()
                }
            } else {
                Vec::new().into_iter()
            }
        } else {
            Vec::new().into_iter()
        }
    })
}
