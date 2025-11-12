use std::path::PathBuf;

use walkdir::WalkDir;

pub(crate) fn get_all_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .iter()
        .flat_map(move |path| {
            if path.is_dir() {
                WalkDir::new(path)
                    .into_iter()
                    .filter_entry(|e| {
                        e.file_name()
                            .to_str()
                            .map(|s| !s.starts_with("."))
                            .unwrap_or(false)
                    })
                    .filter_map(Result::ok)
                    .filter(|e| e.path().is_file())
                    .map(|e| e.path().to_path_buf())
                    .collect::<Vec<_>>()
            } else if path.is_file() {
                vec![path.clone()]
            } else {
                Vec::new()
            }
        })
        .collect()
}
