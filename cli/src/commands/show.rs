use std::path::PathBuf;

use anyhow::{Context, Result};
use apk_info::apk::APK;
use walkdir::WalkDir;

pub(crate) fn command_show(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        if path.is_dir() {
            for entry in WalkDir::new(path)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.path().is_file())
                .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("apk"))
            {
                let apk_path = entry.path().to_path_buf();
                show(&apk_path)?
            }
        } else if path.is_file() {
            show(&path)?
        }
    }

    Ok(())
}

fn show(path: &PathBuf) -> Result<()> {
    let apk = APK::new(path).with_context(|| format!("got error while parsing apk: {:?}", path))?;

    let package_name = apk.get_package_name().unwrap_or_default();
    let min_sdk = apk.get_min_sdk_version().unwrap_or_default();

    println!("{} ({})", package_name, min_sdk);

    Ok(())
}
