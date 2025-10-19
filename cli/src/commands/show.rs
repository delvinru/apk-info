use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use apk_info::apk::Apk;
use walkdir::WalkDir;

pub(crate) fn command_show(paths: &[PathBuf], show_signatures: &bool) -> Result<()> {
    for path in paths {
        if path.is_dir() {
            for entry in WalkDir::new(path)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.path().is_file())
                .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("apk"))
            {
                let apk_path = entry.path().to_path_buf();
                show(&apk_path, show_signatures)?
            }
        } else if path.is_file() {
            show(path, show_signatures)?
        }
    }

    Ok(())
}

fn show(path: &Path, show_signatures: &bool) -> Result<()> {
    let apk = Apk::new(path).with_context(|| format!("got error while parsing apk: {:?}", path))?;

    let info = apk.get_all_information(true);

    println!("{}", info);
    if *show_signatures {
        // TODO: remove this message after bunch of testing
        println!(
            "{:#?}",
            apk.get_signatures()
                .expect("if this call failed, probably bug in library, report this apk")
        );
    }

    Ok(())
}
