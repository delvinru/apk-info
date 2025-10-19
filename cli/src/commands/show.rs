use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use apk_info::apk::Apk;
use walkdir::WalkDir;

pub(crate) fn command_show(paths: &[PathBuf], certs: &bool) -> Result<()> {
    for path in paths {
        if path.is_dir() {
            for entry in WalkDir::new(path)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.path().is_file())
                .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("apk"))
            {
                let apk_path = entry.path().to_path_buf();
                show(&apk_path, certs)?
            }
        } else if path.is_file() {
            show(path, certs)?
        }
    }

    Ok(())
}

fn show(path: &Path, certs: &bool) -> Result<()> {
    let apk = Apk::new(path).with_context(|| format!("got error while parsing apk: {:?}", path))?;

    // let info = apk.get_all_information(true);

    // TODO: need better output with some options, ok for now
    // println!("{}", info);
    if *certs {
        println!("{:#?}", apk.get_certificate_v1());
        println!("{:#?}", apk.get_certificate_v2());
    }

    Ok(())
}
