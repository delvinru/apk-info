use std::path::PathBuf;

use anyhow::{Context, Result};
use apk_info::Apk;
use apk_info_dex::Dex;

pub(crate) fn command_dex(path: &PathBuf) -> Result<()> {
    let apk = Apk::new(path).with_context(|| format!("can't parse apk file: {:?}", path))?;

    let (data, _) = apk
        .read("classes.dex")
        .with_context(|| "can't open classes.dex")?;

    std::fs::write("classes.dex", &data).unwrap();

    let dex = Dex::new(data).with_context(|| "can't parse dex file")?;

    println!("{:?} - {:?}", dex.checksum(), dex.header.checksum);

    Ok(())
}
