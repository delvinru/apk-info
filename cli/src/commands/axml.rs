use std::path::Path;

use anyhow::{Context, Result};
use apk_info_axml::AXML;

pub(crate) fn command_axml(path: &Path) -> Result<()> {
    let file =
        std::fs::read(path).with_context(|| format!("can't open and read file: {:?}", path))?;

    let axml = AXML::new(&mut &file[..])?;

    println!("{}", String::from(&axml.root));

    Ok(())
}
