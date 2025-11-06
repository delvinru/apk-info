use std::path::Path;

use anyhow::{Context, Result};
use apk_info::apk::Apk;
use apk_info_axml::AXML;

pub(crate) fn command_axml(path: &Path) -> Result<()> {
    if path.ends_with("zip") || path.ends_with("apk") || path.ends_with("jar") {
        let apk = Apk::new(path).with_context(|| format!("can't open apk file: {:?}", path))?;

        println!("{}", apk.axml.get_xml_string());
    } else {
        let file =
            std::fs::read(path).with_context(|| format!("can't open and read file: {:?}", path))?;
        let axml = AXML::new(&mut &file[..])?;

        println!("{}", axml.get_xml_string());
    }

    Ok(())
}
