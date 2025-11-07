use std::path::Path;

use anyhow::{Context, Result};
use apk_info::apk::Apk;
use apk_info_axml::AXML;

use crate::commands::path_helpers::contains_extensions;

pub(crate) fn command_axml(path: &Path) -> Result<()> {
    if contains_extensions(path, &["apk", "zip", "jar"]) {
        let apk = Apk::new(path).with_context(|| format!("can't open apk file: {:?}", path))?;

        println!("{}", apk.axml.get_xml_string());
    } else {
        let file =
            std::fs::read(path).with_context(|| format!("can't open and read file: {:?}", path))?;
        let axml = AXML::new(&mut &file[..], None)?;

        println!("{}", axml.get_xml_string());
    }

    Ok(())
}
