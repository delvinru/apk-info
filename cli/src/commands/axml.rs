use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};
use apk_info::{Apk, ZipEntry};
use apk_info_axml::AXML;
use apk_info_xml::Element;

pub(crate) fn command_axml(path: &Path) -> Result<()> {
    match Apk::new(path) {
        Ok(apk) => print_xml(&apk.get_manifest().root),
        // a zip that isn't an apk keeps its own error
        Err(err) if ZipEntry::open(path).is_ok() => Err(err.into()),
        Err(_) => {
            let file = std::fs::read(path)
                .with_context(|| format!("can't open and read file: {:?}", path))?;
            let axml = AXML::new(&mut &file[..], None)?;
            print_xml(&axml.root)
        }
    }
}

/// Prints the document, colored by the rules of the other commands: a
/// terminal, `NO_COLOR`, `CLICOLOR` and `CLICOLOR_FORCE`.
fn print_xml(root: &Element) -> Result<()> {
    let mut out = BufWriter::new(std::io::stdout().lock());
    if colored::control::SHOULD_COLORIZE.should_colorize() {
        write!(out, "{}", root.colored())?;
    } else {
        write!(out, "{root}")?;
    }
    out.flush().context("can't print the manifest")
}
