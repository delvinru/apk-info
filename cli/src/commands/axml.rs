use std::io::IsTerminal;
use std::path::Path;

use anyhow::{Context, Result};
use apk_info::Apk;
use apk_info_axml::AXML;
use bat::PrettyPrinter;

pub(crate) fn command_axml(path: &Path) -> Result<()> {
    let stdout_is_tty = std::io::stdout().is_terminal();

    let xml = match Apk::new(path) {
        Ok(apk) => apk.get_xml_string(),
        Err(_) => {
            // raw axml?
            let file = std::fs::read(path)
                .with_context(|| format!("can't open and read file: {:?}", path))?;
            let axml = AXML::new(&mut &file[..], None)?;

            axml.get_xml_string()
        }
    };

    let mut printer = PrettyPrinter::new();
    printer.input_from_bytes(xml.as_bytes()).language("xml");

    if stdout_is_tty {
        printer.print().unwrap();
    } else {
        print!("{}", xml);
    }

    Ok(())
}
