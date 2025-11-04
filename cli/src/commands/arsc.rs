use std::path::Path;

use anyhow::{Context, Result};
use apk_info::apk::Apk;

pub(crate) fn command_arsc(path: &Path) -> Result<()> {
    let apk = Apk::new(path).with_context(|| format!("got error while parsing apk: {:?}", path))?;

    let package_name = apk.get_package_name();
    println!("package_name: {:?}", package_name);

    Ok(())
}
