//! Reading files from an APK: listing, DEX files and tampered entries.
//!
//! Usage: `cargo run --example files -- <path-to-apk> <output-dir>`

use std::path::Path;

use apk_info::{Apk, FileCompressionType, ZipEntry};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: files <path-to-apk> <output-dir>";
    let path = args.next().ok_or(usage)?;
    let out = args.next().ok_or(usage)?;
    std::fs::create_dir_all(&out)?;

    let apk = Apk::new(&path)?;

    // --8<-- [start:read]
    println!("{} entries", apk.namelist().count());

    let (data, compression) = apk.read("AndroidManifest.xml")?;
    println!("{} bytes, {compression:?}", data.len());
    // --8<-- [end:read]

    // --8<-- [start:dex]
    for name in apk.namelist() {
        if name.starts_with("classes") && name.ends_with(".dex") {
            let (data, _) = apk.read(name)?;
            std::fs::write(Path::new(&out).join(name), &data)?;
        }
    }
    // --8<-- [end:dex]

    // --8<-- [start:tampered]
    // reading every entry decompresses it; to only check headers, use the zip
    // reader directly
    let (_, compression) = apk.read("AndroidManifest.xml")?;
    if matches!(
        compression,
        FileCompressionType::StoredTampered | FileCompressionType::DeflatedTampered
    ) {
        println!("tampered header: AndroidManifest.xml ({compression:?})");
    }

    let zip = ZipEntry::open(&path)?;
    for name in zip.namelist() {
        if zip.entry_info(name).is_some_and(|info| info.tampered) {
            println!("tampered header: {name}");
        }
    }
    // --8<-- [end:tampered]

    Ok(())
}
