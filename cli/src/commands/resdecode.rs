use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use apk_info_axml::structs::ResTableEntry;
use apk_info_axml::{ARSC, AXML};
use apk_info_xml::Element;
use apk_info_zip::ZipEntry;

/// Maps a resource type name to the file that holds it (including the `.xml` suffix).
#[inline]
fn type_file(type_name: &str) -> &'static str {
    match type_name {
        "bool" => "bools.xml",
        "color" => "colors.xml",
        "dimen" => "dimens.xml",
        "float" => "floats.xml",
        "integer" => "integers.xml",
        "plurals" => "plurals.xml",
        "string" => "strings.xml",
        "string-array" | "integer-array" | "array" => "arrays.xml",
        "style" => "styles.xml",
        _ => "",
    }
}

/// Returns the scalar value of a simple (non-complex) entry, if it has one.
#[inline]
fn scalar_value(arsc: &ARSC, entry: &ResTableEntry) -> Option<String> {
    match entry {
        ResTableEntry::Default(e) => Some(arsc.value_to_string(&e.value)),
        _ => None,
    }
}

/// Encodes a plural item's quantity from the map item name.
///
/// Android encodes the quantity as a special map-id `0x01000004 + rule`:
/// 0x04=other, 0x05=zero, 0x06=one, 0x07=two, 0x08=few, 0x09=many.
#[inline]
fn plural_quantity(name: u32) -> &'static str {
    match name & 0xff {
        5 => "zero",
        6 => "one",
        7 => "two",
        8 => "few",
        9 => "many",
        _ => "other",
    }
}

/// Decodes `resources.arsc` (`bytes`) into `<out_dir>/res/values*/...` files.
pub(crate) fn decode_arsc(out_dir: &Path, bytes: &[u8]) -> Result<()> {
    let arsc = ARSC::new(&mut &bytes[..]).context("can't parse resources.arsc")?;

    // folder (e.g. "values", "values-en-rUS") -> file ("strings.xml") -> child elements
    let mut files: BTreeMap<String, BTreeMap<String, Vec<Element>>> = BTreeMap::new();

    for pkg in arsc.packages() {
        for (config, type_map) in &pkg.resources {
            // one `folder` bucket per config, handed out once and reused by every entry
            let qualifier = config.as_string();
            let folder = if qualifier.is_empty() {
                "values".to_string()
            } else {
                format!("values-{qualifier}")
            };
            let file_map = files.entry(folder).or_default();

            for (type_id, entries) in type_map {
                for entry in entries {
                    if matches!(entry, ResTableEntry::NoEntry) {
                        continue;
                    }

                    let Some(full_name) = pkg.get_entry_full_name(entry, *type_id) else {
                        continue;
                    };
                    let Some((type_name, key)) = full_name.split_once('/') else {
                        continue;
                    };

                    let file = type_file(type_name);
                    match file {
                        "strings.xml" | "bools.xml" | "integers.xml" | "colors.xml"
                        | "dimens.xml" | "floats.xml" => {
                            if let Some(v) = scalar_value(&arsc, entry) {
                                let mut el = Element::new(type_name);
                                el.set_attribute("name", key);
                                el.set_text(&v);
                                file_map.entry(file.to_string()).or_default().push(el);
                            }
                        }
                        "arrays.xml" => {
                            if let ResTableEntry::Complex(e) = entry {
                                let mut el = Element::new(type_name);
                                el.set_attribute("name", key);
                                for m in &e.values {
                                    let mut item = Element::new("item");
                                    item.set_text(&arsc.value_to_string(&m.value));
                                    el.append_child(item);
                                }
                                file_map.entry(file.to_string()).or_default().push(el);
                            }
                        }
                        "plurals.xml" => {
                            if let ResTableEntry::Complex(e) = entry {
                                let mut el = Element::new("plurals");
                                el.set_attribute("name", key);
                                for m in &e.values {
                                    let mut item = Element::new("item");
                                    item.set_attribute("quantity", plural_quantity(m.name));
                                    item.set_text(&arsc.value_to_string(&m.value));
                                    el.append_child(item);
                                }
                                file_map.entry(file.to_string()).or_default().push(el);
                            }
                        }
                        "styles.xml" => {
                            if let ResTableEntry::Complex(e) = entry {
                                let mut el = Element::new("style");
                                el.set_attribute("name", key);
                                if e.parent != 0
                                    && let Some(parent) = arsc.get_resource_name(e.parent)
                                {
                                    el.set_attribute("parent", &parent);
                                }
                                for m in &e.values {
                                    let attr = arsc
                                        .get_resource_name(m.name)
                                        .map(|n| {
                                            n.strip_prefix("attr/").map(str::to_owned).unwrap_or(n)
                                        })
                                        .unwrap_or_else(|| format!("0x{:08x}", m.name));
                                    let mut item = Element::new("item");
                                    item.set_attribute("name", &attr);
                                    item.set_text(&arsc.value_to_string(&m.value));
                                    el.append_child(item);
                                }
                                file_map.entry(file.to_string()).or_default().push(el);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // write everything out
    let res_dir = out_dir.join("res");
    for (folder, file_map) in files {
        // skip configs that produced no value files (e.g. density-only drawables)
        if file_map.is_empty() {
            continue;
        }
        let dir = res_dir.join(folder);
        std::fs::create_dir_all(&dir).with_context(|| format!("can't create res dir {:?}", dir))?;
        for (file, mut elements) in file_map {
            elements.sort_by(|a, b| {
                (
                    a.attr("name").unwrap_or_default(),
                    a.attr("type").unwrap_or_default(),
                    a.attr("id").unwrap_or_default(),
                )
                    .cmp(&(
                        b.attr("name").unwrap_or_default(),
                        b.attr("type").unwrap_or_default(),
                        b.attr("id").unwrap_or_default(),
                    ))
            });

            let mut root = Element::new("resources");
            for element in elements {
                root.append_child(element);
            }

            let path = dir.join(file);
            let mut f =
                std::fs::File::create(&path).with_context(|| format!("can't create {:?}", path))?;
            write!(f, "{root}").with_context(|| format!("can't write {:?}", path))?;
        }
    }

    Ok(())
}

/// Returns `true` when `data` looks like a binary AXML document (magic `0x00080003`).
#[inline]
fn is_axml(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 3 && data[1] == 0 && data[2] == 8 && data[3] == 0
}

/// Decodes a binary AXML blob into a readable XML string, if possible.
fn decode_axml(data: &[u8], arsc: Option<&ARSC>) -> Option<String> {
    let axml = AXML::new(&mut &data[..], arsc).ok()?;
    Some(axml.get_xml_string())
}

/// Writes the file resources declared in `resources.arsc` into their canonical
/// `res/<type>[-<config>]/` folders (apktool/jadx layout).
pub(crate) fn decode_files(out_dir: &Path, arsc: &ARSC, zip: &ZipEntry) -> Result<()> {
    for pkg in arsc.packages() {
        for (config, type_map) in &pkg.resources {
            let qualifier = config.as_string();
            let folder_pfx = if qualifier.is_empty() {
                String::new()
            } else {
                format!("-{qualifier}")
            };

            for (type_id, entries) in type_map {
                for entry in entries {
                    if matches!(entry, ResTableEntry::NoEntry) {
                        continue;
                    }
                    let Some(full_name) = pkg.get_entry_full_name(entry, *type_id) else {
                        continue;
                    };
                    let Some((type_name, key)) = full_name.split_once('/') else {
                        continue;
                    };
                    // file resources store their `res/...` path as a String value
                    let ResTableEntry::Default(e) = entry else {
                        continue;
                    };
                    let src = arsc.value_to_string(&e.value);
                    if !src.starts_with("res/") {
                        continue;
                    }

                    // canonical folder: `res/<type>` or `res/<type>-<qualifier>`
                    let folder = format!("{type_name}{folder_pfx}");

                    // output basename: the resource key name + the source extension
                    let ext = src
                        .rsplit_once('.')
                        .map(|(_, e)| e.trim())
                        .filter(|e| {
                            !e.is_empty()
                                && e.len() <= 8
                                && e.bytes().all(|b| b.is_ascii_alphanumeric())
                        })
                        .map(|e| format!(".{e}"))
                        .unwrap_or_default();
                    let out_name = format!("{key}{ext}");

                    let Ok((data, _)) = zip.read(&src) else {
                        continue;
                    };

                    // decode AXML in place, otherwise keep the bytes as-is
                    let contents = if is_axml(&data) {
                        decode_axml(&data, Some(arsc))
                            .map(String::into_bytes)
                            .unwrap_or(data)
                    } else {
                        data
                    };

                    let path = out_dir.join("res").join(&folder).join(&out_name);
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)
                            .with_context(|| format!("can't create res dir {:?}", parent))?;
                    }
                    let mut f = std::fs::File::create(&path)
                        .with_context(|| format!("can't create {:?}", path))?;
                    f.write_all(&contents)
                        .with_context(|| format!("can't write {:?}", path))?;
                }
            }
        }
    }
    Ok(())
}

/// Decodes `resources.arsc` into both `res/values*/...` and the canonical file-
/// resource layout, plus the decoded `AndroidManifest.xml`, driven entirely by the
/// resource table. This is the public entry used for a standalone APK or the base
/// inner APK of a split container.
pub(crate) fn decode_resources(out_dir: &Path, zip: &ZipEntry) -> Result<()> {
    decode_resources_impl(out_dir, zip, true)
}

/// Like [`decode_resources`], but skips `AndroidManifest.xml`. Used for the config
/// splits of a container, whose resource variations are merged into the shared
/// `res` tree without clobbering the base APK's manifest.
pub(crate) fn decode_resources_split(out_dir: &Path, zip: &ZipEntry) -> Result<()> {
    decode_resources_impl(out_dir, zip, false)
}

fn decode_resources_impl(out_dir: &Path, zip: &ZipEntry, with_manifest: bool) -> Result<()> {
    let Ok((data, _)) = zip.read("resources.arsc") else {
        return Ok(());
    };
    let arsc = ARSC::new(&mut &data[..]).context("can't parse resources.arsc")?;

    if let Err(e) = decode_arsc(out_dir, &data) {
        println!("[-] can't decode resources.arsc values - {e}");
    }
    if let Err(e) = decode_files(out_dir, &arsc, zip) {
        println!("[-] can't decode resources.arsc files - {e}");
    }

    // decode AndroidManifest.xml (with reference resolution) into the output root
    if with_manifest
        && let Ok((mdata, _)) = zip.read("AndroidManifest.xml")
        && let Some(xml) = decode_axml(&mdata, Some(&arsc))
    {
        let mpath = out_dir.join("AndroidManifest.xml");
        if let Some(parent) = mpath.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(&mpath, xml.as_bytes()).is_ok() {
            println!("[+] decoded \"AndroidManifest.xml\"");
        }
    }
    Ok(())
}
