use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use apk_info_axml::structs::{ResTableEntry, ResTableTypeEntries};
use apk_info_axml::{ARSC, AXML};
use apk_info_xml::Element;
use apk_info_zip::ZipEntry;

/// Types in id order: hash map order changes between runs.
fn types_in_order(type_map: &HashMap<u8, ResTableTypeEntries>) -> Vec<(u8, &ResTableTypeEntries)> {
    let mut types: Vec<_> = type_map
        .iter()
        .map(|(&id, entries)| (id, entries))
        .collect();
    types.sort_unstable_by_key(|&(id, _)| id);
    types
}

fn entry_ids(entries: &ResTableTypeEntries) -> impl Iterator<Item = (u16, &ResTableEntry)> {
    entries.entries.iter().enumerate().map(|(position, entry)| {
        let id = entries
            .entry_ids
            .as_ref()
            .and_then(|ids| ids.get(position).copied())
            .unwrap_or(position as u16);
        (id, entry)
    })
}

/// The values file of a resource type.
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

#[inline]
fn scalar_value(arsc: &ARSC, entry: &ResTableEntry) -> Option<String> {
    match entry {
        ResTableEntry::Default(e) => Some(arsc.value_to_string(&e.value)),
        _ => None,
    }
}

/// Plural quantity from its map id, `0x01000004 + rule`.
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

/// Writes `res/values*/` from `resources.arsc`.
pub(crate) fn decode_arsc(out_dir: &Path, bytes: &[u8]) -> Result<()> {
    let arsc = ARSC::new(&mut &bytes[..]).context("can't parse resources.arsc")?;

    // folder -> file -> elements
    let mut files: BTreeMap<String, BTreeMap<String, Vec<Element>>> = BTreeMap::new();

    for pkg in arsc.packages() {
        for (config, type_map) in &pkg.resources {
            let qualifier = config.as_string();
            let folder = if qualifier.is_empty() {
                "values".to_string()
            } else {
                format!("values-{qualifier}")
            };
            let file_map = files.entry(folder).or_default();

            for (type_id, entries) in types_in_order(type_map) {
                for entry in &entries.entries {
                    if matches!(entry, ResTableEntry::NoEntry) {
                        continue;
                    }

                    let Some(full_name) = pkg.get_entry_full_name(entry, type_id) else {
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

    let res_dir = out_dir.join("res");
    for (folder, file_map) in files {
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

#[inline]
fn is_axml(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 3 && data[1] == 0 && data[2] == 8 && data[3] == 0
}

fn decode_axml(data: &[u8], arsc: Option<&ARSC>) -> Option<String> {
    let axml = AXML::new(&mut &data[..], arsc).ok()?;
    Some(axml.get_xml_string())
}

/// Longest type or key name used as is; leaves room for an id suffix and an
/// extension within the 255-byte limit of a file name.
const MAX_NAME_LEN: usize = 200;

/// Whether a name from the table can be one path component of the output.
fn is_safe_component(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', ':', '\0'])
}

/// Folder and file stem of a file resource: `res/<type><qualifier>/<key>`.
///
/// Both names come from the table: an unsafe one, which could write outside
/// the output directory, is replaced by the type or resource id.
fn resource_file_names(
    type_name: &str,
    qualifier: &str,
    key: &str,
    type_id: u8,
    id: u32,
) -> (String, String, bool) {
    let safe_type = is_safe_component(type_name);
    let safe_key = is_safe_component(key);
    let folder = if safe_type {
        format!("{type_name}{qualifier}")
    } else {
        format!("0x{type_id:02x}{qualifier}")
    };
    let stem = if safe_key {
        key.to_owned()
    } else {
        format!("0x{id:08x}")
    };
    (folder, stem, !(safe_type && safe_key))
}

/// Writes file resources to `res/<type>[-<config>]/`, as apktool does.
pub(crate) fn decode_files(out_dir: &Path, arsc: &ARSC, zip: &ZipEntry) -> Result<()> {
    // obfuscated tables reuse names: later duplicates get their resource id
    let mut written: HashSet<PathBuf> = HashSet::new();
    let mut renamed = 0usize;
    let mut sanitized = 0usize;

    for pkg in arsc.packages() {
        for (config, type_map) in &pkg.resources {
            let qualifier = config.as_string();
            let folder_pfx = if qualifier.is_empty() {
                String::new()
            } else {
                format!("-{qualifier}")
            };

            for (type_id, entries) in types_in_order(type_map) {
                for (entry_id, entry) in entry_ids(entries) {
                    if matches!(entry, ResTableEntry::NoEntry) {
                        continue;
                    }
                    let Some(full_name) = pkg.get_entry_full_name(entry, type_id) else {
                        continue;
                    };
                    let Some((type_name, key)) = full_name.split_once('/') else {
                        continue;
                    };
                    let ResTableEntry::Default(e) = entry else {
                        continue;
                    };
                    let src = arsc.value_to_string(&e.value);
                    if !src.starts_with("res/") {
                        continue;
                    }

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
                    let Ok((data, _)) = zip.read(&src) else {
                        continue;
                    };

                    let contents = if is_axml(&data) {
                        decode_axml(&data, Some(arsc))
                            .map(String::into_bytes)
                            .unwrap_or(data)
                    } else {
                        data
                    };

                    let id =
                        (pkg.header.id << 24) | (u32::from(type_id) << 16) | u32::from(entry_id);
                    let (folder, stem, unsafe_name) =
                        resource_file_names(type_name, &folder_pfx, key, type_id, id);
                    sanitized += usize::from(unsafe_name);
                    let dir = out_dir.join("res").join(folder);
                    let mut path = dir.join(format!("{stem}{ext}"));
                    if !written.insert(path.clone()) {
                        path = dir.join(format!("{stem}_0x{id:08x}{ext}"));
                        written.insert(path.clone());
                        renamed += 1;
                    }
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

    if sanitized != 0 {
        println!(
            "[!] {sanitized} file resources have a type or name unsafe for a path, saved by id"
        );
    }
    if renamed != 0 {
        println!(
            "[~] {renamed} file resources share a name with another one, saved with their resource id appended"
        );
    }
    Ok(())
}

/// Decodes the manifest and resources of an apk or a container's base.
pub(crate) fn decode_resources(out_dir: &Path, zip: &ZipEntry) -> Result<()> {
    decode_resources_impl(out_dir, zip, true)
}

/// [`decode_resources`] without the manifest, for splits.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(ids: Option<Vec<u16>>, len: usize) -> ResTableTypeEntries {
        ResTableTypeEntries {
            entry_ids: ids,
            entries: (0..len).map(|_| ResTableEntry::NoEntry).collect(),
        }
    }

    /// Whatever the table holds, the result is two plain components that stay
    /// inside `res/`.
    #[test]
    fn unsafe_resource_names_stay_inside_res() {
        let hostile = [
            "..",
            ".",
            "",
            "../../../../tmp/evil",
            "/etc/passwd",
            "a/../../b",
            "..\\..\\evil",
            "C:evil",
            "nul\0byte",
            &"a".repeat(300),
        ];
        for name in hostile {
            for (type_name, key) in [(name, "icon"), ("drawable", name), (name, name)] {
                let (folder, stem, sanitized) =
                    resource_file_names(type_name, "-mdpi", key, 0x02, 0x7f02_0001);
                assert!(sanitized, "{type_name:?}/{key:?}");
                let path = Path::new("res").join(&folder).join(format!("{stem}.png"));
                let components: Vec<_> = path.components().collect();
                assert_eq!(components.len(), 3, "{path:?}");
                assert!(
                    components
                        .iter()
                        .all(|c| matches!(c, std::path::Component::Normal(_))),
                    "{path:?}"
                );
                assert!(folder.len() <= 255 && stem.len() + 4 <= 255);
            }
        }
    }

    #[test]
    fn safe_resource_names_are_kept() {
        assert_eq!(
            resource_file_names("drawable", "-mdpi", "ic_launcher", 0x02, 0x7f02_0001),
            ("drawable-mdpi".to_owned(), "ic_launcher".to_owned(), false)
        );
        // an obfuscated name is unusual but harmless
        assert_eq!(
            resource_file_names("ㅤㅤ", "", "ㅤ.9", 0x02, 0x7f02_0001),
            ("ㅤㅤ".to_owned(), "ㅤ.9".to_owned(), false)
        );
        assert_eq!(
            resource_file_names("..", "", "../x", 0x02, 0x7f02_0001),
            ("0x02".to_owned(), "0x7f020001".to_owned(), true)
        );
    }

    #[test]
    fn types_come_in_id_order() {
        let map: HashMap<u8, ResTableTypeEntries> =
            (1..=50).rev().map(|id| (id, entries(None, 0))).collect();
        let ids: Vec<u8> = types_in_order(&map).into_iter().map(|(id, _)| id).collect();
        assert_eq!(ids, (1..=50).collect::<Vec<_>>());
    }

    #[test]
    fn entry_ids_follow_sparse_tables() {
        let dense = entries(None, 3);
        let ids: Vec<u16> = entry_ids(&dense).map(|(id, _)| id).collect();
        assert_eq!(ids, [0, 1, 2]);

        let sparse = entries(Some(vec![2, 7, 40]), 3);
        let ids: Vec<u16> = entry_ids(&sparse).map(|(id, _)| id).collect();
        assert_eq!(ids, [2, 7, 40]);
    }
}
