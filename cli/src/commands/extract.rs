use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use apk_info::FileCompressionType;
use apk_info::apk::{apks_base_apk_name, find_base_apk};
use apk_info::models::XAPKManifest;
use apk_info_zip::ZipEntry;
use colored::Colorize;
use log::warn;
use md5::{Digest, Md5};
use regex::Regex;

use crate::commands::path_helpers::get_all_files;
use crate::commands::resdecode::{decode_resources, decode_resources_split};

/// Maximum length (in bytes) of a single path component on most filesystems.
const MAX_COMPONENT_LEN: usize = 255;

/// Conservative maximum length (in bytes) of the full output path
const MAX_PATH_LEN: usize = 1024;

pub(crate) fn command_extract(
    paths: &[PathBuf],
    output: &Option<PathBuf>,
    files: &[String],
    verbose: bool,
    resources: bool,
    list: bool,
) -> Result<()> {
    let all_files = get_all_files(paths);

    if list {
        let regexes = compile_regexes(files)?;
        for path in all_files {
            if let Err(e) = list_archive(&path, &regexes) {
                println!("[-] can't list {:?} - {}", path, e.to_string().red().bold());
            }
        }
        return Ok(());
    }

    for path in all_files {
        let out_dir = make_output_dir(&path, output);
        if let Err(e) = extract(&path, &out_dir, files, verbose, resources) {
            println!(
                "[-] can't extract {:?} - {}",
                path,
                e.to_string().red().bold()
            );
        }
    }
    Ok(())
}

fn compile_regexes(files: &[String]) -> Result<Vec<Regex>> {
    files
        .iter()
        .map(|file| Regex::new(file).with_context(|| format!("invalid regex: {:?}", file)))
        .collect()
}

/// `--list` mode: prints the archive contents without extracting anything.
///
/// Names are sorted: the central directory is stored in a hash map, so its
/// iteration order is random per process.
fn list_archive(path: &Path, regexes: &[Regex]) -> Result<()> {
    // the archive is opened lazily, without reading the whole file into memory
    let zip = ZipEntry::open(path).with_context(|| format!("can't open file: {:?}", path))?;

    let mut names: Vec<&str> = zip
        .namelist()
        .filter(|name| regexes.is_empty() || regexes.iter().any(|re| re.is_match(name)))
        .collect();
    names.sort_unstable();

    println!(
        "[*] listing {} entries of \"{}\"",
        names.len(),
        path.display()
    );
    println!("{:>10}  {:<12}{:>10}  name", "size", "method", "csize");

    for name in &names {
        let Some(info) = zip.entry_info(name) else {
            println!("[-] can't read entry metadata of {:?}", name);
            continue;
        };

        let mut method = match info.compression_method {
            ZipEntry::METHOD_STORED => "Stored".to_string(),
            ZipEntry::METHOD_DEFLATED => "Deflate".to_string(),
            other => format!("Other({other})"),
        };
        if info.tampered {
            method.push('!');
        }

        let row = format!(
            "{:>10}  {:<12}{:>10}  {}",
            info.uncompressed_size, method, info.compressed_size, name
        );
        if info.tampered {
            println!("{}", row.red());
        } else {
            println!("{row}");
        }
    }

    Ok(())
}

fn make_output_dir(path: &Path, output: &Option<PathBuf>) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|n| {
            let mut s = n.to_os_string();
            s.push(".unp");
            s
        })
        .unwrap_or_else(|| "unknown.unp".into());

    match output {
        Some(out) => {
            // ./<output>/<file_name>.unp
            let mut p = PathBuf::from(out);
            p.push(file_name);
            p
        }
        None => {
            // ./<file_name>.unp
            PathBuf::from(file_name)
        }
    }
}

/// Whether `name` stays inside `out_dir` once joined. Rejects `..` in any
/// segment, an absolute root, a Windows drive, or a NUL. Both `/` and `\` count
/// as separators so a crafted name can't escape on Windows either.
fn is_safe_relative_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    // unix root, windows drive-relative `\`, or a UNC `\\server` share
    if name.starts_with('/') || name.starts_with('\\') {
        return false;
    }
    name.split(['/', '\\']).all(|segment| match segment {
        // empty segments come from interior/trailing separators; they stay put
        "" | "." => true,
        ".." => false,
        // `:` marks a windows drive or an alternate data stream
        _ => !segment.contains([':', '\0']),
    })
}

/// Resolves where an entry should be written inside `out_dir`.
///
/// Returns `None` for traversal or directory entries that must never be written.
/// Returns `Some((path, renamed))`, where `renamed` is `true` when the original
/// name was a malicious/broken path (a component or the full path is too long for
/// the filesystem) designed to break extraction tools - in that case the data is
/// saved under an md5 hash of the original name.
fn resolve_output_path(out_dir: &Path, file_name: &str) -> Option<(PathBuf, bool)> {
    if file_name.ends_with('/') || !is_safe_relative_name(file_name) {
        return None;
    }

    let direct = out_dir.join(file_name);
    let too_long = file_name.split('/').any(|c| c.len() > MAX_COMPONENT_LEN)
        || direct.as_os_str().len() > MAX_PATH_LEN;

    if too_long {
        let mut hasher = Md5::new();
        hasher.update(file_name.as_bytes());
        let hash = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        eprintln!(
            "[-] malicious/broken filename (too long for the filesystem) - saving \"{}\" as \"{}\"",
            file_name.yellow(),
            hash.bold()
        );
        Some((out_dir.join(hash), true))
    } else {
        Some((direct, false))
    }
}

/// The entry name as a relative path: empty and `.` components dropped, so
/// `/a//b` is `a/b`. `None` for a directory entry or a name that could leave
/// the output directory.
fn normalized_name(name: &str) -> Option<String> {
    if name.ends_with('/') {
        return None;
    }
    let normalized = name
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect::<Vec<_>>()
        .join("/");
    is_safe_relative_name(&normalized).then_some(normalized)
}

/// `stem~n.ext` for the `n`-th entry that wants the same file name.
fn numbered(name: &str, n: usize) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem}~{n}.{ext}"),
        _ => format!("{name}~{n}"),
    }
}

/// A distinct path on disk for every entry Android tells apart.
///
/// Android finds entries by exact name, but on disk `a//b` and `a/b` are one
/// file, and `classes.dex` can't be both a file and the directory of
/// `classes.dex/x`. The file keeps its name and the directory becomes
/// `classes.dex.dir`; a second entry on one path becomes `name~2.ext`. An
/// entry whose name is already a plain path keeps it. Unsafe names are absent.
fn disk_names<'a>(names: &[&'a str]) -> HashMap<&'a str, String> {
    let normalized: Vec<(&str, String)> = names
        .iter()
        .filter_map(|&name| normalized_name(name).map(|path| (name, path)))
        .collect();

    let files: HashSet<&str> = normalized.iter().map(|(_, path)| path.as_str()).collect();
    // every path an entry uses, as a file or a directory
    let mut taken: HashSet<String> = HashSet::new();
    for (_, path) in &normalized {
        taken.extend(
            path.match_indices('/')
                .map(|(end, _)| path[..end].to_owned()),
        );
        taken.insert(path.clone());
    }

    // plain names first, so they keep their path; the sort is stable
    let mut order: Vec<&(&str, String)> = normalized.iter().collect();
    order.sort_by_key(|(name, path)| name != path);

    let mut renamed_dirs: HashMap<&str, String> = HashMap::new();
    let mut used: HashSet<String> = HashSet::new();
    let mut out = HashMap::with_capacity(order.len());
    for (name, path) in order {
        // the mapped directory so far, ending with `/` once it has one
        let mut mapped = String::with_capacity(path.len() + 4);
        let mut start = 0;
        for (end, _) in path.match_indices('/') {
            let dir = &path[..end];
            let component = &path[start..end];
            start = end + 1;
            if files.contains(dir) {
                let renamed = renamed_dirs.entry(dir).or_insert_with(|| {
                    let new = (1..)
                        .map(|n| match n {
                            1 => format!("{mapped}{component}.dir"),
                            n => format!("{mapped}{component}.dir{n}"),
                        })
                        .find(|candidate| !taken.contains(candidate))
                        .expect("an unused name exists");
                    taken.insert(new.clone());
                    new
                });
                mapped.clone_from(renamed);
            } else {
                mapped.push_str(component);
            }
            mapped.push('/');
        }

        let file = &path[start..];
        let mut target = format!("{mapped}{file}");
        if used.contains(&target) {
            target = (2..)
                .map(|n| format!("{mapped}{}", numbered(file, n)))
                .find(|candidate| !used.contains(candidate) && !taken.contains(candidate))
                .expect("an unused name exists");
            taken.insert(target.clone());
        }
        used.insert(target.clone());
        out.insert(*name, target);
    }
    out
}

/// Enumerates the config/other split inner APKs of a `xapk`/`apkm`/`apks` container
/// (everything that is *not* the base).
///
/// Each carries its own `resources.arsc` with locale/configuration string variations that complement the base's.
fn container_split_apks(zip: &ZipEntry, base: &str) -> Vec<(String, ZipEntry)> {
    let mut names: BTreeSet<String> = BTreeSet::new();

    // xapk: manifest.json split_apks -> file names (skip the id == "base" module)
    if let Ok((m, _)) = zip.read("manifest.json")
        && let Ok(manifest) = XAPKManifest::from_json(&m)
    {
        for split in manifest.split_apks {
            if let (Some(file), Some(id)) = (split.file, split.id)
                && file.ends_with(".apk")
                && !id.is_empty()
                && id != "base"
            {
                names.insert(file);
            }
        }
    }

    // apks: the splits of the base's variant; bundletool names the splits
    // of further sdk variants with a `_<n>` suffix (`base-ru_2.apk`)
    if let Some(base) = apks_base_apk_name(zip)
        && let Some(dir) = apks_splits_dir(&base)
    {
        let all: BTreeSet<&str> = zip.namelist().collect();
        for &name in &all {
            if name.starts_with(dir)
                && name.ends_with(".apk")
                && name != base
                && !is_apks_variant_copy(name, &all)
            {
                names.insert(name.to_string());
            }
        }
    }

    // heuristic fallback (apkm / manifestless containers): config.*/split_* APKs
    for name in zip.namelist() {
        if name.ends_with(".apk") && (name.starts_with("config.") || name.starts_with("split_")) {
            names.insert(name.to_string());
        }
    }

    names.remove(base);

    names
        .into_iter()
        .filter_map(|name| {
            zip.read(&name)
                .ok()
                .and_then(|(d, _)| ZipEntry::new(d).ok())
                .map(|inner| (name, inner))
        })
        .collect()
}

/// Directory holding the splits that complement an apks base: `system` mode
/// keeps its language and feature splits in `splits/` next to `system/system.apk`.
fn apks_splits_dir(base: &str) -> Option<&'static str> {
    match base {
        "splits/base-master.apk" | "system/system.apk" => Some("splits/"),
        "instant/instant-base-master.apk" => Some("instant/"),
        _ => None,
    }
}

/// Checks whether an apks split is the `_<n>` copy of another entry for a further
/// sdk variant, e.g. `splits/base-ru_2.apk` next to `splits/base-ru.apk`.
///
/// The unsuffixed entry must exist, and the `_64` of `x86_64` is part of the
/// abi, not a variant: `splits/base-x86_64.apk` sits next to `splits/base-x86.apk`.
fn is_apks_variant_copy(name: &str, names: &BTreeSet<&str>) -> bool {
    name.strip_suffix(".apk")
        .filter(|stem| !stem.ends_with("-x86_64"))
        .and_then(|stem| stem.rsplit_once('_'))
        .is_some_and(|(stem, n)| {
            !n.is_empty()
                && n.bytes().all(|b| b.is_ascii_digit())
                && names.contains(format!("{stem}.apk").as_str())
        })
}

fn write_bytes(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        println!(
            "[-] can't create parent dirs for {:?} - {}",
            path,
            e.to_string().red()
        );
        return Ok(());
    }

    let mut f = match std::fs::File::create(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::IsADirectory => {
            println!("[-] can't create file {:?} - occupied by a directory", path);
            return Ok(());
        }
        Err(e) => return Err(e).with_context(|| format!("can't create file {:?}", path)),
    };
    f.write_all(contents)
        .with_context(|| format!("can't write to {:?}", path))
}

/// `resources` toggles apktool-style decoding: the manifest, binary XML resources
/// and `resources.arsc` are decoded arsc-driven (see [`decode_resources`]); every
/// non-resource entry (dex, libs, assets, ...) is still copied as-is.
fn extract(
    path: &PathBuf,
    out_dir: &PathBuf,
    files: &[String],
    verbose: bool,
    resources: bool,
) -> Result<()> {
    // the archive is opened lazily, without reading the whole file into memory
    let zip = ZipEntry::open(path).with_context(|| format!("can't open file: {:?}", path))?;

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("can't create output directory {:?}", out_dir))?;

    let regexes = compile_regexes(files)?;

    // the same base apk `show` uses; the outer archive of a container has
    // no resources of its own to decode
    let base = if resources {
        match find_base_apk(&zip) {
            Ok(None) => {
                if let Err(e) = decode_resources(out_dir, &zip) {
                    println!("[-] can't decode resources - {}", e.to_string().red());
                }
                None
            }
            Ok(Some(base)) => Some(base),
            Err(e) => {
                println!("[-] can't decode resources - {}", e.to_string().red());
                None
            }
        }
    } else {
        None
    };

    let names: Vec<&str> = zip.namelist().collect();
    let disk = disk_names(&names);
    let mut moved = 0usize;

    for file_name in names {
        if !regexes.is_empty() && !regexes.iter().any(|re| re.is_match(file_name)) {
            continue;
        }

        let Some(out_name) = disk.get(file_name).map(String::as_str) else {
            warn!("got bad filename: {:?}, skipped", file_name);
            continue;
        };
        let Some((file_path, renamed)) = resolve_output_path(out_dir, out_name) else {
            warn!("got bad filename: {:?}, skipped", file_name);
            continue;
        };

        if resources
            && (file_name == "AndroidManifest.xml"
                || file_name == "resources.arsc"
                || file_name.starts_with("res/"))
        {
            continue;
        }

        let (data, compression) = match zip.read(file_name) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "[-] can't extract file from archive - {:?} - {}",
                    file_name,
                    e.to_string().red().bold(),
                );
                continue;
            }
        };

        write_bytes(&file_path, &data)?;
        moved += usize::from(out_name != file_name);

        // show interesting files (native libs) and tampered entries
        let display_name = if renamed {
            file_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
        } else {
            None
        };
        let shown = display_name.as_deref().unwrap_or(file_name);

        let is_tampered = matches!(
            compression,
            FileCompressionType::StoredTampered | FileCompressionType::DeflatedTampered
        );
        if verbose || is_tampered || file_name.ends_with(".so") {
            if file_name.ends_with(".so") {
                print!("[*] extracted \"{}\" ", shown.magenta().bold());
            } else {
                print!("[~] extracted \"{}\" ", shown);
            }
            if is_tampered {
                println!("({})", format!("{:?}", compression).bold().red());
            } else {
                println!("({:?})", compression);
            }
        }
    }

    if moved != 0 {
        println!(
            "[~] {moved} entries share a path on disk with another one or aren't a plain path, saved under another name"
        );
    }

    if let Some((base_name, inner)) = base {
        println!("[*] decoding resources of the base inner apk \"{base_name}\"");
        if let Err(e) = decode_resources(out_dir, &inner) {
            println!("[-] can't decode inner resources - {}", e.to_string().red());
        }
        for (name, split) in container_split_apks(&zip, &base_name) {
            println!("[*] decoding resources of split apk \"{name}\"");
            if let Err(e) = decode_resources_split(out_dir, &split) {
                println!(
                    "[-] can't decode split \"{name}\" resources - {}",
                    e.to_string().red()
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Entries saved under a path other than their name.
    fn mapped(names: &[&str]) -> Vec<(String, String)> {
        let mut out: Vec<_> = disk_names(names)
            .into_iter()
            .filter(|(name, path)| name != path)
            .map(|(name, path)| (name.to_owned(), path))
            .collect();
        out.sort();
        out
    }

    fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
        expected
            .iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }

    #[test]
    fn ordinary_archive_has_no_conflicts() {
        assert!(mapped(&["AndroidManifest.xml", "classes.dex", "res/a.xml", "res/"]).is_empty());
    }

    #[test]
    fn file_wins_over_a_directory_of_the_same_name() {
        // the directory entries come first, as in the sample that lost its dex
        let names = [
            "classes.dex/a.xml",
            "classes.dex/b/c.png",
            "classes.dex",
            "x.txt",
        ];
        assert_eq!(
            mapped(&names),
            pairs(&[
                ("classes.dex/a.xml", "classes.dex.dir/a.xml"),
                ("classes.dex/b/c.png", "classes.dex.dir/b/c.png"),
            ])
        );
        // the order of the entries doesn't matter
        let reversed: Vec<&str> = names.iter().rev().copied().collect();
        assert_eq!(mapped(&reversed), mapped(&names));
    }

    #[test]
    fn nested_conflicts_are_all_resolved() {
        assert_eq!(
            mapped(&["a", "a/b", "a/b/c"]),
            pairs(&[("a/b", "a.dir/b"), ("a/b/c", "a.dir/b.dir/c")])
        );
    }

    #[test]
    fn taken_dir_name_is_skipped() {
        assert_eq!(
            mapped(&["a", "a/x", "a.dir", "a.dir2/y"]),
            pairs(&[("a/x", "a.dir3/x")])
        );
    }

    #[test]
    fn names_that_collapse_to_one_path_get_numbered() {
        // the plain name keeps the path even when it comes last
        let names = ["a//x.xml", "/a/x.xml", "a/./x.xml", "a/x.xml"];
        assert_eq!(
            mapped(&names),
            pairs(&[
                ("/a/x.xml", "a/x~3.xml"),
                ("a/./x.xml", "a/x~4.xml"),
                ("a//x.xml", "a/x~2.xml"),
            ])
        );
        assert_eq!(disk_names(&names)["a/x.xml"], "a/x.xml");
    }

    #[test]
    fn absolute_name_is_saved_relative() {
        assert_eq!(
            mapped(&["/etc/x.png"]),
            pairs(&[("/etc/x.png", "etc/x.png")])
        );
    }

    #[test]
    fn unsafe_and_directory_names_are_left_out() {
        let names = ["../x", "a/../../x", "C:x", "res/", "//", "ok"];
        let disk = disk_names(&names);
        assert_eq!(disk.len(), 1);
        assert_eq!(disk["ok"], "ok");
    }

    #[test]
    fn every_entry_gets_its_own_path() {
        let names = [
            "classes.dex/a",
            "classes.dex",
            "classes.dex//a",
            "/classes.dex/a",
            "a",
            "a~2",
            "a/b",
            "a.dir",
            "a.dir/c",
        ];
        let disk = disk_names(&names);
        let paths: HashSet<&String> = disk.values().collect();
        assert_eq!(disk.len(), names.len());
        assert_eq!(paths.len(), names.len(), "{disk:?}");
        // no path is the directory of another one
        for path in &paths {
            assert!(
                !paths
                    .iter()
                    .any(|other| other.starts_with(&format!("{path}/"))),
                "{path}"
            );
        }
    }

    #[test]
    fn apks_splits_dir_follows_the_base() {
        assert_eq!(apks_splits_dir("splits/base-master.apk"), Some("splits/"));
        assert_eq!(apks_splits_dir("system/system.apk"), Some("splits/"));
        assert_eq!(
            apks_splits_dir("instant/instant-base-master.apk"),
            Some("instant/")
        );
        assert_eq!(apks_splits_dir("universal.apk"), None);
        assert_eq!(apks_splits_dir("standalones/standalone-x86_64.apk"), None);
    }

    #[test]
    fn apks_variant_copies_are_detected() {
        let names: BTreeSet<&str> = [
            "splits/base-master.apk",
            "splits/base-master_2.apk",
            "splits/base-ru.apk",
            "splits/base-ru_2.apk",
            "splits/base-x86.apk",
            "splits/base-x86_2.apk",
            "splits/base-x86_64.apk",
            "splits/base-x86_64_2.apk",
        ]
        .into_iter()
        .collect();

        for copy in [
            "splits/base-master_2.apk",
            "splits/base-ru_2.apk",
            "splits/base-x86_2.apk",
            "splits/base-x86_64_2.apk",
        ] {
            assert!(is_apks_variant_copy(copy, &names), "{copy:?}");
        }
        for split in [
            "splits/base-ru.apk",
            "splits/base-x86.apk",
            "splits/base-x86_64.apk",
        ] {
            assert!(!is_apks_variant_copy(split, &names), "{split:?}");
        }
    }

    #[test]
    fn rejects_path_traversal() {
        let out = Path::new("/tmp/out");
        for name in [
            "../evil",
            "assets/../../etc/passwd",
            "a/../../b",
            "/etc/passwd",
            "\\windows\\system32",
            "..\\..\\evil",
            "C:\\evil",
            "res/../../x",
            "foo/..",
        ] {
            assert!(
                resolve_output_path(out, name).is_none(),
                "{name} must be rejected"
            );
        }
    }

    #[test]
    fn accepts_ordinary_names() {
        let out = Path::new("/tmp/out");
        for name in ["res/layout/main.xml", "classes.dex", "..foo", "a.b..c"] {
            let (path, renamed) =
                resolve_output_path(out, name).unwrap_or_else(|| panic!("{name} must be accepted"));
            assert!(!renamed, "{name} should not be renamed");
            assert!(path.starts_with(out), "{name} escaped out_dir");
        }
    }

    #[test]
    fn directory_entries_are_skipped() {
        assert!(resolve_output_path(Path::new("/tmp/out"), "res/").is_none());
    }

    #[test]
    fn overlong_name_is_hashed_but_stays_inside() {
        let out = Path::new("/tmp/out");
        let long = format!("dir/{}", "a".repeat(MAX_COMPONENT_LEN + 1));
        let (path, renamed) = resolve_output_path(out, &long).expect("overlong name is kept");
        assert!(renamed, "overlong name must be saved under a hash");
        assert!(path.starts_with(out));
    }
}
