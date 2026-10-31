//! Base apk lookup in xapk / apkm containers that don't follow the usual
//! layout. Containers are built at test time around the `universal.apk` of
//! the bundletool fixture.

use std::path::PathBuf;

use apk_info::models::{XAPKManifest, XAPKSplitApk};
use apk_info::{APKError, Apk, ZipEntry, ZipError};

const PACKAGE: &str = "io.github.delvinru.apkstest";

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn base_apk() -> Vec<u8> {
    let apks = ZipEntry::open(fixture("apks-universal.apks")).unwrap();
    apks.read("universal.apk").unwrap().0
}

/// Builds a stored zip archive with the given files.
fn stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central_directory = Vec::new();

    for (name, data) in files {
        let offset = out.len() as u32;
        let crc = crc32(data);

        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&[0u8; 8]); // flags, method, time, date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        central_directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central_directory.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central_directory.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central_directory.extend_from_slice(&[0u8; 8]); // flags, method, time, date
        central_directory.extend_from_slice(&crc.to_le_bytes());
        central_directory.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central_directory.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central_directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central_directory.extend_from_slice(&[0u8; 12]); // extra, comment, disk, attrs
        central_directory.extend_from_slice(&offset.to_le_bytes());
        central_directory.extend_from_slice(name.as_bytes());
    }

    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central_directory);

    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // disk numbers
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central_directory.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                crc >> 1 ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Writes the container to a unique temp file, `Apk::new` takes a path.
fn container(test: &str, files: &[(&str, &[u8])]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("apk-info-{}-{test}.xapk", std::process::id()));
    std::fs::write(&path, stored_zip(files)).unwrap();
    path
}

fn open(test: &str, files: &[(&str, &[u8])]) -> Result<Apk, APKError> {
    let path = container(test, files);
    let apk = Apk::new(&path);
    std::fs::remove_file(path).unwrap();
    apk
}

fn package(test: &str, files: &[(&str, &[u8])]) -> String {
    open(test, files)
        .unwrap_or_else(|err| panic!("{test}: {err}"))
        .get_package_name()
        .unwrap()
}

#[test]
fn xapk_manifest_with_bom() {
    let base = base_apk();
    let manifest = format!("\u{feff}{{\"package_name\": \"{PACKAGE}\"}}");
    let files = [
        ("manifest.json", manifest.as_bytes()),
        (&format!("{PACKAGE}.apk"), &base),
    ];
    assert_eq!(package("bom", &files), PACKAGE);
}

#[test]
fn broken_xapk_manifest_falls_back_to_base_apk() {
    let base = base_apk();
    let files = [("manifest.json", &b"{not json"[..]), ("base.apk", &base)];
    assert_eq!(package("bad-json", &files), PACKAGE);
}

#[test]
fn xapk_base_comes_from_split_apks() {
    let base = base_apk();
    let manifest =
        br#"{"package_name": "x", "split_apks": [{"file": "app-release.apk", "id": "base"}]}"#;
    let files = [("manifest.json", &manifest[..]), ("app-release.apk", &base)];
    assert_eq!(package("split-apks", &files), PACKAGE);
}

#[test]
fn garbage_root_manifest_falls_back_to_base_apk() {
    let base = base_apk();
    let files = [
        ("AndroidManifest.xml", &b"garbage"[..]),
        ("base.apk", &base),
    ];
    assert_eq!(package("decoy-root", &files), PACKAGE);
}

#[test]
fn garbage_root_manifest_without_container_is_an_error() {
    let files = [("AndroidManifest.xml", &b"garbage"[..])];
    assert!(matches!(
        open("broken-apk", &files),
        Err(APKError::ManifestError(_))
    ));
}

#[test]
fn missing_xapk_base_is_reported() {
    let manifest = format!("{{\"package_name\": \"{PACKAGE}\"}}");
    let files = [("manifest.json", manifest.as_bytes())];
    assert!(matches!(
        open("missing-base", &files),
        Err(APKError::ZipError(ZipError::FileNotFound))
    ));
}

#[test]
fn xapk_manifest_is_read_leniently() {
    let manifest = XAPKManifest::from_json(
        br#"{"package_name": 42, "split_apks": [{"file": "a.apk"}, {"file": "b.apk", "id": "base"}, 7]}"#,
    )
    .unwrap();
    assert_eq!(manifest.package_name, None);
    assert_eq!(
        manifest.split_apks[1],
        XAPKSplitApk {
            file: Some("b.apk".to_owned()),
            id: Some("base".to_owned()),
        }
    );
    assert_eq!(manifest.base_apk_names().collect::<Vec<_>>(), ["b.apk"]);

    assert!(XAPKManifest::from_json(b"{not json").is_err());
}
