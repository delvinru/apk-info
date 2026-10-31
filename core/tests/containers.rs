//! Base apk lookup in xapk / apkm containers that don't follow the usual
//! layout. Containers are built at test time around the `universal.apk` of
//! the bundletool fixture.

use std::path::PathBuf;

use apk_info::apk::find_base_apk;
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

#[test]
fn find_base_apk_tells_apk_from_container() {
    let base = base_apk();

    let plain = ZipEntry::new(base.clone()).unwrap();
    assert!(find_base_apk(&plain).unwrap().is_none());

    let container =
        ZipEntry::new(stored_zip(&[("info.json", b"{}"), ("base.apk", &base)])).unwrap();
    let (name, inner) = find_base_apk(&container).unwrap().unwrap();
    assert_eq!(name, "base.apk");
    assert!(inner.contains("AndroidManifest.xml"));
}

#[test]
fn app_bundle_is_reported() {
    let files = [
        ("BundleConfig.pb", &b""[..]),
        ("base/manifest/AndroidManifest.xml", &b""[..]),
    ];
    let Err(APKError::InvalidInput(message)) = open("aab", &files) else {
        panic!("an aab must be rejected with a clear message");
    };
    assert!(message.contains("app bundle"), "{message}");
}

#[test]
fn encrypted_apkm_is_reported() {
    let path = std::env::temp_dir().join(format!("apk-info-{}-encrypted.apkm", std::process::id()));
    std::fs::write(&path, b"\x01\x02 not a zip archive").unwrap();
    let apk = Apk::new(&path);
    std::fs::remove_file(&path).unwrap();

    let Err(APKError::InvalidInput(message)) = apk else {
        panic!("a non-zip apkm must be rejected with a clear message");
    };
    assert!(message.contains("unapkm"), "{message}");
}

#[test]
fn base_apk_is_guessed_by_case_and_directory() {
    let base = base_apk();
    assert_eq!(package("upper", &[("BASE.APK", &base)]), PACKAGE);
    assert_eq!(package("nested", &[("app/base.apk", &base)]), PACKAGE);
    assert_eq!(package("root-apk", &[("app-release.apk", &base)]), PACKAGE);
    assert_eq!(
        package("no-toc", &[("splits/base-master.apk", &base)]),
        PACKAGE
    );
}

#[test]
fn split_is_never_guessed_as_base() {
    let apks = ZipEntry::open(fixture("apks-split.apks")).unwrap();
    let split = apks.read("splits/base-ru.apk").unwrap().0;
    assert!(open("splits-only", &[("config.ru.apk", &split)]).is_err());
}

/// An apk with a broken manifest is not a container: an apk it carries,
/// e.g. a dropper's payload, must not be reported as the app.
#[test]
fn payload_of_a_broken_apk_is_not_guessed() {
    let payload = base_apk();
    let files = [
        ("AndroidManifest.xml", &b"garbage"[..]),
        ("payload.apk", &payload),
        ("assets/base.apk", &payload),
    ];
    assert!(matches!(
        open("dropper", &files),
        Err(APKError::ManifestError(_))
    ));
}
