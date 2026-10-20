//! Regression tests for BadPack-style zip evasions. Each fixture is a benign
//! signed APK carrying one technique that a real device (adb, API 34) installs
//! and runs, so our reader must extract what Android does.

use apk_info_zip::ZipEntry;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Binary `AndroidManifest.xml` opens with a `RES_XML_TYPE` chunk: type `0x0003`
/// and header size `0x0008`, little-endian.
const AXML_MAGIC: &[u8; 4] = &[0x03, 0x00, 0x08, 0x00];

/// A `PK\x05\x06` planted in the archive comment must not win over the real
/// EOCD; a reader that takes the rightmost raw match fails to open the archive.
#[test]
fn fake_eocd_in_comment_does_not_break_open() {
    let zip = ZipEntry::open(fixture("badpack-fake-eocd-in-comment.apk"))
        .expect("archive with a planted EOCD signature must still open");

    let (manifest, _) = zip
        .read("AndroidManifest.xml")
        .expect("manifest must be readable");
    assert_eq!(
        &manifest[..4],
        AXML_MAGIC,
        "expected real binary manifest, got {:02x?}",
        &manifest[..manifest.len().min(4)]
    );
}

/// A decoy record appended past `num_records` reuses the manifest's name; a
/// reader that walks the directory to EOF lets it shadow the real entry.
#[test]
fn decoy_cd_record_does_not_shadow_manifest() {
    let zip = ZipEntry::open(fixture("badpack-decoy-cd-record.apk"))
        .expect("archive with a trailing decoy record must open");

    let (manifest, _) = zip
        .read("AndroidManifest.xml")
        .expect("manifest must be readable");

    assert_eq!(
        &manifest[..4],
        AXML_MAGIC,
        "decoy record shadowed the real manifest: {:02x?}",
        &manifest[..manifest.len().min(4)]
    );
    assert_ne!(
        manifest, b"DECOY-MANIFEST-BYTES",
        "read returned the decoy payload"
    );
}
