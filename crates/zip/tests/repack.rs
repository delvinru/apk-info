//! Integration tests for [`ZipEntry::repack`], run against the golden APK
//! fixtures from the AOSP `apksig` project (Apache License 2.0,
//! Copyright (C) The Android Open Source Project).
//!
//! `repack` produces a fresh unsigned archive; the contract under test is
//! that our own reader can re-parse it and that every entry roundtrips
//! byte-for-byte, preserving the central directory order.

use apk_info_zip::ZipEntry;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Repacking a real APK must preserve its entry list (order included) and
/// every entry's content. The signing block is intentionally dropped: a
/// repacked archive is unsigned.
#[test]
fn repacked_fixture_roundtrips_through_own_reader() {
    for name in [
        "v2-only-with-rsa-pkcs1-sha256-2048.apk",
        "broken-v1v2v3-with-rsa-2048-lineage-3-signers-no-sig-block.apk",
        "stamp-1-v31-tgt-33-signer.apk",
    ] {
        let original = ZipEntry::open(fixture(name))
            .unwrap_or_else(|e| panic!("{name}: failed to parse fixture: {e:?}"));

        // repack skips directory entries; the expected list must too
        let expected: Vec<String> = original
            .namelist()
            .filter(|n| !n.ends_with('/'))
            .map(str::to_owned)
            .collect();
        assert!(!expected.is_empty(), "{name}: fixture must have entries");

        let repacked = original
            .repack()
            .unwrap_or_else(|e| panic!("{name}: repack failed: {e:?}"));
        let reparsed = ZipEntry::new(repacked)
            .unwrap_or_else(|e| panic!("{name}: repacked archive failed to re-parse: {e:?}"));

        assert_eq!(
            reparsed.namelist().collect::<Vec<_>>(),
            expected,
            "{name}: repacked namelist differs"
        );

        for entry in &expected {
            let original_data = original
                .read(entry)
                .unwrap_or_else(|e| panic!("{name}: reading {entry} from original: {e:?}"))
                .0;
            let repacked_data = reparsed
                .read(entry)
                .unwrap_or_else(|e| panic!("{name}: reading {entry} from repacked: {e:?}"))
                .0;
            assert_eq!(
                original_data, repacked_data,
                "{name}: entry {entry} did not roundtrip"
            );
        }
    }
}

/// The repacked archive is unsigned: neither a JAR signature in `META-INF/`
/// nor an `APK Sig Block 42` before the central directory survives.
#[test]
fn repacked_fixture_is_unsigned() {
    let original = ZipEntry::open(fixture("v2-only-with-rsa-pkcs1-sha256-2048.apk")).unwrap();
    let repacked = original.repack().unwrap();
    let reparsed = ZipEntry::new(repacked).unwrap();

    assert!(matches!(
        reparsed.get_signature_v1(),
        Ok(apk_info_zip::Signature::Unknown)
    ));
    assert!(reparsed.get_signatures_other().unwrap().is_empty());
}
