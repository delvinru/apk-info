//! Structural anomaly reports, one defect per fixture.
//!
//! The fixtures in `tests/fixtures/anomalies` are built by
//! `tests/fixtures/build-anomaly-fixtures.py` from the AOSP tinyapp; each one
//! carries a single change to the zip headers, the manifest or the resource
//! table.

use apk_info::{Anomaly, AnomalyKind, Apk, Severity};

fn fixture(name: &str) -> String {
    format!(
        "{}/tests/fixtures/anomalies/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn anomalies(name: &str) -> Vec<Anomaly> {
    Apk::new(fixture(name))
        .unwrap_or_else(|err| panic!("{name} must open: {err}"))
        .anomalies()
}

/// Asserts the exact anomaly codes of a fixture, in order, and its verdict.
fn check(name: &str, codes: &[&str], tampered: bool) {
    let apk = Apk::new(fixture(name)).unwrap_or_else(|err| panic!("{name} must open: {err}"));
    let found = apk.anomalies();
    let found_codes: Vec<&str> = found.iter().map(Anomaly::code).collect();

    assert_eq!(found_codes, codes, "{name}: {found:#?}");
    assert_eq!(apk.is_tampered(), tampered, "{name}: {found:#?}");
}

#[test]
fn clean_apk_has_no_anomalies() {
    check("clean.apk", &[], false);
}

#[test]
fn zip_tampering_is_reported() {
    for (name, code) in [
        (
            "zip-compression-method-mismatch.apk",
            "compression_method_mismatch",
        ),
        (
            "zip-unknown-compression-method.apk",
            "unknown_compression_method",
        ),
        ("zip-stored-size-mismatch.apk", "stored_size_mismatch"),
        ("zip-encryption-flag.apk", "encryption_flag"),
        ("zip-entry-path-conflict.apk", "entry_path_conflict"),
        ("zip-invalid-utf8-name.apk", "invalid_utf8_name"),
        ("zip-duplicate-entry.apk", "duplicate_entry"),
        (
            "zip-extra-central-directory-record.apk",
            "extra_central_directory_records",
        ),
        ("zip-fake-eocd-in-comment.apk", "fake_eocd_in_comment"),
    ] {
        check(name, &[code], true);
    }
}

#[test]
fn zip_damage_is_suspicious() {
    for (name, code) in [
        ("zip-local-header-shifted.apk", "local_header_shifted"),
        ("zip-local-header-missing.apk", "local_header_missing"),
        (
            "zip-missing-central-directory-record.apk",
            "missing_central_directory_records",
        ),
        ("zip-eocd-not-at-end.apk", "eocd_not_at_end"),
        (
            "zip-central-directory-shifted.apk",
            "central_directory_shifted",
        ),
    ] {
        check(name, &[code], false);
    }
}

#[test]
fn manifest_tampering_is_reported() {
    check(
        "manifest-attribute-layout.apk",
        &["attribute_start_shifted", "attribute_size_mismatch"],
        true,
    );
    for (name, code) in [
        (
            "manifest-invalid-attribute-name.apk",
            "invalid_attribute_name",
        ),
        ("manifest-invalid-element-name.apk", "invalid_element_name"),
        (
            "manifest-string-count-mismatch.apk",
            "string_count_mismatch",
        ),
        ("manifest-xml-node-header-size.apk", "xml_node_header_size"),
        (
            "manifest-element-trailing-bytes.apk",
            "element_trailing_bytes",
        ),
        // three garbage chunks in a row are one anomaly
        ("manifest-non-xml-chunk.apk", "non_xml_chunk"),
    ] {
        check(name, &[code], true);
    }
}

#[test]
fn manifest_damage_is_suspicious() {
    check(
        "manifest-unclosed-elements.apk",
        &["unclosed_elements"],
        false,
    );
    check(
        "manifest-truncated.apk",
        &["truncated_xml", "unclosed_elements"],
        false,
    );
}

/// `android:name` as plain text, with no namespace and no resource id, next
/// to the real attribute: a protector trick seen in clean apps. Android
/// ignores it, so does the parser, and it rates below tampering.
#[test]
fn decoy_attribute_name_is_suspicious_and_ignored() {
    check(
        "manifest-decoy-attribute-name.apk",
        &["invalid_attribute_name"],
        false,
    );

    let apk = Apk::new(fixture("manifest-decoy-attribute-name.apk")).unwrap();
    assert_eq!(apk.get_main_activity(), Some(".MainActivity"));
}

#[test]
fn resources_tampering_is_reported() {
    for (name, code) in [
        (
            "resources-string-pool-garbage-chunk.apk",
            "string_pool_garbage_chunk",
        ),
        (
            "resources-type-entries-out-of-bounds.apk",
            "type_entries_out_of_bounds",
        ),
        ("resources-unreadable.apk", "resources_unreadable"),
        ("resources-package-header-size.apk", "package_header_size"),
    ] {
        check(name, &[code], true);
    }
}

#[test]
fn resources_damage_is_suspicious_or_info() {
    check(
        "resources-duplicate-package-id.apk",
        &["duplicate_package_id"],
        false,
    );
    check(
        "resources-duplicate-type-chunk.apk",
        &["duplicate_type_chunk"],
        false,
    );

    let [anomaly] = &anomalies("resources-duplicate-type-chunk.apk")[..] else {
        unreachable!()
    };
    assert_eq!(anomaly.severity, Severity::Info);
}

#[test]
fn container_quirks_are_reported() {
    check("container-guessed-base.xapk", &["guessed_base_apk"], false);
    check(
        "container-root-manifest-garbage.xapk",
        &["root_manifest_unreadable"],
        false,
    );
}

#[test]
fn location_names_the_entry() {
    let [anomaly] = &anomalies("zip-encryption-flag.apk")[..] else {
        panic!("one anomaly expected");
    };
    assert_eq!(anomaly.location.as_deref(), Some("classes.dex"));
    assert!(matches!(anomaly.kind, AnomalyKind::Zip(_)));

    let [anomaly] = &anomalies("resources-unreadable.apk")[..] else {
        panic!("one anomaly expected");
    };
    assert_eq!(anomaly.location.as_deref(), Some("resources.arsc"));

    let [anomaly] = &anomalies("zip-fake-eocd-in-comment.apk")[..] else {
        panic!("one anomaly expected");
    };
    assert_eq!(anomaly.location, None);
}

/// Anomalies of a container's base apk are located inside it.
#[test]
fn container_base_anomalies_are_prefixed() {
    check("container-tampered-base.apkm", &["encryption_flag"], true);

    let [anomaly] = &anomalies("container-tampered-base.apkm")[..] else {
        panic!("one anomaly expected");
    };
    assert_eq!(anomaly.location.as_deref(), Some("base.apk!classes.dex"));
}
