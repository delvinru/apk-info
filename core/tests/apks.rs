//! `bundletool build-apks` archives: a `toc.pb` next to the generated APKs.
//! Fixtures come from `fixtures/build-apks-fixtures.sh`.

use apk_info::{Apk, Signature};

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn assert_app(apk: &Apk) {
    assert_eq!(
        apk.get_package_name().as_deref(),
        Some("io.github.delvinru.apkstest")
    );
    assert_eq!(apk.get_version_code().as_deref(), Some("7"));
    assert_eq!(apk.get_version_name().as_deref(), Some("1.0.7"));
    assert_eq!(apk.get_application_label().as_deref(), Some("APKS Test"));
    assert_eq!(apk.get_supported_abis(), ["x86_64"]);

    let signatures = apk.get_signatures().expect("base apk signatures");
    let subjects: Vec<&str> = signatures
        .iter()
        .filter_map(|s| match s {
            Signature::V1(certs) => certs.first().map(|c| c.subject.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(subjects, ["CN=apk-info apks test"]);

    // the .apks archive itself is never signed
    assert!(
        apk.get_container_signatures()
            .expect("container signatures")
            .iter()
            .all(|s| matches!(s, Signature::Unknown)),
    );
}

/// Default mode: the base is `splits/base-master.apk`, picked over the
/// `base-master_2.apk` of the next sdk variant; the abi comes from the
/// `splits/base-x86_64.apk` split.
#[test]
fn split_apks_parse_base_master() {
    let apk = Apk::new(fixture("apks-split.apks")).expect("split apks must parse");
    assert_app(&apk);

    let inner = apk.get_inner_zip().expect("base-master is the inner apk");
    assert!(inner.namelist().any(|n| n == "AndroidManifest.xml"));
    assert!(!inner.namelist().any(|n| n.starts_with("lib/")));
}

/// `--mode=universal`: a single `universal.apk` that carries the native libs.
#[test]
fn universal_apks_parse_universal_apk() {
    let apk = Apk::new(fixture("apks-universal.apks")).expect("universal apks must parse");
    assert_app(&apk);

    let inner = apk.get_inner_zip().expect("universal.apk is the inner apk");
    assert!(inner.namelist().any(|n| n == "lib/x86_64/libstub.so"));
}

/// `--mode=system`: `system/system.apk` merges the device's abi and density
/// splits, the language splits stay next to it in `splits/`.
#[test]
fn system_apks_parse_system_apk() {
    let apk = Apk::new(fixture("apks-system.apks")).expect("system apks must parse");
    assert_app(&apk);

    let inner = apk.get_inner_zip().expect("system.apk is the inner apk");
    assert!(inner.namelist().any(|n| n == "lib/x86_64/libstub.so"));
    assert!(apk.namelist().any(|n| n == "splits/base-ru.apk"));
}

/// `--mode=instant`: only `instant/` exists; the abi comes from the
/// `instant/instant-base-x86_64.apk` split.
#[test]
fn instant_apks_parse_instant_base_master() {
    let apk = Apk::new(fixture("apks-instant.apks")).expect("instant apks must parse");
    assert_app(&apk);

    let inner = apk
        .get_inner_zip()
        .expect("instant-base-master is the inner apk");
    assert!(inner.namelist().any(|n| n == "AndroidManifest.xml"));
    assert!(!inner.namelist().any(|n| n.starts_with("lib/")));
}
