//! Integration tests for signature parsing, run against golden APK fixtures
//! produced by the AOSP `apksig` project (Apache License 2.0,
//! Copyright (C) The Android Open Source Project).
//!
//! One fixture per parser path: each scheme, the multi-signer and
//! unknown-block shapes, and a malformed-certificate negative case.
//! See `fixtures/README.md` for provenance and licensing.

use apk_info_zip::{Signature, ZipEntry};

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn signatures_of(name: &str) -> Vec<Signature> {
    let zip = ZipEntry::open(fixture(name)).expect("failed to parse fixture apk");
    zip.get_signatures_other()
        .expect("v2+ signature blocks must parse without errors")
}

fn subject(cert: &apk_info_zip::CertificateInfo) -> &str {
    cert.subject.as_str()
}

#[test]
fn v1_only_jar_signing() {
    let zip = ZipEntry::open(fixture("v1-only-with-rsa-2048.apk")).unwrap();
    let Signature::V1(certs) = zip.get_signature_v1().expect("v1 signature expected") else {
        panic!("expected a v1 signature");
    };
    assert_eq!(certs.len(), 1);
    assert_eq!(subject(&certs[0]), "CN=rsa-2048");

    // no APK Signing Block in a v1-only apk
    assert!(signatures_of("v1-only-with-rsa-2048.apk").is_empty());
}

#[test]
fn v2_only_block() {
    let sigs = signatures_of("v2-only-with-rsa-pkcs1-sha256-2048.apk");
    assert_eq!(sigs.len(), 1);
    let Signature::V2(certs) = &sigs[0] else {
        panic!("expected a v2 signature, got {:?}", sigs[0].name());
    };
    assert_eq!(certs.len(), 1);
    assert_eq!(subject(&certs[0]), "CN=rsa-2048");
}

#[test]
fn v2_block_with_ten_signers() {
    let sigs = signatures_of("v2-only-10-signers.apk");
    assert_eq!(sigs.len(), 1);
    let Signature::V2(certs) = &sigs[0] else {
        panic!("expected a v2 signature");
    };
    assert_eq!(
        certs.len(),
        10,
        "all ten signers' certificates must be read"
    );
}

#[test]
fn v3_only_block() {
    let sigs = signatures_of("v3-only-with-rsa-pkcs1-sha256-2048.apk");
    assert_eq!(sigs.len(), 1);
    let Signature::V3(certs) = &sigs[0] else {
        panic!("expected a v3 signature, got {:?}", sigs[0].name());
    };
    assert_eq!(certs.len(), 1);
    assert_eq!(subject(&certs[0]), "CN=rsa-2048");
}

#[test]
fn v31_block_is_recognized_alongside_v1_v2() {
    let sigs = signatures_of("v31-tgt-33-no-v3-attr.apk");
    let names: Vec<String> = sigs.iter().map(|s| s.name()).collect();
    assert!(names.contains(&"v2".to_owned()), "got {names:?}");
    assert!(names.contains(&"v3.1".to_owned()), "got {names:?}");

    let v31 = sigs
        .iter()
        .find(|s| matches!(s, Signature::V31(_)))
        .unwrap();
    let Signature::V31(certs) = v31 else {
        unreachable!()
    };
    // the rotated key, distinct from the v1/v2 signer
    assert_eq!(certs.len(), 1);
    assert_eq!(subject(&certs[0]), "CN=rsa-2048_2");
}

#[test]
fn v32_hybrid_block_yields_both_signers() {
    let sigs = signatures_of("v32-mldsa-rsa-2048_2-v3-rsa-2048-min-max-strip-attr-valid.apk");
    let v32 = sigs
        .iter()
        .find(|s| matches!(s, Signature::V32(_)))
        .expect("v3.2 hybrid block must be recognized");
    let Signature::V32(certs) = v32 else {
        unreachable!()
    };

    // A valid v3.2 block carries exactly two signers: classical + PQC.
    assert_eq!(certs.len(), 2);
    let algos: Vec<String> = certs
        .iter()
        .map(|c| c.signature_type.to_lowercase())
        .collect();
    assert!(algos.iter().any(|a| a.contains("rsa")), "got {algos:?}");
    assert!(
        algos.iter().any(|a| a.contains("ml-dsa")),
        "PQC ML-DSA signer expected, got {algos:?}"
    );

    // the classical fallback v3 block is still reported
    assert!(
        sigs.iter().any(|s| matches!(s, Signature::V3(_))),
        "plain v3 block must still be parsed alongside v3.2"
    );
}

#[test]
fn v2_source_stamp_block_is_parsed() {
    let sigs = signatures_of("stamp-1-v31-tgt-33-signer.apk");
    let stamp = sigs
        .iter()
        .find(|s| matches!(s, Signature::StampBlockV2(_)))
        .expect("v2 source stamp block must be recognized");
    let Signature::StampBlockV2(cert) = stamp else {
        unreachable!()
    };
    assert_eq!(subject(cert), "CN=rsa-2048");

    // the fixture is signed with v2 + v3 + v3.1 alongside the stamp
    for expected in ["v2", "v3", "v3.1"] {
        assert!(
            sigs.iter().any(|s| s.name() == expected),
            "{expected} block expected, got {:?}",
            sigs.iter().map(|s| s.name()).collect::<Vec<_>>()
        );
    }
}

#[test]
fn unknown_block_id_is_skipped_silently() {
    // v2 + an ID-value pair with an unrecognized id: the parser must not
    // choke, and the unknown pair must not surface as a signature
    let sigs = signatures_of("v2-only-unknown-pair-in-apk-sig-block.apk");
    assert_eq!(sigs.len(), 1);
    assert!(matches!(sigs[0], Signature::V2(_)));
}

#[test]
fn verity_padding_block_does_not_hide_signatures() {
    // verity padding must be skipped without breaking the v2/v3 blocks after it
    let sigs = signatures_of("golden-rsa-verity-out.apk");
    let names: Vec<String> = sigs.iter().map(|s| s.name()).collect();
    assert!(names.contains(&"v2".to_owned()), "got {names:?}");
    assert!(names.contains(&"v3".to_owned()), "got {names:?}");
}

#[test]
fn malformed_v1_certificate_is_an_error() {
    // the .RSA file holds a certificate that is not DER: the v1 parse must
    // fail cleanly instead of returning garbage
    let zip = ZipEntry::open(fixture("v1-only-with-rsa-1024-cert-not-der.apk")).unwrap();
    assert!(zip.get_signature_v1().is_err());
}
