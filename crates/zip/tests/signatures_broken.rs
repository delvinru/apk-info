//! Integration tests for parser robustness, run against deliberately
//! malformed APK fixtures produced by the AOSP `apksig` project test
//! suite (Apache License 2.0, Copyright (C) The Android Open Source
//! Project). Files are prefixed `broken-`; see `fixtures/README.md`.
//!
//! The contract under test: a damaged archive must fail with a clean
//! [`ZipError`] (never a panic), and a damaged *signature block* must
//! degrade gracefully — the schemes that do parse are still reported.

use apk_info_zip::{Signature, ZipEntry, ZipError};

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Builds a minimal stored ZIP archive with one file and an `APK Sig Block 42`
/// carrying the given ID-value pairs, spliced in between the file data and
/// the central directory.
fn zip_with_signing_block(pairs: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();

    // local file header + data for "a.txt" (stored)
    out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
    out.extend_from_slice(&0u16.to_le_bytes()); // mod time
    out.extend_from_slice(&0u16.to_le_bytes()); // mod date
    out.extend_from_slice(&0u32.to_le_bytes()); // crc
    out.extend_from_slice(&1u32.to_le_bytes()); // csize
    out.extend_from_slice(&1u32.to_le_bytes()); // usize
    out.extend_from_slice(&5u16.to_le_bytes()); // name len
    out.extend_from_slice(&0u16.to_le_bytes()); // extra len
    out.extend_from_slice(b"a.txt");
    out.extend_from_slice(b"a");

    // the signing block: [size u64][pairs][size u64][magic 16]
    let mut pairs_bytes = Vec::new();
    for (id, value) in pairs {
        pairs_bytes.extend_from_slice(&(4 + value.len() as u64).to_le_bytes());
        pairs_bytes.extend_from_slice(&id.to_le_bytes());
        pairs_bytes.extend_from_slice(value);
    }
    let size_of_block = pairs_bytes.len() as u64 + 24;
    out.extend_from_slice(&size_of_block.to_le_bytes());
    out.extend_from_slice(&pairs_bytes);
    out.extend_from_slice(&size_of_block.to_le_bytes());
    out.extend_from_slice(b"APK Sig Block 42");

    // central directory (one entry, local header at 0)
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes()); // version made by
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // method
    out.extend_from_slice(&0u16.to_le_bytes()); // mod time
    out.extend_from_slice(&0u16.to_le_bytes()); // mod date
    out.extend_from_slice(&0u32.to_le_bytes()); // crc
    out.extend_from_slice(&1u32.to_le_bytes()); // csize
    out.extend_from_slice(&1u32.to_le_bytes()); // usize
    out.extend_from_slice(&5u16.to_le_bytes()); // name len
    out.extend_from_slice(&0u16.to_le_bytes()); // extra len
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    out.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    out.extend_from_slice(b"a.txt");
    let cd_size = out.len() as u32 - cd_offset;

    // end of central directory
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&1u16.to_le_bytes()); // entries this disk
    out.extend_from_slice(&1u16.to_le_bytes()); // total entries
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len

    out
}

/// A minimal, structurally valid v2 signer with an empty certificate list:
/// `[signers seq [signer [signed-data [digests][certs][attrs]][sigs][pubkey]]]`
/// — everything inside the signer's own length prefix, every sequence empty.
fn minimal_v2_signers() -> Vec<u8> {
    let mut signed_data_field = Vec::new();
    signed_data_field.extend_from_slice(&12u32.to_le_bytes());
    signed_data_field.extend_from_slice(&0u32.to_le_bytes()); // digests
    signed_data_field.extend_from_slice(&0u32.to_le_bytes()); // certificates
    signed_data_field.extend_from_slice(&0u32.to_le_bytes()); // attributes

    let mut signer_data = Vec::new();
    signer_data.extend_from_slice(&signed_data_field);
    signer_data.extend_from_slice(&0u32.to_le_bytes()); // signatures
    signer_data.extend_from_slice(&0u32.to_le_bytes()); // public key

    let mut signer = Vec::new();
    signer.extend_from_slice(&(signer_data.len() as u32).to_le_bytes());
    signer.extend_from_slice(&signer_data);

    let mut value = Vec::new();
    value.extend_from_slice(&(signer.len() as u32).to_le_bytes());
    value.extend_from_slice(&signer);
    value
}

/// A minimal, structurally valid v3 signer with an empty certificate list,
/// including the signed-data and duplicated min/max SDK fields, all inside
/// the signer's own length prefix.
fn minimal_v3_signers() -> Vec<u8> {
    let mut signed_data_field = Vec::new();
    signed_data_field.extend_from_slice(&20u32.to_le_bytes());
    signed_data_field.extend_from_slice(&0u32.to_le_bytes()); // digests
    signed_data_field.extend_from_slice(&0u32.to_le_bytes()); // certificates
    signed_data_field.extend_from_slice(&24u32.to_le_bytes()); // min sdk
    signed_data_field.extend_from_slice(&1000u32.to_le_bytes()); // max sdk
    signed_data_field.extend_from_slice(&0u32.to_le_bytes()); // attributes

    let mut signer_data = Vec::new();
    signer_data.extend_from_slice(&signed_data_field);
    signer_data.extend_from_slice(&24u32.to_le_bytes()); // duplicate min sdk
    signer_data.extend_from_slice(&1000u32.to_le_bytes()); // duplicate max sdk
    signer_data.extend_from_slice(&0u32.to_le_bytes()); // signatures
    signer_data.extend_from_slice(&0u32.to_le_bytes()); // public key

    let mut signer = Vec::new();
    signer.extend_from_slice(&(signer_data.len() as u32).to_le_bytes());
    signer.extend_from_slice(&signer_data);

    let mut value = Vec::new();
    value.extend_from_slice(&(signer.len() as u32).to_le_bytes());
    value.extend_from_slice(&signer);
    value
}

/// Files that are not recognizable ZIP archives at all.
#[test]
fn not_a_zip_is_rejected_with_invalid_header() {
    for name in [
        "broken-empty-unsigned.apk",
        "broken-v2-only-empty.apk",
        "broken-v3-only-empty.apk",
    ] {
        let err = ZipEntry::open(fixture(name)).expect_err("must be rejected");
        assert!(matches!(err, ZipError::InvalidHeader), "{name}: {err:?}");
    }
}

/// A file whose End of Central Directory record cannot be found.
#[test]
fn missing_eocd_is_reported() {
    let err = ZipEntry::open(fixture("broken-invalid_manifest.apk")).expect_err("must fail");
    assert!(matches!(err, ZipError::NotFoundEOCD), "{err:?}");
}

/// A v1 signature over an APK with an empty body: the JAR signature
/// itself is well-formed, so it must still be extracted.
#[test]
fn v1_over_empty_apk_body_is_parsed() {
    let zip = ZipEntry::open(fixture("broken-v1-only-empty.apk")).unwrap();
    assert!(matches!(zip.get_signature_v1(), Ok(Signature::V1(_))));
    assert!(zip.get_signatures_other().unwrap().is_empty());
}

/// A maximum-size (64 KiB) ZIP comment must not hide the EOCD from the
/// backward signature scan, for both v1- and v2-signed archives.
#[test]
fn max_sized_eocd_comment_is_tolerated() {
    let v1 = ZipEntry::open(fixture("broken-v1-only-max-sized-eocd-comment.apk")).unwrap();
    assert!(matches!(v1.get_signature_v1(), Ok(Signature::V1(_))));

    let v2 = ZipEntry::open(fixture("broken-v2-only-max-sized-eocd-comment.apk")).unwrap();
    assert!(matches!(
        &v2.get_signatures_other().unwrap()[..],
        [Signature::V2(_)]
    ));
}

/// Garbage bytes between the central directory and the EOCD leave the
/// EOCD's declared CD offset stale; the derived-offset fallback must
/// still locate both the central directory and the signing block.
#[test]
fn garbage_between_cd_and_eocd_still_finds_signatures() {
    let zip = ZipEntry::open(fixture("broken-v2-only-garbage-between-cd-and-eocd.apk")).unwrap();
    assert!(matches!(
        &zip.get_signatures_other().unwrap()[..],
        [Signature::V2(_)]
    ));
}

/// A truncated central directory: the parser reads the CD to the end of
/// the stream and stops at the first non-header magic, so the signature
/// block before the damage is still reachable.
#[test]
fn truncated_cd_still_finds_signatures() {
    let zip = ZipEntry::open(fixture("broken-v2-only-truncated-cd.apk")).unwrap();
    assert!(matches!(
        &zip.get_signatures_other().unwrap()[..],
        [Signature::V2(_)]
    ));
}

/// Signer records with an empty certificate sequence: structurally valid,
/// so the block parses — just with zero certificates.
#[test]
fn signer_without_certificates_parses_to_empty_list() {
    for name in [
        "broken-v2-only-no-certs-in-sig.apk",
        "broken-v3-only-no-certs-in-sig.apk",
    ] {
        let zip = ZipEntry::open(fixture(name)).unwrap();
        let sigs = zip.get_signatures_other().unwrap();
        assert_eq!(sigs.len(), 1, "{name}");
        match &sigs[0] {
            Signature::V2(certs) | Signature::V3(certs) => {
                assert!(certs.is_empty(), "{name}: expected no certificates");
            }
            other => panic!("{name}: unexpected scheme {}", other.name()),
        }
    }
}

/// An APK whose APK Signing Block was stripped entirely: the v1 JAR
/// signature in `META-INF/` survives and must still be reported.
#[test]
fn stripped_signing_block_falls_back_to_v1() {
    let zip = ZipEntry::open(fixture(
        "broken-v1v2v3-with-rsa-2048-lineage-3-signers-no-sig-block.apk",
    ))
    .unwrap();
    assert!(matches!(zip.get_signature_v1(), Ok(Signature::V1(_))));
    assert!(zip.get_signatures_other().unwrap().is_empty());
}

/// A stamp block truncated to a single payload byte: the malformed
/// ID-value pair is skipped by its declared length, and every other block
/// in the signing block is still reported — no error, no panic.
#[test]
fn malformed_stamp_pair_degrades_gracefully() {
    let zip = ZipEntry::open(fixture("broken-stamp-malformed-signature.apk")).unwrap();
    let sigs = zip.get_signatures_other().expect("must not hard-fail");
    let names: Vec<String> = sigs.iter().map(|s| s.name()).collect();
    assert_eq!(names, vec!["v2".to_owned(), "v3".to_owned()]);
}

/// A signing block whose leading and trailing sizes disagree is corrupt:
/// it must be treated as absent instead of failing the whole signature
/// listing (a v1 JAR signature, if present, would still be reported).
#[test]
fn signing_block_size_mismatch_is_treated_as_absent() {
    let zip = ZipEntry::open(fixture("broken-v2-only-apk-sig-block-size-mismatch.apk")).unwrap();

    // the archive itself is a healthy zip
    assert!(zip.namelist().count() > 0);

    // the corrupt block yields no signatures, but no error either
    let sigs = zip.get_signatures_other().expect("must not hard-fail");
    assert!(sigs.is_empty());
}

/// A malformed pair sitting *between* two healthy blocks must not hide
/// them: `[v2][truncated stamp][v3]` still yields both v2 and v3.
#[test]
fn malformed_pair_between_blocks_does_not_hide_neighbors() {
    let pairs = [
        (ZipEntry::SIGNATURE_SCHEME_V2_BLOCK_ID, minimal_v2_signers()),
        // a stamp value cut to a single byte: no prefix, no certificate
        (ZipEntry::V2_SOURCE_STAMP_BLOCK_ID, vec![0xAB]),
        (ZipEntry::SIGNATURE_SCHEME_V3_BLOCK_ID, minimal_v3_signers()),
    ];
    let data = zip_with_signing_block(&pairs);

    let zip = ZipEntry::new(data).unwrap();
    let sigs = zip.get_signatures_other().expect("must not hard-fail");
    let names: Vec<String> = sigs.iter().map(|s| s.name()).collect();
    assert_eq!(names, vec!["v2".to_owned(), "v3".to_owned()]);
}
