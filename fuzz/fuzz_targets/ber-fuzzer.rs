#![no_main]

//! Fuzzes the BER normalization of certificates and PKCS#7 blobs, and the v1
//! signature parsing on top of it.

use apk_info_fuzz::{Layout, RawEntry, build_zip};
use apk_info_zip::ZipEntry;
use apk_info_zip::fuzzing::ber_to_der;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(der) = ber_to_der(data) {
        // DER is a fixed point of the normalization
        assert_eq!(
            ber_to_der(&der).as_deref(),
            Some(der.as_slice()),
            "normalized output changes on the second pass"
        );
    }

    let entries = [
        RawEntry::stored(b"META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n"),
        RawEntry::stored(b"META-INF/CERT.SF", b"Signature-Version: 1.0\r\n"),
        RawEntry::stored(b"META-INF/CERT.RSA", data),
    ];
    let zip = ZipEntry::new(build_zip(&entries, &Layout::default())).expect("the archive is valid");
    let _ = zip.get_signature_v1();
});
