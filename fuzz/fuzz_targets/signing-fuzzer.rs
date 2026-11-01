#![no_main]

//! Fuzzes the ID-value pairs of the APK Signing Block. The input is placed
//! inside a block with consistent sizes, right before the central directory of
//! a valid archive, so mutations are spent on the pairs and not on offsets.

use apk_info_fuzz::{Layout, RawEntry, build_zip, signing_block};
use apk_info_zip::ZipEntry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|pairs: &[u8]| {
    let entries = [RawEntry::stored(
        b"AndroidManifest.xml",
        b"\x03\x00\x08\x00",
    )];
    let layout = Layout {
        before_cd: signing_block(pairs),
        ..Layout::default()
    };

    let zip = ZipEntry::new(build_zip(&entries, &layout)).expect("the archive is valid");
    let _ = zip.get_signatures_other();
});
