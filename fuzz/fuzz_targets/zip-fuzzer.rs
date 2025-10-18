#![no_main]

use apk_info_zip::entry::ZipEntry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = data.to_vec();
    let _ = ZipEntry::new(input);
});
