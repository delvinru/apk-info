#![no_main]

use apk_info_zip::ZipEntry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(zip) = ZipEntry::new(data.to_vec()) else {
        return;
    };

    apk_info_fuzz::exercise_zip(&zip);
});
