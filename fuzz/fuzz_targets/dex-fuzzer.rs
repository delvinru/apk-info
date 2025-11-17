#![no_main]

use apk_info_dex::Dex;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // must provide at least 8 bytes
    if data.len() < 8 {
        return;
    }

    let _ = Dex::new(data.to_vec());
});
