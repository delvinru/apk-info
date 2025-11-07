#![no_main]

use apk_info_axml::AXML;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // must provide at least 8 bytes
    if data.len() < 8 {
        return;
    }

    let mut input = data;
    let _ = AXML::new(&mut input, None);
});
