#![no_main]

use apk_info_axml::axml::AXML;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // must provide at least 8 byte
    if data.len() < 8 {
        return;
    }

    let mut input = data;
    let _ = AXML::new(&mut input);
});
