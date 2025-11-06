#![no_main]

use apk_info_axml::ARSC;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // must provide at least 12 bytes
    if data.len() < 12 {
        return;
    }

    let mut input = data;
    let _ = ARSC::new(&mut input);
});
