#![no_main]

use apk_info_axml::AXML;
use libfuzzer_sys::fuzz_target;

/// Lookups the core crate does on every manifest.
const ATTRIBUTES: &[(&str, &str)] = &[
    ("manifest", "package"),
    ("manifest", "versionCode"),
    ("manifest", "versionName"),
    ("uses-sdk", "minSdkVersion"),
    ("uses-sdk", "targetSdkVersion"),
    ("application", "label"),
    ("application", "name"),
    ("uses-permission", "name"),
    ("activity", "name"),
];

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    let Ok(axml) = AXML::new(&mut input, None) else {
        return;
    };

    apk_info_fuzz::check_xml(&axml.get_xml_string());

    let _ = axml.get_main_activities().count();
    for (tag, name) in ATTRIBUTES {
        let _ = axml.get_attribute_value(tag, name, None);
        let _ = axml.get_root_attribute_values(tag, name).count();
        let _ = axml.get_all_attribute_values(tag, name).count();
    }
});
