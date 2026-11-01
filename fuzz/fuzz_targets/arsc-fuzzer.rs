#![no_main]

use apk_info_axml::ARSC;
use libfuzzer_sys::fuzz_target;

/// Bounds the lookups per input on tables with many entries.
const MAX_LOOKUPS: usize = 256;

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    let Ok(arsc) = ARSC::new(&mut input) else {
        return;
    };

    // ids of the entries the table really has
    let mut ids = Vec::new();
    for package in arsc.packages() {
        let package_id = package.header.id & 0xff;
        for types in package.resources.values() {
            for (&type_id, entries) in types {
                let count = entries.entries.len().min(MAX_LOOKUPS);
                let entry_ids: Vec<u16> = match &entries.entry_ids {
                    Some(ids) => ids.iter().copied().take(count).collect(),
                    None => (0..count as u16).collect(),
                };
                for entry_id in entry_ids {
                    ids.push(package_id << 24 | u32::from(type_id) << 16 | u32::from(entry_id));
                }
            }
        }
    }
    ids.truncate(MAX_LOOKUPS);

    for id in ids {
        let _ = arsc.get_resource_value(id);
        if let Some(name) = arsc.get_resource_name(id) {
            let _ = arsc.get_resource_id(&name);
            let _ = arsc.get_resource_value_by_name(&name);
        }
    }

    // and a few that it likely doesn't
    for id in [0, 0x7f00_0000, 0x7f01_0000, 0x0101_0000, u32::MAX] {
        let _ = arsc.get_resource_value(id);
        let _ = arsc.get_resource_name(id);
    }
    for name in [
        "string/app_name",
        "android:string/ok",
        "pkg:drawable/icon",
        "/",
        ":",
    ] {
        let _ = arsc.get_resource_value_by_name(name);
    }
});
