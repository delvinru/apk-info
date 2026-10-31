//! Inspecting an APK: triage, launchability, device targets and raw manifest values.
//!
//! Usage: `cargo run --example triage -- <path-to-apk>`

use apk_info::Apk;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: triage <path-to-apk>")?;
    let apk = Apk::new(&path)?;

    // --8<-- [start:triage]
    let package = apk.get_package_name().unwrap_or_default();
    println!("Package:    {package}");
    println!(
        "Version:    {} ({})",
        apk.get_version_name().unwrap_or_default(),
        apk.get_version_code().unwrap_or_default()
    );
    println!(
        "SDK:        min {}, target {}",
        apk.get_min_sdk_version().unwrap_or_default(),
        apk.get_target_sdk_version()
    );
    println!(
        "Label:      {}",
        apk.get_application_label().unwrap_or_default()
    );
    println!("Debuggable: {:?}", apk.get_application_debuggable());
    println!("Backup:     {:?}", apk.get_application_allow_backup());
    println!("Multidex:   {}", apk.is_multidex());
    println!("ABIs:       {:?}", apk.get_supported_abis());
    // --8<-- [end:triage]

    // --8<-- [start:launchable]
    let mut activities = apk.get_main_activities().peekable();
    if activities.peek().is_none() {
        println!("not launchable: no MAIN + LAUNCHER activity");
    }
    for activity in activities {
        println!("adb shell am start -n {package}/{activity}");
    }
    // --8<-- [end:launchable]

    // --8<-- [start:targets]
    let targets: Vec<&str> = [
        ("TV", apk.is_leanback()),
        ("Wear OS", apk.is_wearable()),
        ("Android Automotive", apk.is_automotive()),
        ("ChromeOS", apk.is_chromebook()),
    ]
    .into_iter()
    .filter_map(|(name, matches)| matches.then_some(name))
    .collect();
    println!("Targets: {targets:?}");
    // --8<-- [end:targets]

    // --8<-- [start:attributes]
    println!(
        "{:?}",
        apk.get_attribute_value("application", "networkSecurityConfig")
    );
    let permissions: Vec<&str> = apk
        .get_all_attribute_values("uses-permission", "name")
        .collect();
    println!("{permissions:?}");
    // --8<-- [end:attributes]

    // --8<-- [start:resources]
    println!("{:?}", apk.get_application_label());
    println!("{:?}", apk.get_resource_value("@string/app_name"));
    // --8<-- [end:resources]

    // --8<-- [start:manifest]
    std::fs::write("AndroidManifest.xml", apk.get_xml_string())?;
    // --8<-- [end:manifest]

    Ok(())
}
