//! Permissions and manifest components.
//!
//! Usage: `cargo run --example components -- <path-to-apk>`

use apk_info::Apk;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: components <path-to-apk>")?;
    let apk = Apk::new(&path)?;

    // --8<-- [start:permissions]
    for permission in apk.get_permissions() {
        println!("uses-permission         {permission}");
    }
    for permission in apk.get_permissions_sdk23() {
        println!("uses-permission-sdk-23  {permission}");
    }
    for permission in apk.get_declared_permissions() {
        println!(
            "permission              {:?} [{:?}]",
            permission.name, permission.protection_level
        );
    }
    // --8<-- [end:permissions]

    // --8<-- [start:exported]
    let target_sdk = apk.get_target_sdk_version();

    // before Android 12 (target SDK 31), a component with an intent filter
    // was exported unless it said otherwise
    let is_exported = |exported: Option<&str>, has_filters: bool| match exported {
        Some(value) => value == "true",
        None => has_filters && target_sdk < 31,
    };

    for activity in apk.get_activities() {
        if is_exported(activity.exported, !activity.intent_filters.is_empty()) {
            println!("activity  {:?}", activity.name);
        }
    }
    for service in apk.get_services() {
        if is_exported(service.exported, !service.intent_filters.is_empty()) {
            println!("service   {:?}", service.name);
        }
    }
    for receiver in apk.get_receivers() {
        if is_exported(receiver.exported, !receiver.intent_filters.is_empty()) {
            println!("receiver  {:?}", receiver.name);
        }
    }
    for provider in apk.get_providers() {
        if provider.exported == Some("true") {
            println!("provider  {:?} {:?}", provider.name, provider.authorities);
        }
    }
    // --8<-- [end:exported]

    Ok(())
}
