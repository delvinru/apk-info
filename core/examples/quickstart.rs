//! Prints basic information and signing certificates of an APK.
//!
//! Usage: `cargo run --example quickstart -- <path-to-apk>`

use apk_info::{Apk, Signature};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: quickstart <path-to-apk>")?;

    // --8<-- [start:basic]
    let apk = Apk::new(&path)?;

    println!(
        "Package:     {}",
        apk.get_package_name().unwrap_or_default()
    );
    println!(
        "Version:     {}",
        apk.get_version_name().unwrap_or_default()
    );
    println!(
        "Min SDK:     {}",
        apk.get_min_sdk_version().unwrap_or_default()
    );
    println!("Target SDK:  {}", apk.get_target_sdk_version());
    println!(
        "Label:       {}",
        apk.get_application_label().unwrap_or_default()
    );
    println!(
        "Main:        {}",
        apk.get_main_activity().unwrap_or_default()
    );
    // --8<-- [end:basic]

    // --8<-- [start:signatures]
    for signature in apk.get_signatures()? {
        match &signature {
            Signature::V1(certs)
            | Signature::V2(certs)
            | Signature::V3(certs)
            | Signature::V31(certs)
            | Signature::V32(certs) => {
                for cert in certs {
                    println!(
                        "{}: {} ({})",
                        signature.name(),
                        cert.subject,
                        cert.sha256_fingerprint
                    );
                }
            }
            other => println!("{}", other.name()),
        }
    }
    // --8<-- [end:signatures]

    Ok(())
}
