use std::path::{Path, PathBuf};

use anyhow::Result;
use apk_info::Apk;
use apk_info_zip::{CertificateInfo, Signature};
use colored::Colorize;
use serde::Serialize;

use crate::commands::path_helpers::get_all_files;

pub(crate) fn command_show(paths: &[PathBuf], show_signatures: &bool, jsonl: &bool) -> Result<()> {
    let files = get_all_files(paths);

    for (i, path) in files.iter().enumerate() {
        show(path, show_signatures, jsonl)?;

        // Add a newline between APKs except after the last one
        if i != files.len() - 1 {
            println!();
        }
    }

    Ok(())
}

fn show(path: &Path, show_signatures: &bool, jsonl: &bool) -> Result<()> {
    let info = collect_apk_info(path, show_signatures)?;

    if *jsonl {
        print!("{}", serde_json::to_string(&info)?);
    } else {
        pretty_print(&info);
    }

    Ok(())
}

#[derive(Serialize)]
struct ApkInfo {
    pub package_name: String,
    pub version_name: String,
    pub version_code: String,
    pub main_activity: String,
    pub min_sdk_version: String,
    pub max_sdk_version: String,
    pub target_sdk_version: String,
    pub application_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<Signature>>,
}

fn collect_apk_info(path: &Path, show_signatures: &bool) -> Result<ApkInfo> {
    let apk = Apk::new(path)?;

    let signatures = if *show_signatures {
        Some(
            apk.get_signatures()?
                .into_iter()
                .filter(|s| !matches!(s, Signature::Unknown))
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };

    Ok(ApkInfo {
        package_name: apk.get_package_name().unwrap_or_else(|| "-".to_string()),
        version_name: apk.get_version_name().unwrap_or_else(|| "-".to_string()),
        version_code: apk.get_version_code().unwrap_or_else(|| "-".to_string()),
        main_activity: format!(
            "{}/{}",
            apk.get_package_name().unwrap_or_default(),
            apk.get_main_activity().unwrap_or("-")
        ),
        min_sdk_version: apk.get_min_sdk_version().unwrap_or_else(|| "-".to_string()),
        max_sdk_version: apk.get_max_sdk_version().unwrap_or_else(|| "-".to_string()),
        target_sdk_version: apk.get_target_sdk_version().to_string(),
        application_label: apk
            .get_application_label()
            .unwrap_or_else(|| "-".to_string()),
        signatures,
    })
}

fn pretty_print(info: &ApkInfo) {
    println!("Package Name: {}", info.package_name.green(),);
    println!("Main Activity: {}", info.main_activity.green(),);
    println!("Min SDK Version: {}", info.min_sdk_version.green(),);
    println!("Max SDK Version: {}", info.max_sdk_version.green(),);
    println!("Target SDK Version: {}", info.target_sdk_version.green(),);
    println!("Application Label: {}", info.application_label.green(),);
    println!("Version Name: {}", info.version_name.green(),);
    println!("Version Code: {}", info.version_code.green(),);

    if let Some(signatures) = &info.signatures {
        println!("{}:", "APK Signature block".blue().bold());

        for (i, signature) in signatures.iter().enumerate() {
            match signature {
                Signature::V1(certificates)
                | Signature::V2(certificates)
                | Signature::V3(certificates)
                | Signature::V31(certificates) => {
                    println!("  Type: {}", signature.name().green());

                    for (j, certificate) in certificates.iter().enumerate() {
                        print_certificate(certificate);
                        if j != certificates.len() - 1 {
                            println!();
                        }
                    }
                }
                Signature::StampBlockV1(certificate) | Signature::StampBlockV2(certificate) => {
                    println!("  Type: {}", signature.name().green());
                    print_certificate(certificate);
                }
                Signature::ApkChannelBlock(channel) => {
                    println!("  Type: {}", signature.name().green());
                    println!("  Channel: {}", channel.green());
                }
                Signature::PackerNextGenV2(data) => {
                    let hex_string = data
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join("");

                    println!("  Type: {}", signature.name().green());
                    println!("  Value: {}", hex_string.green());
                }
                Signature::GooglePlayFrosting => {
                    println!("  Type: {}", signature.name().green());
                    println!("  Info: {}", "Metadata exist".green());
                }
                Signature::VasDollyV2(channel) => {
                    println!("  Type: {}", signature.name().green());
                    println!("  Channel: {}", channel.green());
                }
                _ => continue,
            }

            if i != signatures.len() - 1 {
                println!();
            }
        }
    }
}

fn print_certificate(certificate: &CertificateInfo) {
    println!("  Serial Number: {}", certificate.serial_number.green());
    println!("  Subject: {}", certificate.subject.green());
    println!("  Issuer: {}", certificate.issuer.green());
    println!("  Valid from: {}", certificate.valid_from.green());
    println!("  Valid until: {}", certificate.valid_until.green());
    println!("  Signature type: {}", certificate.signature_type.green());
    println!("  MD5 fingerprint: {}", certificate.md5_fingerprint.green());
    println!(
        "  SHA1 fingerprint: {}",
        certificate.sha1_fingerprint.green()
    );
    println!(
        "  SHA256 fingerprint: {}",
        certificate.sha256_fingerprint.green()
    );
}
