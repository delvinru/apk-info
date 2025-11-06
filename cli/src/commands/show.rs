use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use apk_info::apk::Apk;
use apk_info_zip::signature::{CertificateInfo, Signature};
use colored::Colorize;

use crate::commands::path_helpers::get_all_files;

pub(crate) fn command_show(paths: &[PathBuf], show_signatures: &bool) -> Result<()> {
    let files: Vec<PathBuf> = get_all_files(paths, &["apk", "zip", "jar"]).collect();

    for (i, path) in files.iter().enumerate() {
        show(path, show_signatures)?;

        // Add a newline between APKs except after the last one
        if i != files.len() - 1 {
            println!();
        }
    }

    Ok(())
}

fn show(path: &Path, show_signatures: &bool) -> Result<()> {
    let apk = Apk::new(path).with_context(|| format!("got error while parsing apk: {:?}", path))?;

    println!(
        "{}: {}",
        "Package Name",
        apk.get_package_name().unwrap_or("-").green()
    );
    println!(
        "{}: {}",
        "Main Activity",
        apk.get_main_activities().next().unwrap_or("-").green()
    );
    println!(
        "{}: {}",
        "Min SDK Version",
        apk.get_min_sdk_version().unwrap_or("-").green()
    );
    println!(
        "{}: {}",
        "Max SDK Version",
        apk.get_max_sdk_version().unwrap_or("-").green()
    );
    println!(
        "{}: {}",
        "Target SDK Version",
        apk.get_target_sdk_version().unwrap_or("-").green()
    );
    println!(
        "{}: {}",
        "Application Label",
        apk.get_application_label()
            .unwrap_or("-".to_owned())
            .green()
    );

    if *show_signatures {
        println!("\n{}:", "APK Signature block".blue().bold());

        let signatures = apk.get_signatures().with_context(|| {
            format!(
                "got error while parsing signatures, please report this bug: {:?}",
                path
            )
        })?;

        for (i, signature) in signatures.iter().enumerate() {
            match signature {
                Signature::V1(certificates)
                | Signature::V2(certificates)
                | Signature::V3(certificates)
                | Signature::V31(certificates) => {
                    println!("  {}: {}", "Type", signature.name().green());
                    for (j, certificate) in certificates.iter().enumerate() {
                        print_certificate(&certificate);
                        if j != certificates.len() - 1 {
                            println!();
                        }
                    }
                }
                Signature::StampBlockV1(certificate) | Signature::StampBlockV2(certificate) => {
                    println!("  {}: {}", "Type", signature.name().green());
                    print_certificate(certificate);
                }
                Signature::ApkChannelBlock(channel) => {
                    println!("  {}: {}", signature.name(), channel.green());
                }
                _ => continue,
            }

            if i != signatures.len() - 1 {
                println!();
            }
        }
    }

    Ok(())
}

fn print_certificate(certificate: &CertificateInfo) {
    println!(
        "  {}: {}",
        "Serial Number",
        certificate.serial_number.green()
    );
    println!("  {}: {}", "Subject", certificate.subject.green());
    println!("  {}: {}", "Valid from", certificate.valid_from.green());
    println!("  {}: {}", "Valid until", certificate.valid_until.green());
    println!(
        "  {}: {}",
        "Signature type",
        certificate.signature_type.green()
    );
    println!(
        "  {}: {}",
        "MD5 fingerprint",
        certificate.md5_fingerprint.green()
    );
    println!(
        "  {}: {}",
        "SHA1 fingerprint",
        certificate.sha1_fingerprint.green()
    );
    println!(
        "  {}: {}",
        "SHA256 fingerprint",
        certificate.sha256_fingerprint.green()
    );
}
