use std::path::{Path, PathBuf};

use anyhow::Result;
use apk_info::{Apk, Severity};
use apk_info_zip::{CertificateInfo, Signature};
use colored::Colorize;
use serde::Serialize;

use crate::commands::path_helpers::get_all_files;

pub(crate) fn command_show(
    paths: &[PathBuf],
    show_signatures: &bool,
    show_anomalies: &bool,
    jsonl: &bool,
) -> Result<()> {
    let mut printed = false;

    for path in get_all_files(paths) {
        let info = match collect_apk_info(&path, show_signatures, show_anomalies) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{:?} - {}", path, e.to_string().red());
                // a failed file is a record too
                if *jsonl {
                    let record = ErrorRecord {
                        path: &path,
                        error: e.to_string(),
                    };
                    println!("{}", serde_json::to_string(&record)?);
                }
                continue;
            }
        };

        if *jsonl {
            println!("{}", serde_json::to_string(&info)?);
        } else {
            if printed {
                println!();
            }
            pretty_print(&info);
        }
        printed = true;
    }

    Ok(())
}

/// A file that failed to parse, in the JSON output.
#[derive(Serialize)]
struct ErrorRecord<'a> {
    path: &'a Path,
    error: String,
}

/// What `show` prints for an APK; missing values are `None`, `null` in JSON.
#[derive(Serialize)]
struct ApkInfo {
    pub path: PathBuf,
    pub package_name: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    /// As written in the manifest, e.g. `.MainActivity`.
    pub main_activity: Option<String>,
    /// `package/activity` as written in the manifest, the form `adb` takes.
    #[serde(skip)]
    pub main_component: Option<String>,
    pub min_sdk_version: Option<String>,
    pub max_sdk_version: Option<String>,
    pub target_sdk_version: String,
    pub application_label: Option<String>,
    pub abis: Vec<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_signatures"
    )]
    pub signatures: Option<Vec<Signature>>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_signatures"
    )]
    pub container_signatures: Option<Vec<Signature>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tampered: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomalies: Option<Vec<AnomalyInfo>>,
}

/// A signing block in JSON: `scheme`, then `certificates` or `value`.
#[derive(Serialize)]
struct SignatureRecord<'a> {
    scheme: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificates: Option<&'a [CertificateInfo]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

impl<'a> From<&'a Signature> for SignatureRecord<'a> {
    fn from(signature: &'a Signature) -> Self {
        let (scheme, certificates, value): (_, Option<&[CertificateInfo]>, _) = match signature {
            Signature::V1(certificates) => ("v1", Some(certificates), None),
            Signature::V2(certificates) => ("v2", Some(certificates), None),
            Signature::V3(certificates) => ("v3", Some(certificates), None),
            Signature::V31(certificates) => ("v31", Some(certificates), None),
            Signature::V32(certificates) => ("v32", Some(certificates), None),
            Signature::StampBlockV1(certificate) => (
                "stamp_block_v1",
                Some(std::slice::from_ref(certificate)),
                None,
            ),
            Signature::StampBlockV2(certificate) => (
                "stamp_block_v2",
                Some(std::slice::from_ref(certificate)),
                None,
            ),
            Signature::ApkChannelBlock(value) => ("apk_channel_block", None, Some(value.clone())),
            Signature::VasDollyV2(value) => ("vasdolly_v2", None, Some(value.clone())),
            Signature::ByteDance(value) => ("bytedance", None, Some(value.clone())),
            Signature::PackerNextGenV2(data) => (
                "packer_next_gen_v2",
                None,
                Some(data.iter().map(|b| format!("{b:02x}")).collect()),
            ),
            Signature::GooglePlayFrosting => ("google_play_frosting", None, None),
        };

        SignatureRecord {
            scheme,
            certificates,
            value,
        }
    }
}

fn serialize_signatures<S: serde::Serializer>(
    signatures: &Option<Vec<Signature>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(signatures.iter().flatten().map(SignatureRecord::from))
}

#[derive(Serialize)]
struct AnomalyInfo {
    pub code: &'static str,
    pub severity: Severity,
    pub location: Option<String>,
    pub detail: String,
}

fn collect_apk_info(path: &Path, show_signatures: &bool, show_anomalies: &bool) -> Result<ApkInfo> {
    let apk = Apk::new(path)?;

    let signatures = if *show_signatures {
        Some(apk.get_signatures()?)
    } else {
        None
    };

    let container_signatures = if *show_signatures {
        let sigs = apk.get_container_signatures()?;
        if sigs.is_empty() { None } else { Some(sigs) }
    } else {
        None
    };

    let anomalies = show_anomalies.then(|| {
        apk.anomalies()
            .into_iter()
            .map(|anomaly| AnomalyInfo {
                code: anomaly.code(),
                severity: anomaly.severity,
                detail: anomaly.to_string(),
                location: anomaly.location,
            })
            .collect::<Vec<_>>()
    });
    let tampered = anomalies.as_ref().map(|anomalies| {
        anomalies
            .iter()
            .any(|anomaly| anomaly.severity == Severity::Tampered)
    });

    let package_name = apk.get_package_name();
    let main_activity = apk.get_main_activity();

    Ok(ApkInfo {
        path: path.to_path_buf(),
        main_activity: main_activity.map(str::to_owned),
        main_component: main_activity
            .map(|name| format!("{}/{name}", package_name.as_deref().unwrap_or("-"))),
        package_name,
        version_name: apk.get_version_name(),
        version_code: apk.get_version_code(),
        min_sdk_version: apk.get_min_sdk_version(),
        max_sdk_version: apk.get_max_sdk_version(),
        target_sdk_version: apk.get_target_sdk_version().to_string(),
        application_label: apk.get_application_label(),
        abis: apk.get_supported_abis(),
        signatures,
        container_signatures,
        tampered,
        anomalies,
    })
}

const KEY_WIDTH: usize = 18;

/// Locations listed per anomaly kind.
const LOCATIONS_PER_CODE: usize = 2;

fn field(indent: usize, key: &str, value: impl std::fmt::Display) {
    let pad = (KEY_WIDTH.saturating_sub(indent))
        .saturating_sub(key.chars().count())
        .max(1);
    println!("{:indent$}{key}{:pad$}{value}", "", "");
}

fn pretty_print(info: &ApkInfo) {
    println!("{}", info.path.display().to_string().bold());
    let or_dash = |value: &Option<String>| value.clone().unwrap_or_else(|| "-".to_owned());

    field(2, "Package", or_dash(&info.package_name).green());
    field(2, "Label", or_dash(&info.application_label).green());
    field(
        2,
        "Version",
        format!(
            "{} ({})",
            or_dash(&info.version_name),
            or_dash(&info.version_code)
        )
        .green(),
    );

    let mut sdk = format!(
        "min {} · target {}",
        or_dash(&info.min_sdk_version),
        info.target_sdk_version
    );
    if let Some(max) = &info.max_sdk_version {
        sdk.push_str(&format!(" · max {max}"));
    }
    field(2, "SDK", sdk.green());
    field(2, "Main activity", or_dash(&info.main_component).green());
    if !info.abis.is_empty() {
        field(2, "ABIs", info.abis.join(", ").green());
    }

    if let Some(signatures) = &info.signatures {
        println!();
        println!("{}", "Signatures".blue().bold());
        print_signatures(signatures);
    }

    if let Some(signatures) = &info.container_signatures {
        println!();
        println!("{}", "Container signatures".blue().bold());
        print_signatures(signatures);
    }

    if let (Some(tampered), Some(anomalies)) = (info.tampered, &info.anomalies) {
        println!();
        print_anomalies(tampered, anomalies);
    }
}

/// Schemes signed with the same certificates share one entry.
fn print_signatures(signatures: &[Signature]) {
    if signatures.is_empty() {
        println!("  {}", "none".yellow());
        return;
    }

    let mut schemes: Vec<(Vec<String>, &[CertificateInfo])> = Vec::new();

    for signature in signatures {
        match signature {
            Signature::V1(certificates)
            | Signature::V2(certificates)
            | Signature::V3(certificates)
            | Signature::V31(certificates)
            | Signature::V32(certificates) => {
                match schemes
                    .iter_mut()
                    .find(|(_, known)| *known == certificates.as_slice())
                {
                    Some((names, _)) => names.push(signature.name()),
                    None => schemes.push((vec![signature.name()], certificates)),
                }
            }
            Signature::StampBlockV1(certificate) | Signature::StampBlockV2(certificate) => {
                schemes.push((vec![signature.name()], std::slice::from_ref(certificate)));
            }
            Signature::ApkChannelBlock(value)
            | Signature::VasDollyV2(value)
            | Signature::ByteDance(value) => field(2, &signature.name(), value.green()),
            Signature::PackerNextGenV2(data) => {
                let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
                field(2, &signature.name(), hex.green());
            }
            Signature::GooglePlayFrosting => field(2, &signature.name(), "present".green()),
        }
    }

    for (names, certificates) in schemes {
        let names = names.join(", ");
        if certificates.is_empty() {
            field(2, &names, "no certificates".yellow());
        }
        for certificate in certificates {
            field(2, &names, certificate.subject.green());
            print_certificate(certificate);
        }
    }
}

fn print_certificate(certificate: &CertificateInfo) {
    let date = |time: &str| time.split('T').next().unwrap_or(time).to_owned();

    if certificate.issuer != certificate.subject {
        field(4, "Issuer", &certificate.issuer);
    }
    field(4, "Serial", &certificate.serial_number);
    field(
        4,
        "Valid",
        format!(
            "{} → {}",
            date(&certificate.valid_from),
            date(&certificate.valid_until)
        ),
    );
    field(4, "Algorithm", &certificate.signature_type);
    field(4, "SHA-256", &certificate.sha256_fingerprint);
    field(4, "SHA-1", &certificate.sha1_fingerprint);
    field(4, "MD5", &certificate.md5_fingerprint);
}

fn print_anomalies(tampered: bool, anomalies: &[AnomalyInfo]) {
    let mut groups: Vec<Vec<&AnomalyInfo>> = Vec::new();
    for anomaly in anomalies {
        match groups
            .iter_mut()
            .find(|group| group[0].code == anomaly.code)
        {
            Some(group) => group.push(anomaly),
            None => groups.push(vec![anomaly]),
        }
    }
    // stable: kinds of one severity keep the order they were found in
    groups.sort_by_key(|group| std::cmp::Reverse(group[0].severity));

    let verdict = if tampered {
        "YES".red().bold()
    } else {
        "no".green()
    };
    let counts: Vec<String> = [Severity::Tampered, Severity::Suspicious, Severity::Info]
        .into_iter()
        .filter_map(|severity| {
            let kinds = groups
                .iter()
                .filter(|group| group[0].severity == severity)
                .count();
            (kinds != 0).then(|| format!("{kinds} {severity}"))
        })
        .collect();
    let pad = KEY_WIDTH - "Tampering".len();
    if counts.is_empty() {
        println!("{}{:pad$}{verdict}", "Tampering".blue().bold(), "");
    } else {
        println!(
            "{}{:pad$}{verdict} · {}",
            "Tampering".blue().bold(),
            "",
            counts.join(", ")
        );
    }

    let code_width = groups
        .iter()
        .map(|group| group[0].code.len())
        .max()
        .unwrap_or(0);
    let count_width = groups
        .iter()
        .map(|group| group.len().to_string().len())
        .max()
        .unwrap_or(0);

    for group in groups {
        let first = group[0];
        let marker = match first.severity {
            Severity::Tampered => "✗".red(),
            Severity::Suspicious => "!".yellow(),
            _ => "·".normal(),
        };

        let (count, rest) = match group.as_slice() {
            [one] => (
                String::new(),
                match &one.location {
                    Some(location) => format!("{location}: {}", one.detail),
                    None => one.detail.clone(),
                },
            ),
            many => {
                let located: Vec<&str> =
                    many.iter().filter_map(|a| a.location.as_deref()).collect();
                let rest = match located.len() {
                    0 => first.detail.clone(),
                    n if n <= LOCATIONS_PER_CODE => located.join(", "),
                    n => format!(
                        "{}, {}",
                        located[..LOCATIONS_PER_CODE].join(", "),
                        format!("… {} more", n - LOCATIONS_PER_CODE).dimmed()
                    ),
                };
                (many.len().to_string(), rest)
            }
        };

        println!(
            "  {marker} {:<code_width$}  {count:>count_width$}  {rest}",
            first.code
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_signature_has_a_scheme_and_a_uniform_shape() {
        let signatures = Some(vec![
            Signature::V2(Vec::new()),
            Signature::GooglePlayFrosting,
            Signature::PackerNextGenV2(vec![0xab, 0x01]),
        ]);
        let json = serde_json::to_value(SerializeSignatures(&signatures)).unwrap();
        assert_eq!(
            json,
            serde_json::json!([
                {"scheme": "v2", "certificates": []},
                {"scheme": "google_play_frosting"},
                {"scheme": "packer_next_gen_v2", "value": "ab01"},
            ])
        );
    }

    /// Runs [`serialize_signatures`] on its own.
    struct SerializeSignatures<'a>(&'a Option<Vec<Signature>>);

    impl Serialize for SerializeSignatures<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serialize_signatures(self.0, serializer)
        }
    }
}
