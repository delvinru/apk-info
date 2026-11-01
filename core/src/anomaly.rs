//! Structural anomalies of an apk and how much each one says about tampering.

use std::fmt;

use apk_info_axml::ResAnomaly;
use apk_info_xml::is_valid_name;
use apk_info_zip::ZipAnomaly;
use serde::Serialize;

/// How strongly an anomaly points at deliberate tampering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// A quirk that ordinary build tools produce too.
    Info,

    /// Unusual: no ordinary build tool produces it, but plain corruption, an
    /// exotic tool or a commercial protector can.
    Suspicious,

    /// A known technique against static analysis tools.
    Tampered,
}

impl Severity {
    /// Lowercase name of the level.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Suspicious => "suspicious",
            Severity::Tampered => "tampered",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnomalyKind {
    /// A defect of a zip archive.
    Zip(ZipAnomaly),

    /// A defect of `AndroidManifest.xml`.
    Manifest(ResAnomaly),

    /// A defect of `resources.arsc`.
    Resources(ResAnomaly),

    /// `resources.arsc` is present but can't be read or parsed.
    ResourcesUnreadable { reason: String },

    /// The root `AndroidManifest.xml` of a container doesn't parse; the base
    /// apk inside was used instead.
    RootManifestUnreadable { reason: String },

    /// The container doesn't name its base apk; it was guessed.
    GuessedBaseApk,
}

/// A structural defect of an apk, see [`crate::Apk::anomalies`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// What is wrong.
    pub kind: AnomalyKind,

    /// How strongly it points at tampering.
    pub severity: Severity,

    /// Where: an entry name, `base.apk!classes.dex` for an entry of a
    /// container's base apk, or `None` for the archive itself.
    pub location: Option<String>,
}

impl Anomaly {
    /// Builds an anomaly, rating its severity.
    pub(crate) fn new(kind: AnomalyKind, location: Option<String>) -> Anomaly {
        Anomaly {
            severity: severity(&kind),
            kind,
            location,
        }
    }

    /// Stable machine-readable identifier of the anomaly kind.
    pub fn code(&self) -> &'static str {
        match &self.kind {
            AnomalyKind::Zip(anomaly) => anomaly.code(),
            AnomalyKind::Manifest(anomaly) | AnomalyKind::Resources(anomaly) => anomaly.code(),
            AnomalyKind::ResourcesUnreadable { .. } => "resources_unreadable",
            AnomalyKind::RootManifestUnreadable { .. } => "root_manifest_unreadable",
            AnomalyKind::GuessedBaseApk => "guessed_base_apk",
        }
    }
}

impl fmt::Display for Anomaly {
    /// The human-readable description, without the location.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            AnomalyKind::Zip(anomaly) => anomaly.fmt(f),
            AnomalyKind::Manifest(anomaly) | AnomalyKind::Resources(anomaly) => anomaly.fmt(f),
            AnomalyKind::ResourcesUnreadable { reason } => {
                write!(f, "resource table can't be read: {reason}")
            }
            AnomalyKind::RootManifestUnreadable { reason } => {
                write!(f, "root manifest of the container doesn't parse: {reason}")
            }
            AnomalyKind::GuessedBaseApk => {
                write!(f, "the container doesn't name its base apk")
            }
        }
    }
}

/// Rates an anomaly.
///
/// `Tampered` marks what no build tool produces and what breaks or misleads
/// other parsers. Calibrated against a corpus of clean apps: nothing rated
/// `Tampered` should show up there.
fn severity(kind: &AnomalyKind) -> Severity {
    match kind {
        AnomalyKind::Zip(anomaly) => zip_severity(anomaly),
        AnomalyKind::Manifest(anomaly) | AnomalyKind::Resources(anomaly) => res_severity(anomaly),
        AnomalyKind::ResourcesUnreadable { .. } => Severity::Tampered,
        AnomalyKind::RootManifestUnreadable { .. } => Severity::Suspicious,
        AnomalyKind::GuessedBaseApk => Severity::Info,
    }
}

fn zip_severity(anomaly: &ZipAnomaly) -> Severity {
    match anomaly {
        ZipAnomaly::FakeEocdInComment { .. }
        | ZipAnomaly::ExtraCentralDirectoryRecords { .. }
        | ZipAnomaly::DuplicateEntry { .. }
        | ZipAnomaly::EntryPathConflict { .. }
        | ZipAnomaly::InvalidUtf8Name { .. }
        | ZipAnomaly::CompressionMethodMismatch { .. }
        | ZipAnomaly::UnknownCompressionMethod { .. }
        | ZipAnomaly::StoredSizeMismatch { .. }
        | ZipAnomaly::EncryptionFlag { .. } => Severity::Tampered,

        ZipAnomaly::EocdNotAtEnd { .. }
        | ZipAnomaly::CentralDirectoryShifted { .. }
        | ZipAnomaly::MissingCentralDirectoryRecords { .. }
        | ZipAnomaly::LocalHeaderShifted { .. }
        | ZipAnomaly::LocalHeaderMissing { .. } => Severity::Suspicious,

        // a kind not rated yet
        _ => Severity::Suspicious,
    }
}

fn res_severity(anomaly: &ResAnomaly) -> Severity {
    match anomaly {
        ResAnomaly::InvalidAttributeName { name } if !is_decoy_name(name) => Severity::Tampered,
        ResAnomaly::StringPoolGarbageChunk { .. }
        | ResAnomaly::StringCountMismatch { .. }
        | ResAnomaly::StringOffsetsOutOfBounds { .. }
        | ResAnomaly::NonXmlChunk { .. }
        | ResAnomaly::XmlNodeHeaderSize { .. }
        | ResAnomaly::AttributeStartShifted { .. }
        | ResAnomaly::AttributeSizeMismatch { .. }
        | ResAnomaly::ElementTrailingBytes { .. }
        | ResAnomaly::InvalidElementName { .. }
        | ResAnomaly::PackageHeaderSize { .. }
        | ResAnomaly::TypeEntriesOutOfBounds { .. } => Severity::Tampered,

        // a decoy name, see `is_decoy_name`
        ResAnomaly::InvalidAttributeName { .. }
        | ResAnomaly::UnknownChunk { .. }
        | ResAnomaly::TruncatedXml
        | ResAnomaly::UnclosedElements { .. }
        | ResAnomaly::NoPackages
        | ResAnomaly::DuplicatePackageId { .. } => Severity::Suspicious,

        ResAnomaly::DuplicateTypeChunk { .. } => Severity::Info,

        // a kind not rated yet
        _ => Severity::Suspicious,
    }
}

/// `android:name` as a plain string, with no namespace and no resource id:
/// Android ignores it, a parser matching names as text takes its decoy
/// value. Seen in protected clean apps too.
fn is_decoy_name(name: &str) -> bool {
    name.split_once(':')
        .is_some_and(|(prefix, local)| is_valid_name(prefix) && is_valid_name(local))
}
