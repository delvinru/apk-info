//! Structural anomalies of a `zip` archive.
//!
//! The reader recovers from damaged archives instead of failing; each
//! recovery leaves a [`ZipAnomaly`] that tells what was wrong. Whether an
//! anomaly is harmless or a sign of tampering is up to the caller.

use std::fmt;

/// A structural defect the reader recovered from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZipAnomaly {
    /// An end of central directory signature after the real record, planted
    /// in the archive comment.
    FakeEocdInComment { offset: u64 },

    /// The end of central directory record and its comment don't end at the
    /// end of the file: a broken comment length or trailing data.
    EocdNotAtEnd { expected_len: u64, actual_len: u64 },

    /// The central directory is not where the end record says: data was
    /// prepended to the archive.
    CentralDirectoryShifted { declared: u64, actual: u64 },

    /// Central directory records past the count declared in the end record.
    ExtraCentralDirectoryRecords { declared: u64, extra: u64 },

    /// Fewer central directory records than the end record declares.
    MissingCentralDirectoryRecords { declared: u64, parsed: u64 },

    /// Two central directory records with the same name; the last one wins.
    DuplicateEntry { entry: String },

    /// An entry whose path runs through another entry's file name, as in
    /// `AndroidManifest.xml/x.png`: extracting both fails on one of them.
    EntryPathConflict { entry: String, file: String },

    /// An entry name that is not valid UTF-8.
    InvalidUtf8Name { entry: String },

    /// The local header's compression method disagrees with the central
    /// directory's.
    CompressionMethodMismatch {
        entry: String,
        central: u16,
        local: u16,
    },

    /// A compression method other than stored or deflated.
    UnknownCompressionMethod { entry: String, method: u16 },

    /// A stored entry whose compressed and uncompressed sizes differ.
    StoredSizeMismatch {
        entry: String,
        compressed: u64,
        uncompressed: u64,
    },

    /// The encryption flag is set, though the data is not encrypted.
    EncryptionFlag { entry: String },

    /// The local header is not at the declared offset; it was found nearby.
    LocalHeaderShifted {
        entry: String,
        declared: u64,
        actual: u64,
    },

    /// No local header with the entry's name was found.
    LocalHeaderMissing { entry: String },
}

impl ZipAnomaly {
    /// Stable machine-readable identifier of the anomaly kind.
    pub fn code(&self) -> &'static str {
        match self {
            ZipAnomaly::FakeEocdInComment { .. } => "fake_eocd_in_comment",
            ZipAnomaly::EocdNotAtEnd { .. } => "eocd_not_at_end",
            ZipAnomaly::CentralDirectoryShifted { .. } => "central_directory_shifted",
            ZipAnomaly::ExtraCentralDirectoryRecords { .. } => "extra_central_directory_records",
            ZipAnomaly::MissingCentralDirectoryRecords { .. } => {
                "missing_central_directory_records"
            }
            ZipAnomaly::DuplicateEntry { .. } => "duplicate_entry",
            ZipAnomaly::EntryPathConflict { .. } => "entry_path_conflict",
            ZipAnomaly::InvalidUtf8Name { .. } => "invalid_utf8_name",
            ZipAnomaly::CompressionMethodMismatch { .. } => "compression_method_mismatch",
            ZipAnomaly::UnknownCompressionMethod { .. } => "unknown_compression_method",
            ZipAnomaly::StoredSizeMismatch { .. } => "stored_size_mismatch",
            ZipAnomaly::EncryptionFlag { .. } => "encryption_flag",
            ZipAnomaly::LocalHeaderShifted { .. } => "local_header_shifted",
            ZipAnomaly::LocalHeaderMissing { .. } => "local_header_missing",
        }
    }

    /// Name of the entry the anomaly is about, if it is about one.
    pub fn entry(&self) -> Option<&str> {
        match self {
            ZipAnomaly::DuplicateEntry { entry }
            | ZipAnomaly::EntryPathConflict { entry, .. }
            | ZipAnomaly::InvalidUtf8Name { entry }
            | ZipAnomaly::CompressionMethodMismatch { entry, .. }
            | ZipAnomaly::UnknownCompressionMethod { entry, .. }
            | ZipAnomaly::StoredSizeMismatch { entry, .. }
            | ZipAnomaly::EncryptionFlag { entry }
            | ZipAnomaly::LocalHeaderShifted { entry, .. }
            | ZipAnomaly::LocalHeaderMissing { entry } => Some(entry),
            _ => None,
        }
    }
}

impl fmt::Display for ZipAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZipAnomaly::FakeEocdInComment { offset } => write!(
                f,
                "end of central directory signature planted at {offset:#x}, in the archive comment"
            ),
            ZipAnomaly::EocdNotAtEnd {
                expected_len,
                actual_len,
            } => write!(
                f,
                "end of central directory ends at {expected_len:#x}, the file at {actual_len:#x}"
            ),
            ZipAnomaly::CentralDirectoryShifted { declared, actual } => write!(
                f,
                "central directory declared at {declared:#x}, found at {actual:#x}"
            ),
            ZipAnomaly::ExtraCentralDirectoryRecords { declared, extra } => write!(
                f,
                "{extra} central directory records past the declared {declared}"
            ),
            ZipAnomaly::MissingCentralDirectoryRecords { declared, parsed } => write!(
                f,
                "{declared} central directory records declared, {parsed} present"
            ),
            ZipAnomaly::DuplicateEntry { .. } => write!(f, "duplicate central directory record"),
            ZipAnomaly::EntryPathConflict { file, .. } => {
                write!(f, "path runs through the file {file:?}")
            }
            ZipAnomaly::InvalidUtf8Name { .. } => write!(f, "name is not valid UTF-8"),
            ZipAnomaly::CompressionMethodMismatch { central, local, .. } => write!(
                f,
                "compression method {central} in the central directory, {local} in the local header"
            ),
            ZipAnomaly::UnknownCompressionMethod { method, .. } => {
                write!(f, "unknown compression method {method}")
            }
            ZipAnomaly::StoredSizeMismatch {
                compressed,
                uncompressed,
                ..
            } => write!(
                f,
                "stored entry with compressed size {compressed} and uncompressed size {uncompressed}"
            ),
            ZipAnomaly::EncryptionFlag { .. } => write!(f, "encryption flag is set"),
            ZipAnomaly::LocalHeaderShifted {
                declared, actual, ..
            } => write!(
                f,
                "local header declared at {declared:#x}, found at {actual:#x}"
            ),
            ZipAnomaly::LocalHeaderMissing { .. } => write!(f, "local header not found"),
        }
    }
}
