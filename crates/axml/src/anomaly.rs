//! Structural anomalies found while parsing `AXML` and `ARSC` data.
//!
//! The parsers recover from damaged chunks instead of failing; each recovery
//! leaves a [`ResAnomaly`] that tells what was wrong, up to [`MAX_PER_KIND`]
//! of each kind. Whether an anomaly is harmless or a sign of tampering is up
//! to the caller.

use std::fmt;

use winnow::stream::Stateful;

/// Parser input that collects the anomalies met along the way.
pub type Input<'a> = Stateful<&'a [u8], Anomalies>;

/// Wraps `bytes` into an [`Input`] with no anomalies yet.
#[inline]
pub(crate) fn input(bytes: &[u8]) -> Input<'_> {
    Stateful {
        input: bytes,
        state: Anomalies::default(),
    }
}

/// Anomalies of one kind kept at most: a document of garbage chunks would
/// otherwise grow the list by one per chunk, millions in a crafted file.
pub const MAX_PER_KIND: usize = 16;

/// Number of [`ResAnomaly`] kinds.
const KINDS: usize = 18;

/// Collects anomalies, keeping the first [`MAX_PER_KIND`] of each kind.
#[derive(Debug, Default)]
pub struct Anomalies {
    list: Vec<ResAnomaly>,
    counts: [usize; KINDS],
}

impl Anomalies {
    /// Records an anomaly, unless its kind is already at the limit.
    #[inline]
    pub(crate) fn push(&mut self, anomaly: ResAnomaly) {
        let count = &mut self.counts[anomaly.kind_index()];
        if *count < MAX_PER_KIND {
            *count += 1;
            self.list.push(anomaly);
        }
    }

    pub(crate) fn into_vec(self) -> Vec<ResAnomaly> {
        self.list
    }
}

/// A structural defect the parser recovered from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResAnomaly {
    /// A chunk of another type where a string pool was expected, skipped
    /// (the APKEditor `TableConfuser`).
    StringPoolGarbageChunk { chunk_type: u16, skipped: u32 },

    /// The declared string count disagrees with the size of the offsets array.
    StringCountMismatch { declared: u32, actual: u32 },

    /// String offsets that point past the string data.
    StringOffsetsOutOfBounds { count: usize },

    /// A chunk inside the XML tree that is not an XML node, skipped along
    /// with the run of such chunks it starts.
    NonXmlChunk { chunk_type: u16 },

    /// An XML node chunk whose header size is not `0x10`, skipped along with
    /// the run of such chunks it starts.
    XmlNodeHeaderSize { header_size: u16 },

    /// A chunk of a type the parser doesn't know, skipped along with the run
    /// of such chunks it starts.
    UnknownChunk { chunk_type: u16 },

    /// Attributes start further than right after the element header.
    AttributeStartShifted { attribute_start: u16 },

    /// An attribute record is larger than the standard 20 bytes.
    AttributeSizeMismatch { attribute_size: u16 },

    /// Bytes left over at the end of an XML element chunk.
    ElementTrailingBytes { len: u32 },

    /// An element whose name can't be read or written as XML.
    InvalidElementName { name: Option<String> },

    /// An attribute whose name can't be written as XML, dropped.
    InvalidAttributeName { name: String },

    /// The XML tree ends in the middle of a node.
    TruncatedXml,

    /// Elements left open at the end of the document.
    UnclosedElements { count: usize },

    /// The resource table declares no packages.
    NoPackages,

    /// A second package with an id already seen, skipped.
    DuplicatePackageId { id: u8 },

    /// A package header of an unexpected size; the extra bytes were skipped.
    PackageHeaderSize { header_size: u16 },

    /// A type chunk's entry index array is larger than the chunk itself.
    TypeEntriesOutOfBounds { type_id: u8 },

    /// A second type chunk with the same id and configuration, skipped.
    DuplicateTypeChunk { type_id: u8 },
}

impl ResAnomaly {
    /// Position of the kind in the declaration, for [`Anomalies`].
    fn kind_index(&self) -> usize {
        match self {
            ResAnomaly::StringPoolGarbageChunk { .. } => 0,
            ResAnomaly::StringCountMismatch { .. } => 1,
            ResAnomaly::StringOffsetsOutOfBounds { .. } => 2,
            ResAnomaly::NonXmlChunk { .. } => 3,
            ResAnomaly::XmlNodeHeaderSize { .. } => 4,
            ResAnomaly::UnknownChunk { .. } => 5,
            ResAnomaly::AttributeStartShifted { .. } => 6,
            ResAnomaly::AttributeSizeMismatch { .. } => 7,
            ResAnomaly::ElementTrailingBytes { .. } => 8,
            ResAnomaly::InvalidElementName { .. } => 9,
            ResAnomaly::InvalidAttributeName { .. } => 10,
            ResAnomaly::TruncatedXml => 11,
            ResAnomaly::UnclosedElements { .. } => 12,
            ResAnomaly::NoPackages => 13,
            ResAnomaly::DuplicatePackageId { .. } => 14,
            ResAnomaly::PackageHeaderSize { .. } => 15,
            ResAnomaly::TypeEntriesOutOfBounds { .. } => 16,
            ResAnomaly::DuplicateTypeChunk { .. } => 17,
        }
    }

    /// Stable machine-readable identifier of the anomaly kind.
    pub fn code(&self) -> &'static str {
        match self {
            ResAnomaly::StringPoolGarbageChunk { .. } => "string_pool_garbage_chunk",
            ResAnomaly::StringCountMismatch { .. } => "string_count_mismatch",
            ResAnomaly::StringOffsetsOutOfBounds { .. } => "string_offsets_out_of_bounds",
            ResAnomaly::NonXmlChunk { .. } => "non_xml_chunk",
            ResAnomaly::XmlNodeHeaderSize { .. } => "xml_node_header_size",
            ResAnomaly::UnknownChunk { .. } => "unknown_chunk",
            ResAnomaly::AttributeStartShifted { .. } => "attribute_start_shifted",
            ResAnomaly::AttributeSizeMismatch { .. } => "attribute_size_mismatch",
            ResAnomaly::ElementTrailingBytes { .. } => "element_trailing_bytes",
            ResAnomaly::InvalidElementName { .. } => "invalid_element_name",
            ResAnomaly::InvalidAttributeName { .. } => "invalid_attribute_name",
            ResAnomaly::TruncatedXml => "truncated_xml",
            ResAnomaly::UnclosedElements { .. } => "unclosed_elements",
            ResAnomaly::NoPackages => "no_packages",
            ResAnomaly::DuplicatePackageId { .. } => "duplicate_package_id",
            ResAnomaly::PackageHeaderSize { .. } => "package_header_size",
            ResAnomaly::TypeEntriesOutOfBounds { .. } => "type_entries_out_of_bounds",
            ResAnomaly::DuplicateTypeChunk { .. } => "duplicate_type_chunk",
        }
    }
}

impl fmt::Display for ResAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResAnomaly::StringPoolGarbageChunk {
                chunk_type,
                skipped,
            } => write!(
                f,
                "chunk of type {chunk_type:#06x} ({skipped} bytes) in place of the string pool"
            ),
            ResAnomaly::StringCountMismatch { declared, actual } => write!(
                f,
                "string pool declares {declared} strings, its offsets hold {actual}"
            ),
            ResAnomaly::StringOffsetsOutOfBounds { count } => {
                write!(f, "{count} string offsets point past the string data")
            }
            ResAnomaly::NonXmlChunk { chunk_type } => {
                write!(f, "chunk of type {chunk_type:#06x} inside the xml tree")
            }
            ResAnomaly::XmlNodeHeaderSize { header_size } => {
                write!(f, "xml node header size is {header_size:#x}, not 0x10")
            }
            ResAnomaly::UnknownChunk { chunk_type } => {
                write!(f, "unknown chunk type {chunk_type:#06x}")
            }
            ResAnomaly::AttributeStartShifted { attribute_start } => {
                write!(f, "attributes start at {attribute_start:#x}, not 0x14")
            }
            ResAnomaly::AttributeSizeMismatch { attribute_size } => {
                write!(f, "attribute size is {attribute_size:#x}, not 0x14")
            }
            ResAnomaly::ElementTrailingBytes { len } => {
                write!(f, "{len} bytes after the attributes of an element")
            }
            ResAnomaly::InvalidElementName { name: Some(name) } => {
                write!(f, "element name {name:?} is not valid xml")
            }
            ResAnomaly::InvalidElementName { name: None } => {
                write!(f, "element name is not in the string pool")
            }
            ResAnomaly::InvalidAttributeName { name } => {
                write!(f, "attribute name {name:?} is not valid xml")
            }
            ResAnomaly::TruncatedXml => write!(f, "the xml tree ends in the middle of a node"),
            ResAnomaly::UnclosedElements { count } => {
                write!(f, "{count} elements are never closed")
            }
            ResAnomaly::NoPackages => write!(f, "resource table declares no packages"),
            ResAnomaly::DuplicatePackageId { id } => write!(f, "duplicate package id {id:#04x}"),
            ResAnomaly::PackageHeaderSize { header_size } => {
                write!(f, "package header size is {header_size:#x}")
            }
            ResAnomaly::TypeEntriesOutOfBounds { type_id } => write!(
                f,
                "entry indices of type {type_id:#04x} extend beyond its chunk"
            ),
            ResAnomaly::DuplicateTypeChunk { type_id } => {
                write!(f, "duplicate chunk of type {type_id:#04x}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_at_most_max_per_kind() {
        let mut anomalies = Anomalies::default();
        for chunk_type in 0..100 {
            anomalies.push(ResAnomaly::UnknownChunk { chunk_type });
        }
        anomalies.push(ResAnomaly::NoPackages);

        let list = anomalies.into_vec();
        assert_eq!(list.len(), MAX_PER_KIND + 1);
        // the first ones are kept
        assert_eq!(list[0], ResAnomaly::UnknownChunk { chunk_type: 0 });
        assert_eq!(list[MAX_PER_KIND], ResAnomaly::NoPackages);
    }
}
