//! Possible types of compression.

/// Represents the type of compression used for a file in a ZIP archive.
#[derive(Debug)]
pub enum FileCompressionType {
    /// The file is stored without compression.
    Stored,

    /// The file is compressed using the `Deflate` algorithm.
    Deflated,

    /// The file appears tampered but is actually stored without compression.
    StoredTampered,

    /// The file appears tampered but is actually compressed with Deflate.
    DeflatedTampered,
}
