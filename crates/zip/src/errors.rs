use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZipError {
    /// Got error while decompressing object
    #[error("got error while decompressing object")]
    DecompressionError,

    /// Got EOF while reading data
    #[error("got EOF while parsing zip")]
    EOF,

    /// Provided file not found in zip
    #[error("file not exist in zip")]
    FileNotFound,

    /// Can't operate without EOCD
    #[error("can't find EOCD in zip")]
    NotFoundEOCD,

    /// Generic parsing error
    #[error("got error while parsing zip archive")]
    ParseError,
}

/// Provide information about compression type
#[derive(Debug)]
pub enum FileCompressionType {
    /// Used stored method for decompression
    Stored,

    /// Used deflated method for decompression
    Deflated,

    /// There was an attempt to break the parser,
    /// but actually use the stored method for decompression
    StoredTampered,

    /// There was an attempt to break the parser,
    /// but actually use the deflated method for decompression
    DeflatedTampered,
}
