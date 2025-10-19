use openssl::error::ErrorStack;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZipError {
    /// Basic sanity check
    #[error("provided file is not a zip archive")]
    InvalidHeader,

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

#[derive(Error, Debug)]
pub enum CertificateError {
    #[error("got error while parsing certificate")]
    ParseError,

    #[error("got zip error while parsing certificate: {0}")]
    ZipError(#[from] ZipError),

    #[error("got stack error: {0}")]
    StackError(#[from] ErrorStack),

    #[error("got signer error")]
    SignerError,

    #[error("size of blocks not equals (required by format) - (start - {0}, end - {1})")]
    InvalidFormat(u64, u64),
}
