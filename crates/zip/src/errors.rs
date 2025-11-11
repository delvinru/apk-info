//! Errors returned by this crate.
//!
//! This module contains the definitions for all error types returned by this crate.

use openssl::error::ErrorStack;
use thiserror::Error;

/// Represents all possible errors that can occur while parsing a ZIP archive.
#[derive(Error, Debug)]
pub enum ZipError {
    /// The provided file does not have a valid ZIP header.
    #[error("provided file is not a zip archive")]
    InvalidHeader,

    /// An error occurred while decompressing a file entry.
    #[error("got error while decompressing object")]
    DecompressionError,

    /// Unexpected end-of-file (EOF) was reached while reading the ZIP archive.
    #[error("got EOF while parsing zip")]
    EOF,

    /// The requested file does not exist inside the ZIP archive.
    #[error("file not exist in zip")]
    FileNotFound,

    /// The End of Central Directory (EOCD) record could not be found, preventing operations.
    #[error("can't find EOCD in zip")]
    NotFoundEOCD,

    /// A general error occurred while parsing the ZIP archive.
    #[error("got error while parsing zip archive")]
    ParseError,
}

/// Represents all errors that can occur while handling certificates.
#[derive(Error, Debug)]
pub enum CertificateError {
    /// Failed to parse the certificate.
    #[error("got error while parsing certificate")]
    ParseError,

    /// An error occurred while parsing a ZIP archive within the certificate context.
    #[error("got zip error while parsing certificate: {0}")]
    ZipError(#[from] ZipError),

    /// An OpenSSL stack error occurred.
    #[error("got stack error: {0}")]
    StackError(#[from] ErrorStack),

    /// A signing error occurred (e.g., invalid signer or signature verification failed).
    #[error("got signer error")]
    SignerError,

    /// The certificate format is invalid because the block sizes do not match the expected values.
    #[error("size of blocks not equals (required by format) - (start - {0}, end - {1})")]
    InvalidFormat(u64, u64),
}
