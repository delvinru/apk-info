//! Errors returned by this crate.
//!
//! This module contains the definitions for all error types returned by this crate.

use thiserror::Error;

/// Errors that may occur while parsing an Android XML (AXML) manifest.
#[derive(Error, Debug)]
pub enum AXMLError {
    /// The provided file is too small to contain a valid manifest.
    #[error("file size too small for manifest")]
    TooSmallError,

    /// Failed to parse the header.
    #[error("failed to parse header")]
    HeaderError,

    /// The header size is invalid.
    #[error("invalid header size (expected 8, got {0})")]
    HeaderSizeError(u16),

    /// Failed to parse the resource map.
    #[error("failed to parse resource map")]
    ResourceMapError,

    /// Failed to parse the string pool.
    #[error("failed to parse string pool")]
    StringPoolError,

    /// Failed to parse the XML tree.
    #[error("failed to parse XML tree")]
    XmlTreeError,

    /// The XML tree does not have a root node.
    #[error("missing root node in XML tree")]
    MissingRoot,

    /// Failed to parse the manifest.
    #[error("failed to parse manifest")]
    ParseError,
}

/// Errors that may occur while parsing an Android resources.arsc file.
#[derive(Error, Debug)]
pub enum ARCSError {
    /// The provided file is too small to contain a valid resources.arsc file.
    #[error("file size too small for resources file")]
    TooSmallError,

    /// Failed to parse the header.
    #[error("failed to parse header")]
    HeaderError,

    /// Failed to parse the string pool.
    #[error("failed to parse string pool")]
    StringPoolError,

    /// Failed to parse the resource table package.
    #[error("failed to parse resource table package")]
    ResourceTableError,
}
