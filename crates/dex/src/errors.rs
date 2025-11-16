//! Errors returned by this crate.
//!
//! This module contains the definitions for all error types returned by this crate.

use thiserror::Error;

/// Errors that may occur while parsing an Android XML (AXML) manifest.
#[derive(Error, Debug)]
pub enum DexError {
    #[error("got unknown dex version: {0}")]
    UnknownVersion(u16),

    #[error("invalid header")]
    InvalidHeader,

    #[error("got error while parsing strings")]
    StringsError,

    #[error("got error while parsing types")]
    TypesError,
}
