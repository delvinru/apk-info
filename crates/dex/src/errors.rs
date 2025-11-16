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

    #[error("got error while parsing string_ids")]
    StringError,

    #[error("got error while parsing type_ids")]
    TypeError,

    #[error("got error while parsing proto_ids")]
    ProtoError,

    #[error("got error while parsing field_ids")]
    FieldError,

    #[error("got error while parsing method_ids")]
    MethodError,

    #[error("got error while parsing class_defs")]
    ClassError,

    #[error("got unknown type item: {0}")]
    UnknownTypeItem(u16),

    #[error("got error while parsing map_list")]
    MapListError,
}
