//! Errors returned by this crate.
//!
//! This module contains the definitions for all error types returned by this crate.

use std::io;

use apk_info_axml::errors::{ARCSError, AXMLError};
use apk_info_zip::{CertificateError, ZipError};
use thiserror::Error;

/// Possible `APK` errors
#[derive(Error, Debug)]
pub enum APKError {
    /// Generic I/O error while trying to read or write data
    #[error(transparent)]
    IoError(#[from] io::Error),

    /// Got invalid input (for example, empty file or not apk)
    #[error("got invalid input: {0}")]
    InvalidInput(&'static str),

    /// Error occurred while parsing `AndroidManifest.xml`
    #[error("got error while parsing AndroidManifest.xml: {0}")]
    ManifestError(#[from] AXMLError),

    /// Error occured while parsing `resources.arsc`
    #[error("got error while parsing resources.arsc: {0}")]
    ResourceError(#[from] ARCSError),

    #[error("got error while parsing manifest.json inside xapk: {0}")]
    XAPKManifestError(#[from] serde_json::error::Error),

    /// Error occurred while parsing apk as zip archive
    #[error("got error while parsing apk archive: {0}")]
    ZipError(#[from] ZipError),

    #[error("got error while parsing certificates: {0}")]
    CertificateError(#[from] CertificateError),
}
