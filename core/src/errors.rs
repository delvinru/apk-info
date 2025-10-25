use std::io;

use apk_info_axml::errors::AXMLError;
use apk_info_zip::errors::{CertificateError, ZipError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum APKError {
    /// Generic I/O error while trying to read or write data
    #[error(transparent)]
    IoError(#[from] io::Error),

    /// Got invalid input (for example, empty file or not apk)
    #[error("got invalid input: {0}")]
    InvalidInput(&'static str),

    /// Error occurred while parsing AndroidManifest.xml
    #[error("got error while parsing AndroidManifest.xml: {0}")]
    ManifestError(#[from] AXMLError),

    /// Error occurred while parsing apk as zip archive
    #[error("got error while parsing apk archive: {0}")]
    ZipError(#[from] ZipError),

    #[error("got error while parsing certificates")]
    CertificateError(#[from] CertificateError),
}
