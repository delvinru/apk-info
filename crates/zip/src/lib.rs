//! Implementation of a custom error-agnostic zip parser
//!
//! The main purpose of this crate is to correctly unpack archives damaged using the `BadPack` technique.
//!
//! Archives are read lazily from any seekable source ([`ZipEntry::open`],
//! [`ZipEntry::from_reader`], [`ZipEntry::new`]): only the central directory
//! is kept in memory, so a multi-gigabyte apk costs as much memory as the
//! entries actually requested.
//!
//! ## Example
//!
//! ```no_run
//! # use apk_info_zip::ZipEntry;
//! let zip = ZipEntry::open("app.apk").expect("can't parse zip file");
//! let (data, compression_method) = zip.read("AndroidManifest.xml").expect("can't read manifest");
//! ```

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/delvinru/apk-info/main/docs/assets/logo/logo-256.png"
)]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/delvinru/apk-info/main/docs/assets/logo/favicon-32.png"
)]

pub mod anomaly;
pub mod compression;
pub mod entry;
pub mod errors;
pub mod signature;

mod ber;
mod name;
mod source;
mod structs;
mod writer;

pub use anomaly::ZipAnomaly;
pub use compression::*;
pub use entry::*;
pub use errors::*;
pub use signature::*;
pub use source::ReadSeek;

/// Internals reachable from the fuzz targets only.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    /// See `ber::to_der`.
    pub fn ber_to_der(input: &[u8]) -> Option<Vec<u8>> {
        crate::ber::to_der(input)
    }
}
