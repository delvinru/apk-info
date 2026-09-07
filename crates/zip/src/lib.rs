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

pub mod compression;
pub mod entry;
pub mod errors;
pub mod signature;

mod source;
mod structs;
mod writer;

pub use compression::*;
pub use entry::*;
pub use errors::*;
pub use signature::*;
pub use source::ReadSeek;
