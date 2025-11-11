//! Implementation of a custom error-agnostic zip extractor
//!
//! The main purpose of this crate is to correctly unpack archives damaged using the `BadPack` technique.
//!
//! ## Example
//!
//! ```no_run
//! let zip = ZipEntry::new(input);
//! let (data, compression_method) = zip.read("AndroidManifest.xml");
//! ```

pub mod compression;
pub mod entry;
pub mod errors;
pub mod signature;

mod structs;
pub use compression::*;
pub use entry::*;
pub use errors::*;
pub use signature::*;
