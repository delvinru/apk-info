//! Implementation of a custom error-agnostic zip parser
//!
//! The main purpose of this crate is to correctly unpack archives damaged using the `BadPack` technique.
//!
//! ## Example
//!
//! ```no_run
//! let zip = ZipEntry::new(input).expect("can't parser zip file");
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
