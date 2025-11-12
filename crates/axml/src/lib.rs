//! A full-featured `Android Binary XML` (AXML) and `Android Resourcer` (ARSC) parser.
//!
//! Handles all kinds of techniques that are aimed at breaking "standard" parsers,
//! so it allows you to extract information from more files.
//!
//! ## Example
//!
//! ```ignore
//! let axml = AXML::new(input, None /* arsc */).expect("can't parse given axml file");
//! ```

mod arsc;
mod axml;
pub mod errors;

pub mod structs;

pub use arsc::ARSC;
pub use axml::{ANDROID_NAMESPACE, AXML};
