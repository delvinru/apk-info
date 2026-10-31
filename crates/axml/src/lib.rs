//! A full-featured `Android Binary XML` (AXML) and `Android Resource` (ARSC) parser.
//!
//! Handles all kinds of techniques that are aimed at breaking "standard" parsers,
//! so it allows you to extract information from more files.
//!
//! ## Example
//!
//! ```ignore
//! let axml = AXML::new(input, None /* arsc */).expect("can't parse given axml file");
//! ```

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/delvinru/apk-info/main/docs/assets/logo/logo-256.png"
)]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/delvinru/apk-info/main/docs/assets/logo/favicon-32.png"
)]

mod arsc;
mod axml;
pub mod errors;

pub mod structs;

pub use arsc::ARSC;
pub use axml::{ANDROID_NAMESPACE, AXML};
