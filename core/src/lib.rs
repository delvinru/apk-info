//! `apk-info` provides an easy way to parse apk files using rust
//!
//! ## Introduction
//!
//! - A malware-friendly zip extractor. Great [article](https://unit42.paloaltonetworks.com/apk-badpack-malware-tampered-headers/) about `BadPack` technique;
//! - A malware-friendly axml and arsc extractor;
//! - A full AXML (Android Binary XML) implementation;
//! - A full ARSC (Android Resource) implementation;
//! - Support for extracting information contained in the `APK Signature Block 42`:
//!     - [APK Signature scheme v1](https://source.android.com/docs/security/features/apksigning);
//!     - [APK Signature scheme v2](https://source.android.com/docs/security/features/apksigning/v2);
//!     - [APK Signature scheme v3](https://source.android.com/docs/security/features/apksigning/v3);
//!     - [APK Signature scheme v3.1](https://source.android.com/docs/security/features/apksigning/v3-1);
//!     - Stamp Block v1;
//!     - Stamp Block v2;
//!     - Apk Channel Block;
//!     - Google Play Frosting (there are plans, but there is critically little information about it);
//! - Correct extraction of the MainActivity based on how the Android OS [does it](https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/core/java/android/app/ApplicationPackageManager.java#310);
//!
//! ## Example
//!
//! Get a package from given file:
//!
//! ```no_run
//! use apk_info::Apk;
//!
//! let apk = Apk::new("./file.apk").expect("can't parse apk file");
//! println!("{:?}", apk.get_package_name());
//! ```
//!
//! Get main activity:
//!
//! ```no_run
//! use apk_info::Apk;
//!
//! let apk = Apk::new("./file.apk").expect("can't parse apk file");
//! let package_name = apk.get_package_name().expect("empty package name!");
//! let main_activity = apk.get_main_activity().expect("main activity not found!");
//! println!("{}/{}", package_name, main_activity);
//! ```

pub mod apk;
pub mod errors;
pub mod models;

pub use apk::Apk;
pub use apk_info_axml::*;
pub use apk_info_zip::*;
pub use errors::APKError;
