//! Fast, malware-robust parser for Android apk/xapk/apkm/apks files.
//!
//! Documentation: <https://delvinru.github.io/apk-info/>
//!
//! ## Features
//!
//! - A malware-friendly zip reader that reads archives the way Android does, including the `BadPack` technique (great [article](https://unit42.paloaltonetworks.com/apk-badpack-malware-tampered-headers/) about it) and ZIP64;
//! - XAPK, APKM and APKS containers, opened through their base APK;
//! - A full AXML (Android Binary XML) and ARSC (Android Resource) implementation, robust against garbage chunks;
//! - Support for extracting information contained in the `APK Signing Block`:
//!     - [APK Signature scheme v1](https://source.android.com/docs/security/features/apksigning);
//!     - [APK Signature scheme v2](https://source.android.com/docs/security/features/apksigning/v2);
//!     - [APK Signature scheme v3](https://source.android.com/docs/security/features/apksigning/v3);
//!     - [APK Signature scheme v3.1](https://source.android.com/docs/security/features/apksigning/v3-1);
//!     - [APK Signature scheme v3.2](https://source.android.com/docs/security/features/apksigning/v3-2);
//!     - Stamp Block v1 & v2;
//!     - Channel blocks: [Walle](https://github.com/Meituan-Dianping/walle), [VasDolly v2](https://github.com/Tencent/VasDolly), [Packer NG v2](https://github.com/mcxiaoke/packer-ng-plugin), ByteDance;
//!     - Google Play Frosting (presence only, its structure isn't public);
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

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/delvinru/apk-info/main/docs/assets/logo/logo-256.png"
)]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/delvinru/apk-info/main/docs/assets/logo/favicon-32.png"
)]

pub mod apk;
pub mod errors;
pub mod models;
mod toc;

pub use apk::Apk;
pub use apk_info_axml::*;
pub use apk_info_zip::*;
pub use errors::APKError;
