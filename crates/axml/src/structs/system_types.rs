//! Wrapper around `phf` with system attributes.

include!(concat!(env!("OUT_DIR"), "/system_types_phf.rs"));

/// If AndroidManifest.xml refers to the system name, then finds it and returns.
///
/// See: <https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/res/res/values/public-final.xml>
#[inline(always)]
pub fn get_type_name(id: &u32) -> Option<&'static str> {
    SYSTEM_TYPES.get(id).copied()
}
