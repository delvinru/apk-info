//! The names of the framework's resources, by id.

mod table;

/// If AndroidManifest.xml refers to the system name, then finds it and returns.
///
/// See: <https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/res/res/values/public-final.xml>
#[inline(always)]
pub fn get_type_name(id: &u32) -> Option<&'static str> {
    if id >> 24 != 0x01 {
        return None;
    }
    let entries = table::SYSTEM_TYPES.get(((id >> 16) & 0xff) as usize)?;
    let name = *entries.get((id & 0xffff) as usize)?;
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_attribute_has_its_name() {
        assert_eq!(get_type_name(&0x0101_0000), Some("android:attr/theme"));
    }

    #[test]
    fn system_bool_has_its_name() {
        assert_eq!(
            get_type_name(&0x0111_0000),
            Some("android:bool/config_sendPackageName")
        );
    }
}
