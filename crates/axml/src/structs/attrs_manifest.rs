//! The names of the enum and flag values of the framework's attributes.

use std::borrow::Cow;

mod table;

/// How the values of an attribute combine.
#[derive(Clone, Copy)]
enum Kind {
    /// One value at a time.
    Enum,
    /// Values ORed together.
    Flag,
}

/// The values of an attribute: names with their values.
type Values = &'static [(&'static str, u32)];

/// If AndroidManifest.xml If it contains a system attribute, then it finds the value by its name.
///
/// Depending on the type, it will return either `enum` or `flags`.
///
/// See: <https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/res/res/values/attrs_manifest.xml>
pub fn get_attr_value<'a>(name: &'a str, value: &'a u32) -> Option<Cow<'a, str>> {
    let (kind, items) = table::attr(name)?;

    let mut attribute_value = *value;
    match kind {
        Kind::Enum => {
            for &(item_name, item_value) in items {
                if item_value == attribute_value {
                    return Some(Cow::Borrowed(item_name));
                }
            }
            Some(Cow::Owned(u32::to_string(value)))
        }
        Kind::Flag => {
            let parts: Vec<&str> = items
                .iter()
                .filter_map(|&(name, val)| {
                    if val != 0 && (val & attribute_value) == val {
                        attribute_value ^= val;
                        Some(name)
                    } else {
                        None
                    }
                })
                .collect();

            if parts.is_empty() {
                None
            } else if parts.len() == 1 {
                Some(Cow::Borrowed(parts[0]))
            } else {
                Some(Cow::Owned(parts.join("|")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attr_value_1() {
        let value = get_attr_value("installLocation", &1);
        assert_eq!(value, Some(Cow::Owned("internalOnly".to_owned())))
    }

    #[test]
    fn test_attr_value_2() {
        let value = get_attr_value("recreateOnConfigChanges", &3);
        assert_eq!(value, Some(Cow::Owned("mnc|mcc".to_owned())))
    }

    #[test]
    fn test_attr_value_3() {
        let value = get_attr_value("configChanges", &0x130);
        assert_eq!(
            value,
            Some(Cow::Owned(
                "screenLayout|keyboardHidden|keyboard".to_owned()
            ))
        )
    }

    #[test]
    fn test_attr_value_4() {
        let value = get_attr_value("protectionLevel", &3);
        assert_eq!(value, Some(Cow::Owned("signatureOrSystem".to_owned())))
    }

    #[test]
    fn test_attr_value_5() {
        let value = get_attr_value("screenOrientation", &u32::MAX);
        assert_eq!(value, Some(Cow::Owned("unspecified".to_owned())))
    }
}
