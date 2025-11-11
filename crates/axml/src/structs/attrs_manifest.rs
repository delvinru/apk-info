//! Wrapper around `phf` with manifest attributes.

use std::borrow::Cow;

include!(concat!(env!("OUT_DIR"), "/attrs_manifest_phf.rs"));

/// If AndroidManifest.xml If it contains a system attribute, then it finds the value by its name.
///
/// Depending on the type, it will return either `enum` or `flags`.
///
/// See: <https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/res/res/values/attrs_manifest.xml>
pub fn get_attr_value<'a>(name: &'a str, value: &'a u32) -> Option<Cow<'a, str>> {
    let attrs = ATTRS_MANIFEST.get(name)?;

    let mut attribute_value = *value;
    match attrs.0 {
        "enum" => {
            for &(item_name, item_value) in attrs.1.iter() {
                if item_value == attribute_value {
                    return Some(Cow::Borrowed(item_name));
                }
            }
            Some(Cow::Owned(u32::to_string(value)))
        }
        "flag" => {
            let parts: Vec<&str> = attrs
                .1
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
        _ => unreachable!(),
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
