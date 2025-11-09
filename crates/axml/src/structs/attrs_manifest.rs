include!(concat!(env!("OUT_DIR"), "/attrs_manifest_phf.rs"));

#[inline]
pub fn get_attr_value(name: &str, value: &u32) -> Option<String> {
    let attrs = ATTRS_MANIFEST.get(name)?;
    let i64_value = if *value == u32::MAX {
        -1
    } else {
        *value as i64
    };

    match attrs.0 {
        "enum" => {
            for &(item_name, item_value) in attrs.1.iter() {
                if item_value == i64_value {
                    return Some(item_name.to_string());
                }
            }
            Some(i64_value.to_string())
        }
        "flag" => {
            let mut result = String::new();
            for &(flag_name, flag_value) in attrs.1.iter() {
                if flag_value == i64_value {
                    result.push_str(flag_name);
                    break;
                } else if flag_value != 0 && flag_value & i64_value == flag_value {
                    if !result.is_empty() {
                        result.push('|');
                    }
                    result.push_str(flag_name);
                }
            }
            Some(result)
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_attr_value_1() {
        let value = get_attr_value("installLocation", &1);
        assert_eq!(value, Some("internalOnly".to_owned()))
    }

    #[test]
    fn get_attr_value_2() {
        let value = get_attr_value("recreateOnConfigChanges", &3);
        assert_eq!(value, Some("mcc|mnc".to_owned()))
    }

    #[test]
    fn get_attr_value_3() {
        let value = get_attr_value("configChanges", &0x130);
        assert_eq!(
            value,
            Some("keyboard|keyboardHidden|screenLayout".to_owned())
        )
    }
}
