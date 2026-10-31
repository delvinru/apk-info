//! Reads the minimum SDK of an APKS archive from its `toc.pb`.
//!
//! `bundletool build-apks` writes `toc.pb` as a protobuf `BuildApksResult`.
//! Each variant (`splits/`, `standalones/`, ...) targets a range of SDK
//! versions. For an app with `minSdkVersion` below 21, bundletool raises the
//! `minSdkVersion` of the split APKs to 21 (split installs need Lollipop) and
//! adds standalone APKs for older devices, so the base APK's manifest no
//! longer tells the app's minimum SDK, while the lowest variant does.
//!
//! See `commands.proto` and `targeting.proto` in bundletool:
//!
//! ```text
//! BuildApksResult.variant (1)
//!   Variant.targeting (1)
//!     VariantTargeting.sdk_version_targeting (1)
//!       SdkVersionTargeting.value (1)          alternatives (2) are other variants'
//!         SdkVersion.min (1)
//!           Int32Value.value (1)
//! ```
//!
//! A hand-written reader of the few fields needed, instead of a protobuf
//! dependency.

/// A field value of a protobuf message.
enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    /// Fixed-width values, not needed here
    Other,
}

/// Reads a base-128 varint from the front of `data`.
fn varint(data: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = data.split_first()?;
        *data = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// Iterates the fields of a message as `(field number, value)`, stopping at
/// the first malformed one.
fn fields(mut data: &[u8]) -> impl Iterator<Item = (u64, Value<'_>)> {
    std::iter::from_fn(move || {
        if data.is_empty() {
            return None;
        }
        let key = varint(&mut data)?;
        let value = match key & 7 {
            0 => Value::Varint(varint(&mut data)?),
            1 => {
                data = data.get(8..)?;
                Value::Other
            }
            2 => {
                let len = usize::try_from(varint(&mut data)?).ok()?;
                let (bytes, rest) = data.split_at_checked(len)?;
                data = rest;
                Value::Bytes(bytes)
            }
            5 => {
                data = data.get(4..)?;
                Value::Other
            }
            // groups are deprecated and not used by bundletool
            _ => return None,
        };
        Some((key >> 3, value))
    })
}

/// The embedded messages in field `number` of a message.
fn messages(data: &[u8], number: u64) -> impl Iterator<Item = &[u8]> {
    fields(data).filter_map(move |(field, value)| match value {
        Value::Bytes(bytes) if field == number => Some(bytes),
        _ => None,
    })
}

/// The lowest SDK version any variant of `toc.pb` targets.
pub(crate) fn min_sdk(toc: &[u8]) -> Option<u32> {
    messages(toc, 1) // variant
        .flat_map(|variant| messages(variant, 1)) // targeting
        .flat_map(|targeting| messages(targeting, 1)) // sdk_version_targeting
        .flat_map(|sdk| messages(sdk, 1)) // value
        .flat_map(|version| messages(version, 1)) // min
        .flat_map(fields)
        .filter_map(|(field, value)| match value {
            Value::Varint(sdk) if field == 1 => u32::try_from(sdk).ok(),
            _ => None,
        })
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(number: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![(number << 3 | 2) as u8, payload.len() as u8];
        out.extend_from_slice(payload);
        out
    }

    fn varint_field(number: u64, value: u8) -> Vec<u8> {
        vec![(number << 3) as u8, value]
    }

    /// A variant targeting `value`, with `alternatives` for the other variants.
    fn variant(value: u8, alternatives: &[u8]) -> Vec<u8> {
        let version = |sdk| field(1, &varint_field(1, sdk)); // SdkVersion.min.value
        let mut sdk = field(1, &version(value));
        for &other in alternatives {
            sdk.extend(field(2, &version(other)));
        }
        field(1, &field(1, &field(1, &sdk)))
    }

    #[test]
    fn lowest_variant_wins_and_alternatives_are_ignored() {
        let mut toc = variant(21, &[19, 32]);
        toc.extend(variant(19, &[21, 32]));
        toc.extend(variant(32, &[19, 21]));
        // an unrelated field between the variants
        toc.extend(varint_field(4, 0));
        assert_eq!(min_sdk(&toc), Some(19));

        // alternatives alone don't lower the minimum
        assert_eq!(min_sdk(&variant(21, &[1])), Some(21));
    }

    #[test]
    fn no_sdk_targeting_is_none() {
        assert_eq!(min_sdk(&[]), None);
        assert_eq!(min_sdk(&field(1, &field(2, b"x"))), None);
    }

    #[test]
    fn malformed_input_stops_without_panicking() {
        let mut toc = variant(19, &[]);
        // a length past the end, then an unfinished varint
        toc.extend([0x0a, 0x7f, 0x01]);
        assert_eq!(min_sdk(&toc), Some(19));
        assert_eq!(min_sdk(&[0x0a, 0xff]), None);
        assert_eq!(min_sdk(&[0x80; 16]), None);
        assert_eq!(min_sdk(&[0x0b, 0x00]), None); // a group
    }
}
