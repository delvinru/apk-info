use bitflags::bitflags;
use log::{info, warn};
use winnow::binary::{le_u8, le_u16, le_u32};
use winnow::combinator::repeat;
use winnow::error::{ErrMode, Needed};
use winnow::prelude::*;
use winnow::token::take;

use crate::structs::{ResChunkHeader, ResourceHeaderType, XMLResourceMap};

bitflags! {
    #[derive(Debug)]
    pub struct StringType: u32 {
        const Sorted = 1 << 0;
        const Utf8 = 1 << 8;
    }
}

/// Definition for a pool of strings.
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#472>
#[derive(Debug)]
pub struct ResStringPoolHeader {
    pub header: ResChunkHeader,

    /// Number of strings in this pool.
    pub string_count: u32,

    /// Number of style span arrays in the pool.
    pub style_count: u32,

    /// Possible flags
    pub flags: u32,

    // Index from header of the string data.
    pub strings_start: u32,

    /// Index from header of the style data.
    pub styles_start: u32,
}

impl ResStringPoolHeader {
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<ResStringPoolHeader> {
        let mut header = ResChunkHeader::parse(input)?;

        // TODO: research all APKEditor shenanigans with confuser stuff and highlight it
        // The shitty APKEditor confuser that is used for malware purposes, fuck it
        // https://github.com/REAndroid/APKEditor/blob/master/src/main/java/com/reandroid/apkeditor/protect/TableConfuser.java#L41
        // 791c3ed2d1cd986da043bb1b655098d2b7a0b99450440d756bc898f84a88fe3b
        // 131135a7c911bd45db8801ca336fc051246280c90ae5dafc33e68499d8514761
        if header.type_ != ResourceHeaderType::StringPool {
            let garbage_bytes = header.size.saturating_sub(ResChunkHeader::size_of() as u32);
            let _ = take(garbage_bytes as usize).parse_next(input)?;
            info!("malformed string pool, skipped {} bytes", garbage_bytes);

            header = ResChunkHeader::parse(input)?;
        }

        let (string_count, style_count, flags, strings_start, styles_start) =
            (le_u32, le_u32, le_u32, le_u32, le_u32).parse_next(input)?;

        Ok(ResStringPoolHeader {
            header,
            string_count,
            style_count,
            flags,
            strings_start,
            styles_start,
        })
    }

    // currently not using, but maybe in the future
    #[inline]
    pub fn is_sorted(&self) -> bool {
        StringType::from_bits_truncate(self.flags).contains(StringType::Sorted)
    }

    #[inline]
    pub fn is_utf8(&self) -> bool {
        StringType::from_bits_truncate(self.flags).contains(StringType::Utf8)
    }
}

/// Convience struct for accessing strings
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#524>
#[derive(Debug)]
pub struct StringPool {
    pub header: ResStringPoolHeader,

    // The raw values of the offests are useless, so we don't save them
    // pub(crate) string_offsets: Vec<u32>,
    // pub(crate) style_offsets: Vec<u32>,
    /// List of parsed strings
    pub strings: Vec<String>,
}

impl StringPool {
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<StringPool> {
        let mut string_header = ResStringPoolHeader::parse(input)?;

        let calculated_string_count = string_header.strings_start.saturating_sub(
            string_header
                .style_count
                .saturating_mul(4)
                .saturating_add(28),
        ) / 4;

        if calculated_string_count != string_header.string_count {
            info!(
                "malformed string pool, expected {} strings, actually {} strings",
                string_header.string_count, calculated_string_count
            );

            string_header.string_count = calculated_string_count;
        }

        let string_offsets =
            repeat(string_header.string_count as usize, le_u32).parse_next(input)?;

        // style_offsets are not used, but there may be cases when this value is not equal to 0, so we need to consume input
        if string_header.style_count != 0 {
            repeat(string_header.style_count as usize, le_u32).parse_next(input)?
        }

        let strings = Self::parse_strings(input, &string_header, &string_offsets)?;

        Ok(StringPool {
            header: string_header,
            strings,
        })
    }

    fn parse_strings(
        input: &mut &[u8],
        string_header: &ResStringPoolHeader,
        string_offsets: &Vec<u32>,
    ) -> ModalResult<Vec<String>> {
        let string_pool_size = string_header
            .header
            .size
            .saturating_sub(string_header.strings_start) as usize;

        // take just string chunk, because malware likes tampering string pool
        let (slice, rest) = input
            .split_at_checked(string_pool_size)
            .ok_or_else(|| ErrMode::Incomplete(Needed::Unknown))?;
        *input = rest;

        let is_utf8 = string_header.is_utf8();
        let mut strings = Vec::with_capacity(string_header.string_count as usize);

        // There is no streaming parsing because malware often "plays" with strings,
        // so it is much safer to read the entire chunk and already work with it.
        for &offset in string_offsets {
            if offset as usize >= slice.len() {
                warn!("invalid string offset: 0x{:08x}", offset);
                // push empty string to preserve index order
                strings.push(String::new());
                continue;
            }

            let mut string_data = &slice[offset as usize..];

            match Self::parse_string(&mut string_data, is_utf8) {
                Ok(s) => strings.push(s),
                Err(e) => {
                    warn!("failed to parse string at offset 0x{:08x}: {:?}", offset, e);
                    // push empty string to preserve index order
                    strings.push(String::new());
                }
            }
        }

        Ok(strings)
    }

    // some shitty implementation, maybe we can do better?
    fn parse_string(input: &mut &[u8], is_utf8: bool) -> ModalResult<String> {
        if !is_utf8 {
            // utf-16
            let u16len = le_u16(input)?;

            // check if regular utf-16 or with fixup
            let real_len = if u16len & 0x8000 != 0 {
                let hi = (u16len & 0x7fff) as u32;
                let lo = le_u16(input)? as u32;
                ((hi << 16) | lo) as usize
            } else {
                u16len as usize
            };

            let content = take(real_len * 2).parse_next(input)?;
            // skip last two bytes
            let _ = le_u16(input)?;

            Ok(Self::read_utf16(content, real_len))
        } else {
            // utf-8 strings contains two lengths, as they might differ
            let (length1, length2) = (le_u8, le_u8).parse_next(input)?;

            let real_length = if length1 & 0x80 != 0 {
                let length = ((length1 as u16 & !0x80) << 8) | length2 as u16;
                // read and skip another 2 bytes (idk why, need research)
                let _ = le_u16(input)?;

                length as u32
            } else {
                length2 as u32
            };

            let content = take(real_length).parse_next(input)?;
            // skip last byte
            let _ = le_u8(input)?;

            Ok(String::from_utf8_lossy(content).into_owned())
        }
    }

    #[inline]
    fn read_utf16(slice: &[u8], size: usize) -> String {
        std::char::decode_utf16(
            slice
                .chunks_exact(2)
                .take(size)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])),
        )
        .collect::<Result<String, _>>()
        .unwrap_or_default()
    }

    #[inline]
    pub fn get(&self, idx: u32) -> Option<&String> {
        self.strings.get(idx as usize)
    }

    #[inline]
    pub fn get_with_resources<'a>(
        &'a self,
        idx: u32,
        xml_resource: &'a XMLResourceMap,
        is_attribute_name: bool,
    ) -> Option<&'a str> {
        self.strings
            .get(idx as usize)
            .map(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                xml_resource.get_attr(idx).map(|x| {
                    // need remove prefix if looked up in system attributes
                    if is_attribute_name {
                        x.strip_prefix("android:attr/").unwrap_or(x)
                    } else {
                        x
                    }
                })
            })
    }
}
