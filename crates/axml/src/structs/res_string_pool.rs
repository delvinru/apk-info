use std::borrow::Cow;
use std::fmt;

use bitflags::bitflags;
use log::{info, warn};
use winnow::binary::{le_u8, le_u16, le_u32};
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

/// Convenience struct for accessing strings
///
/// The pool keeps the raw string chunk and the per-string offsets, and
/// decodes a string on access. A resource table holds tens of thousands of
/// strings; a typical query reads a handful.
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#524>
pub struct StringPool {
    pub header: ResStringPoolHeader,

    /// Raw string chunk, starting at `strings_start`
    data: Box<[u8]>,

    /// Offsets of every string, relative to `data`
    offsets: Vec<u32>,
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

        let offsets = Self::parse_u32_array(input, string_header.string_count as usize)?;

        // style_offsets are not used, but there may be cases when this value is not equal to 0, so we need to consume input
        if string_header.style_count != 0 {
            let len = (string_header.style_count as usize)
                .checked_mul(4)
                .ok_or_else(|| ErrMode::Incomplete(Needed::Unknown))?;
            let _ = take(len).parse_next(input)?;
        }

        let string_pool_size = string_header
            .header
            .size
            .saturating_sub(string_header.strings_start) as usize;

        // take just string chunk, because malware likes tampering string pool
        let (slice, rest) = input
            .split_at_checked(string_pool_size)
            .ok_or_else(|| ErrMode::Incomplete(Needed::Unknown))?;
        *input = rest;

        Ok(StringPool {
            header: string_header,
            data: slice.into(),
            offsets,
        })
    }

    /// Reads `count` little-endian `u32` values in one bounds check.
    fn parse_u32_array(input: &mut &[u8], count: usize) -> ModalResult<Vec<u32>> {
        let len = count
            .checked_mul(4)
            .ok_or_else(|| ErrMode::Incomplete(Needed::Unknown))?;
        let raw = take(len).parse_next(input)?;

        Ok(raw
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect())
    }

    /// Number of strings in the pool
    #[inline]
    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    /// Returns `true` if the pool holds no strings
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    /// Decodes the string at `offset`; malformed entries decode to an empty
    /// string to preserve index order.
    fn decode(&self, offset: u32) -> Cow<'_, str> {
        let Some(mut string_data) = self.data.get(offset as usize..) else {
            warn!("invalid string offset: 0x{:08x}", offset);
            return Cow::Borrowed("");
        };

        match Self::parse_string(&mut string_data, self.header.is_utf8()) {
            Ok(s) => s,
            Err(_) => {
                warn!(
                    "failed to parse string at offset 0x{:08x}, decoding as empty",
                    offset
                );
                Cow::Borrowed("")
            }
        }
    }

    // some shitty implementation, maybe we can do better?
    fn parse_string<'a>(input: &mut &'a [u8], is_utf8: bool) -> ModalResult<Cow<'a, str>> {
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

            Ok(Cow::Owned(Self::get_utf16_string(content)))
        } else {
            // UTF-8 strings carry two independent varint-style lengths: first the
            // character (UTF-16 code unit) count, then the UTF-8 byte count. Each is
            // one byte, extended to two bytes when its high bit is set. We must take
            // `byte_len` bytes - using the char count would truncate multibyte text.
            let mut _char_len = le_u8(input)? as usize;
            if _char_len & 0x80 != 0 {
                _char_len = ((_char_len & 0x7f) << 8) | le_u8(input)? as usize;
            }
            let mut byte_len = le_u8(input)? as usize;
            if byte_len & 0x80 != 0 {
                byte_len = ((byte_len & 0x7f) << 8) | le_u8(input)? as usize;
            }

            let content = take(byte_len).parse_next(input)?;
            // skip trailing null byte
            let _ = le_u8(input)?;

            Ok(String::from_utf8_lossy(content))
        }
    }

    #[inline]
    fn get_utf16_string(slice: &[u8]) -> String {
        let units = slice.as_chunks::<2>().0;

        // fast path for ascii, the common case in manifests and resource keys
        if units.iter().all(|c| c[1] == 0 && c[0] < 0x80) {
            let bytes = units.iter().map(|c| c[0]).collect();
            // SAFETY: the check above proves every byte is ascii
            return unsafe { String::from_utf8_unchecked(bytes) };
        }

        let mut out = String::with_capacity(units.len());
        for r in std::char::decode_utf16(units.iter().map(|c| u16::from_le_bytes(*c))) {
            match r {
                Ok(ch) => out.push(ch),
                // an unpaired surrogate invalidates the whole string
                Err(_) => return String::new(),
            }
        }
        out
    }

    /// Decodes the string at index `idx`.
    #[inline]
    pub fn get(&self, idx: u32) -> Option<Cow<'_, str>> {
        self.offsets
            .get(idx as usize)
            .map(|&offset| self.decode(offset))
    }

    /// Get string from string pool
    ///
    /// Some malware defines its own strings in the manifest in a peculiar way, therefore,
    /// for correct unpacking, we must first look at the system attributes.
    ///
    /// Examples:
    ///     - 58442d3e3a49eb41986b1099e298c78afe6726edb93b75d0b8b7b38ecd41a4a0
    ///     - 4057a9b12248b345e5c8dccf473e3df44e3663b342d48f4a63c8694e9d07c153
    #[inline]
    pub fn get_with_resources<'a>(
        &'a self,
        idx: u32,
        xml_resource: &'a XMLResourceMap,
        is_attribute_name: bool,
    ) -> Option<Cow<'a, str>> {
        xml_resource
            .get_attr(idx)
            .map(|x| {
                // need remove prefix if looked up in system attributes
                Cow::Borrowed(if is_attribute_name {
                    x.strip_prefix("android:attr/").unwrap_or(x)
                } else {
                    x
                })
            })
            .or_else(|| self.get(idx))
    }
}

impl fmt::Debug for StringPool {
    /// Shows the header, the string count and the first decoded strings;
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// Decoded strings shown before the list is cut off.
        const PREVIEW: usize = 8;

        struct Preview<'a>(&'a StringPool);

        impl fmt::Debug for Preview<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let pool = self.0;
                let mut list = f.debug_list();
                list.entries(
                    pool.offsets
                        .iter()
                        .take(PREVIEW)
                        .map(|&offset| pool.decode(offset)),
                );
                if pool.len() > PREVIEW {
                    list.finish_non_exhaustive()
                } else {
                    list.finish()
                }
            }
        }

        f.debug_struct("StringPool")
            .field("header", &self.header)
            .field("len", &self.len())
            .field("strings", &Preview(self))
            .finish()
    }
}

#[cfg(test)]
impl StringPool {
    /// Builds a utf-8 pool from plain strings.
    pub(crate) fn from_strs(strings: &[&str]) -> StringPool {
        let mut data = Vec::new();
        let mut offsets = Vec::with_capacity(strings.len());
        for s in strings {
            offsets.push(data.len() as u32);
            let len = s.len();
            assert!(len < 0x80, "test helper supports short strings only");
            data.extend_from_slice(&[len as u8, len as u8]);
            data.extend_from_slice(s.as_bytes());
            data.push(0);
        }

        StringPool {
            header: ResStringPoolHeader {
                header: Default::default(),
                string_count: strings.len() as u32,
                style_count: 0,
                flags: StringType::Utf8.bits(),
                strings_start: 0,
                styles_start: 0,
            },
            data: data.into(),
            offsets,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a utf-16 string pool chunk from raw entry bytes and parses it
    /// through [`StringPool::parse`].
    fn utf16_pool(entries: &[Vec<u8>]) -> StringPool {
        const HEADER_SIZE: u32 = 28;

        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for entry in entries {
            offsets.push(data.len() as u32);
            data.extend_from_slice(entry);
        }

        let strings_start = HEADER_SIZE + 4 * entries.len() as u32;
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&0x0001u16.to_le_bytes()); // type: string pool
        chunk.extend_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        chunk.extend_from_slice(&(strings_start + data.len() as u32).to_le_bytes());
        chunk.extend_from_slice(&(entries.len() as u32).to_le_bytes()); // string count
        chunk.extend_from_slice(&0u32.to_le_bytes()); // style count
        chunk.extend_from_slice(&0u32.to_le_bytes()); // flags: utf-16
        chunk.extend_from_slice(&strings_start.to_le_bytes());
        chunk.extend_from_slice(&0u32.to_le_bytes()); // styles start
        for offset in offsets {
            chunk.extend_from_slice(&offset.to_le_bytes());
        }
        chunk.extend_from_slice(&data);

        let mut input = &chunk[..];
        let pool = StringPool::parse(&mut input).expect("test pool should parse");
        assert!(input.is_empty(), "parse must consume the whole chunk");
        pool
    }

    /// Encodes one utf-16 entry: length (with the high-bit fixup for long
    /// strings), code units, NUL terminator.
    fn utf16_entry(units: &[u16]) -> Vec<u8> {
        let mut out = Vec::new();
        let len = units.len();
        if len > 0x7fff {
            out.extend_from_slice(&((0x8000 | (len >> 16)) as u16).to_le_bytes());
            out.extend_from_slice(&((len & 0xffff) as u16).to_le_bytes());
        } else {
            out.extend_from_slice(&(len as u16).to_le_bytes());
        }
        for unit in units {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn entry(s: &str) -> Vec<u8> {
        utf16_entry(&s.encode_utf16().collect::<Vec<_>>())
    }

    #[test]
    fn utf16_ascii_decodes_through_fast_path() {
        let pool = utf16_pool(&[entry("android:label"), entry("x")]);
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.get(0).as_deref(), Some("android:label"));
        assert_eq!(pool.get(1).as_deref(), Some("x"));
    }

    #[test]
    fn utf16_non_ascii_decodes() {
        let pool = utf16_pool(&[entry("Привет"), entry("日本語"), entry("café")]);
        assert_eq!(pool.get(0).as_deref(), Some("Привет"));
        assert_eq!(pool.get(1).as_deref(), Some("日本語"));
        assert_eq!(pool.get(2).as_deref(), Some("café"));
    }

    #[test]
    fn utf16_byte_0x80_and_above_skips_ascii_fast_path() {
        // low byte >= 0x80 with a zero high byte is latin-1, not ascii
        let pool = utf16_pool(&[entry("\u{80}\u{ff}")]);
        assert_eq!(pool.get(0).as_deref(), Some("\u{80}\u{ff}"));
    }

    #[test]
    fn utf16_surrogate_pair_decodes() {
        let pool = utf16_pool(&[entry("a😀b")]);
        assert_eq!(pool.get(0).as_deref(), Some("a😀b"));
    }

    #[test]
    fn utf16_unpaired_surrogate_decodes_as_empty() {
        let pool = utf16_pool(&[
            utf16_entry(&[0x0061, 0xd83d]), // lone high surrogate at the end
            utf16_entry(&[0xde00, 0x0061]), // lone low surrogate
            utf16_entry(&[0xd83d, 0x0061, 0x0062]), // high surrogate without its pair
        ]);
        for idx in 0..3 {
            assert_eq!(pool.get(idx).as_deref(), Some(""), "entry {idx}");
        }
    }

    #[test]
    fn utf16_empty_string_decodes() {
        let pool = utf16_pool(&[entry(""), entry("after")]);
        assert_eq!(pool.get(0).as_deref(), Some(""));
        assert_eq!(pool.get(1).as_deref(), Some("after"));
    }

    #[test]
    fn utf16_long_string_uses_length_fixup() {
        // more than 0x7fff code units needs the two-word length encoding
        let long = "ab".repeat(0x4001); // 0x8002 units
        let pool = utf16_pool(&[entry(&long), entry("next")]);
        assert_eq!(pool.get(0).as_deref(), Some(long.as_str()));
        assert_eq!(pool.get(1).as_deref(), Some("next"));
    }

    #[test]
    fn utf16_length_past_chunk_decodes_as_empty() {
        // declares 10 units but carries 2 and no terminator
        let mut bad = 10u16.to_le_bytes().to_vec();
        bad.extend_from_slice(&[b'h', 0, b'i', 0]);
        let pool = utf16_pool(&[entry("ok"), bad]);
        assert_eq!(pool.get(0).as_deref(), Some("ok"));
        assert_eq!(pool.get(1).as_deref(), Some(""));
    }

    #[test]
    fn utf16_offset_past_chunk_decodes_as_empty() {
        let mut pool = utf16_pool(&[entry("ok")]);
        pool.offsets.push(0xffff);
        assert_eq!(pool.get(1).as_deref(), Some(""));
    }

    #[test]
    fn index_out_of_range_is_none() {
        let pool = utf16_pool(&[entry("only")]);
        assert_eq!(pool.get(1), None);
        assert_eq!(pool.get(u32::MAX), None);
    }

    #[test]
    fn utf16_strings_are_owned() {
        let pool = utf16_pool(&[entry("abc")]);
        assert!(matches!(pool.get(0), Some(Cow::Owned(_))));
    }

    #[test]
    fn utf8_strings_are_borrowed() {
        let pool = StringPool::from_strs(&["abc"]);
        assert!(matches!(pool.get(0), Some(Cow::Borrowed("abc"))));
    }

    #[test]
    fn debug_previews_strings_without_raw_bytes() {
        let names: Vec<String> = (0..20).map(|i| format!("s{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let out = format!("{:?}", StringPool::from_strs(&refs));

        assert!(out.contains("len: 20"), "{out}");
        assert!(
            out.contains(r#"strings: ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", ..]"#),
            "{out}"
        );
        assert!(!out.contains("s8"), "{out}");
        assert!(!out.contains("data"), "{out}");
    }

    #[test]
    fn debug_shows_short_pools_in_full() {
        let out = format!("{:?}", StringPool::from_strs(&["a", "b"]));
        assert!(out.contains(r#"strings: ["a", "b"]"#), "{out}");
    }
}
