use winnow::binary::{le_u16, le_u32, le_u8};
use winnow::combinator::repeat;
use winnow::error::{ErrMode, Needed};
use winnow::prelude::*;
use winnow::token::take;

use crate::structs::res_chunk_header::ResChunkHeader;
use bitflags::bitflags;

bitflags! {
    #[derive(Debug)]
    pub struct StringType: u32 {
        const Sorted = 1 << 0;
        const Utf8 = 1 << 8;
    }
}

#[derive(Debug)]
pub struct ResStringPoolHeader {
    pub header: ResChunkHeader,
    pub string_count: u32,
    pub style_count: u32,
    pub flags: u32,
    pub strings_start: u32,
    pub styles_start: u32,
}

impl ResStringPoolHeader {
    pub fn parse(input: &mut &[u8]) -> ModalResult<ResStringPoolHeader> {
        let header = ResChunkHeader::parse(input)?;
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

    #[inline]
    pub fn is_sorted(&self) -> bool {
        StringType::from_bits_truncate(self.flags).contains(StringType::Sorted)
    }

    #[inline]
    pub fn is_utf8(&self) -> bool {
        StringType::from_bits_truncate(self.flags).contains(StringType::Utf8)
    }
}

#[derive(Debug)]
pub struct StringPool {
    pub header: ResStringPoolHeader,
    pub string_offsets: Vec<u32>,
    pub style_offsets: Vec<u32>,
    pub strings: Vec<String>,

    // emit additional properties
    pub invalid_string_count: bool,
}

impl StringPool {
    pub fn parse(input: &mut &[u8]) -> ModalResult<StringPool> {
        let mut string_header = ResStringPoolHeader::parse(input)?;

        let mut invalid_string_count = false;
        let calculated_string_count =
            (string_header.strings_start - (string_header.style_count * 4 + 28)) / 4;

        if calculated_string_count != string_header.string_count {
            string_header.string_count = calculated_string_count;
            invalid_string_count = true;
        }

        let string_offsets =
            repeat(string_header.string_count as usize, le_u32).parse_next(input)?;

        let style_offsets = repeat(string_header.style_count as usize, le_u32).parse_next(input)?;

        let strings = Self::parse_strings(input, &string_header, &string_offsets)?;

        Ok(StringPool {
            header: string_header,
            string_offsets,
            style_offsets,
            strings,
            invalid_string_count,
        })
    }

    fn parse_strings(
        input: &mut &[u8],
        string_header: &ResStringPoolHeader,
        string_offsets: &Vec<u32>,
    ) -> ModalResult<Vec<String>> {
        let string_pool_size = (string_header.header.size - string_header.strings_start) as usize;

        // take just string chunk, because malware likes tampering string pool
        let (slice, rest) = input
            .split_at_checked(string_pool_size)
            .ok_or_else(|| ErrMode::Incomplete(Needed::Unknown))?;
        *input = rest;

        let is_utf8 = string_header.is_utf8();
        let mut strings = Vec::with_capacity(string_header.string_count as usize);

        for &offset in string_offsets {
            if let Ok(s) = Self::parse_string(&mut &slice[offset as usize..], is_utf8) {
                strings.push(s);
            }
        }

        Ok(strings)
    }

    fn parse_string(input: &mut &[u8], is_utf8: bool) -> ModalResult<String> {
        let string = if !is_utf8 {
            // utf-16
            let u16len = le_u16(input)?;

            // check if regular utf-16 or with fixup
            let real_len = if u16len & 0x8000 != 0 {
                let u16len_fix: u16 = le_u16(input)?;
                (((u16len & 0x7FFF) as u32) << 16 | u16len_fix as u32) as usize
            } else {
                u16len as usize
            };

            let content = take(real_len * 2).parse_next(input)?;
            // skip last two bytes
            let _ = le_u16(input)?;

            Self::read_utf16(content, real_len)
        } else {
            // utf-8
            let (length1, length2) = (le_u8, le_u8).parse_next(input)?;

            let real_length = if length1 & 0x80 != 0 {
                let length = ((length1 as u16 & !0x80) << 8) | length2 as u16;
                // read and skip another 2 bytes (idk why, need research)
                let _ = le_u16(input)?;

                length as u32
            } else {
                length1 as u32
            };

            let content = take(real_length).parse_next(input)?;
            // skip last byte
            let _ = le_u8(input)?;

            String::from_utf8_lossy(content).to_string()
        };

        Ok(string)
    }

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

    pub fn get(&self, idx: u32) -> Option<&String> {
        self.strings.get(idx as usize)
    }
}
