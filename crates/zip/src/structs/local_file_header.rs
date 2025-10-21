#![allow(unused)]

use winnow::binary::{le_u16, le_u32};
use winnow::error::{ErrMode, Needed};
use winnow::prelude::*;
use winnow::token::take;

#[derive(Debug)]
pub(crate) struct LocalFileHeader {
    pub(crate) version_needed: u16,
    pub(crate) general_purpose_bit_flag: u16,
    pub(crate) compression_method: u16,
    pub(crate) last_modification_time: u16,
    pub(crate) last_modification_date: u16,
    pub(crate) crc32: u32,
    pub(crate) compressed_size: u32,
    pub(crate) uncompressed_size: u32,
    pub(crate) file_name_length: u16,
    pub(crate) extra_field_length: u16,
    pub(crate) file_name: Vec<u8>,
    pub(crate) extra_field: Vec<u8>,
}

impl LocalFileHeader {
    const MAGIC: u32 = 0x04034b50;

    #[inline(always)]
    pub fn parse(input: &[u8], offset: usize) -> ModalResult<LocalFileHeader> {
        let mut input = input
            .get(offset..)
            .ok_or(ErrMode::Incomplete(Needed::Unknown))?;

        let (
            _,
            version_needed,
            general_purpose_bit_flag,
            compression_method,
            last_modification_time,
            last_modification_date,
            crc32,
            compressed_size,
            uncompressed_size,
            file_name_length,
            extra_field_length,
        ) = (
            le_u32.verify(|magic| *magic == Self::MAGIC), // magic
            le_u16,                                       // version_needed
            le_u16,                                       // general_purpose_bit_flag
            le_u16,                                       // compression_method
            le_u16,                                       // last_modification_time
            le_u16,                                       // last_modification_date
            le_u32,                                       // crc32
            le_u32,                                       // compressed_size
            le_u32,                                       // uncompressed_size
            le_u16,                                       // file_name_length
            le_u16,                                       // extra_field_length
        )
            .parse_next(&mut input)?;

        let (file_name, extra_field) =
            (take(file_name_length), take(extra_field_length)).parse_next(&mut input)?;

        Ok(LocalFileHeader {
            version_needed,
            general_purpose_bit_flag,
            compression_method,
            last_modification_time,
            last_modification_date,
            crc32,
            compressed_size,
            uncompressed_size,
            file_name_length,
            extra_field_length,
            file_name: file_name.to_vec(),
            extra_field: extra_field.to_vec(), // can't use lifetime parameters due python limitations
        })
    }

    /// Get structure size
    ///
    /// 4 (MAGIC) + 26 (DATA) + file_name length + extra field length
    #[inline]
    pub fn size(&self) -> usize {
        30 + self.file_name.len() + self.extra_field.len()
    }
}
