#![allow(unused)]

use std::collections::HashMap;

use winnow::binary::{le_u16, le_u32};
use winnow::combinator::repeat;
use winnow::error::{ErrMode, Needed};
use winnow::prelude::*;
use winnow::token::take;

use crate::structs::eocd::EndOfCentralDirectory;

#[derive(Debug)]
pub(crate) struct CentralDirectoryEntry {
    pub(crate) version_made_by: u16,
    pub(crate) version_needed: u16,
    pub(crate) general_purpose: u16,
    pub(crate) compression_method: u16,
    pub(crate) last_mod_time: u16,
    pub(crate) last_mod_date: u16,
    pub(crate) crc32: u32,
    pub(crate) compressed_size: u32,
    pub(crate) uncompressed_size: u32,
    pub(crate) file_name_length: u16,
    pub(crate) extra_field_length: u16,
    pub(crate) file_comment_length: u16,
    pub(crate) disk_number_start: u16,
    pub(crate) internal_attrs: u16,
    pub(crate) external_attrs: u32,
    pub(crate) local_header_offset: u32,

    pub(crate) file_name: String,
    pub(crate) extra_field: Vec<u8>,
    pub(crate) file_comment: Vec<u8>,
}

impl CentralDirectoryEntry {
    const MAGIC: u32 = 0x02014b50;

    #[inline(always)]
    fn parse(input: &mut &[u8]) -> ModalResult<CentralDirectoryEntry> {
        let (
            _,
            version_made_by,
            version_needed,
            general_purpose,
            compression_method,
            last_mod_time,
            last_mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            file_name_length,
            extra_field_length,
            file_comment_length,
            disk_number_start,
            internal_attrs,
            external_attrs,
            local_header_offset,
        ) = (
            le_u32.verify(|magic| *magic == Self::MAGIC), // magic
            le_u16,                                       // version_made_by
            le_u16,                                       // version_needed
            le_u16,                                       // general_purpose
            le_u16,                                       // compression_method
            le_u16,                                       // last_mod_time
            le_u16,                                       // last_mod_date
            le_u32,                                       // crc32
            le_u32,                                       // compressed_size
            le_u32,                                       // uncompressed_size
            le_u16,                                       // file_name_length
            le_u16,                                       // extra_field_length
            le_u16,                                       // file_comment_length
            le_u16,                                       // disk_number_start
            le_u16,                                       // internal_attrs
            le_u32,                                       // external_attrs
            le_u32,                                       // local_header_offset
        )
            .parse_next(input)?;

        let (file_name, extra_field, file_comment) = (
            take(file_name_length),
            take(extra_field_length),
            take(file_comment_length),
        )
            .parse_next(input)?;

        Ok(CentralDirectoryEntry {
            version_made_by,
            version_needed,
            general_purpose,
            compression_method,
            last_mod_time,
            last_mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            file_name_length,
            extra_field_length,
            file_comment_length,
            disk_number_start,
            internal_attrs,
            external_attrs,
            local_header_offset,
            file_name: String::from_utf8_lossy(file_name).to_string(),
            extra_field: extra_field.to_vec(),
            file_comment: file_comment.to_vec(), // can't use lifetime parameters due python limitations
        })
    }
}

#[derive(Debug)]
pub struct CentralDirectory {
    pub entries: HashMap<String, CentralDirectoryEntry>,
}

impl CentralDirectory {
    pub fn parse(input: &[u8], eocd: &EndOfCentralDirectory) -> ModalResult<CentralDirectory> {
        let mut input = input
            .get(eocd.central_dir_offset as usize..)
            .ok_or(ErrMode::Incomplete(Needed::Unknown))?;

        let entries: Vec<CentralDirectoryEntry> =
            repeat(0.., CentralDirectoryEntry::parse).parse_next(&mut input)?;

        Ok(CentralDirectory {
            entries: entries
                .into_iter()
                .map(|entry| (entry.file_name.clone(), entry))
                .collect(),
        })
    }
}
