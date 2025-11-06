use std::collections::HashMap;
use std::sync::Arc;

use winnow::binary::{le_u16, le_u32};
use winnow::combinator::repeat;
use winnow::error::{ErrMode, Needed, ParserError};
use winnow::prelude::*;
use winnow::token::take;

use crate::structs::eocd::EndOfCentralDirectory;

#[derive(Debug)]
pub(crate) struct CentralDirectoryEntry {
    #[allow(unused)]
    pub(crate) version_made_by: u16,

    #[allow(unused)]
    pub(crate) version_needed: u16,

    #[allow(unused)]
    pub(crate) general_purpose: u16,

    #[allow(unused)]
    pub(crate) compression_method: u16,

    #[allow(unused)]
    pub(crate) last_mod_time: u16,

    #[allow(unused)]
    pub(crate) last_mod_date: u16,

    #[allow(unused)]
    pub(crate) crc32: u32,

    pub(crate) compressed_size: u32,

    pub(crate) uncompressed_size: u32,

    #[allow(unused)]
    pub(crate) file_name_length: u16,

    #[allow(unused)]
    pub(crate) extra_field_length: u16,

    #[allow(unused)]
    pub(crate) file_comment_length: u16,

    #[allow(unused)]
    pub(crate) disk_number_start: u16,

    #[allow(unused)]
    pub(crate) internal_attrs: u16,

    #[allow(unused)]
    pub(crate) external_attrs: u32,

    pub(crate) local_header_offset: u32,

    pub(crate) file_name: Arc<str>,

    #[allow(unused)]
    pub(crate) extra_field: Arc<[u8]>,

    #[allow(unused)]
    pub(crate) file_comment: Arc<[u8]>,
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

        let file_name = std::str::from_utf8(file_name).map_err(|_| ErrMode::from_input(input))?;

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
            file_name: Arc::from(file_name),
            extra_field: Arc::from(extra_field),
            file_comment: Arc::from(file_comment),
        })
    }
}

#[derive(Debug)]
pub(crate) struct CentralDirectory {
    pub(crate) entries: HashMap<Arc<str>, CentralDirectoryEntry>,
}

impl CentralDirectory {
    #[inline(always)]
    pub(crate) fn parse(
        input: &[u8],
        eocd: &EndOfCentralDirectory,
    ) -> ModalResult<CentralDirectory> {
        let mut input = input
            .get(eocd.central_dir_offset as usize..)
            .ok_or(ErrMode::Incomplete(Needed::Unknown))?;

        let entries = repeat::<_, CentralDirectoryEntry, Vec<CentralDirectoryEntry>, _, _>(
            0..,
            CentralDirectoryEntry::parse,
        )
        .parse_next(&mut input)?
        .into_iter()
        .map(|entry| (Arc::clone(&entry.file_name), entry))
        .collect();

        Ok(CentralDirectory { entries })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn make_cde_record(
        file_name: &str,
        extra_field: &[u8],
        comment: &[u8],
        compressed_size: u32,
        uncompressed_size: u32,
        local_header_offset: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(&CentralDirectoryEntry::MAGIC.to_le_bytes()); // magic
        data.extend_from_slice(&45u16.to_le_bytes()); // version_made_by
        data.extend_from_slice(&20u16.to_le_bytes()); // version_needed
        data.extend_from_slice(&0u16.to_le_bytes()); // general_purpose
        data.extend_from_slice(&8u16.to_le_bytes()); // compression_method
        data.extend_from_slice(&1234u16.to_le_bytes()); // last_mod_time
        data.extend_from_slice(&5678u16.to_le_bytes()); // last_mod_date
        data.extend_from_slice(&0xAABBCCDDu32.to_le_bytes()); // crc32
        data.extend_from_slice(&compressed_size.to_le_bytes());
        data.extend_from_slice(&uncompressed_size.to_le_bytes());
        data.extend_from_slice(&(file_name.len() as u16).to_le_bytes());
        data.extend_from_slice(&(extra_field.len() as u16).to_le_bytes());
        data.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // disk_number_start
        data.extend_from_slice(&0u16.to_le_bytes()); // internal_attrs
        data.extend_from_slice(&0x11223344u32.to_le_bytes()); // external_attrs
        data.extend_from_slice(&local_header_offset.to_le_bytes());

        data.extend_from_slice(file_name.as_bytes()); // file_name
        data.extend_from_slice(extra_field); // extra_field
        data.extend_from_slice(comment); // comment
        data
    }

    #[test]
    fn test_parse_valid_cde_entry() {
        let file_name = "hello.txt";
        let extra = b"extra field";
        let comment = b"comment field";
        let data = make_cde_record(file_name, extra, comment, 111, 222, 333);

        let mut input = &data[..];
        let entry = CentralDirectoryEntry::parse(&mut input).unwrap();

        assert_eq!(entry.file_name.as_ref(), file_name);
        assert_eq!(entry.extra_field.as_ref(), extra);
        assert_eq!(entry.file_comment.as_ref(), comment);
        assert_eq!(entry.compressed_size, 111);
        assert_eq!(entry.uncompressed_size, 222);
        assert_eq!(entry.local_header_offset, 333);
        assert!(input.is_empty());
    }

    #[test]
    fn test_parse_invalid_magic() {
        let mut data = make_cde_record("x", &[], &[], 1, 2, 3);
        data[0] = 0x00; // corrupt magic
        let mut input = &data[..];
        let result = CentralDirectoryEntry::parse(&mut input);
        assert!(result.is_err(), "expected error on invalid magic");
    }

    #[test]
    fn test_parse_non_utf8_filename() {
        // Filename bytes that are invalid UTF-8
        let bad_bytes = [0xFF, 0xFE, 0xFD];
        let mut data = make_cde_record("", &[], &[], 0, 0, 0);
        let name_len = bad_bytes.len() as u16;

        // Patch in new filename length and name
        data[28..30].copy_from_slice(&name_len.to_le_bytes());
        data.extend_from_slice(&bad_bytes);

        let mut input = &data[..];
        let entry = CentralDirectoryEntry::parse(&mut input);

        assert!(entry.is_err());
    }

    #[test]
    fn test_parse_multiple_entries_in_directory() {
        // Two entries back-to-back
        let e1 = make_cde_record("a.txt", b"", b"", 10, 20, 30);
        let e2 = make_cde_record("b.txt", b"extra information", b"comment field", 40, 50, 60);
        let mut data = Vec::new();
        data.extend_from_slice(&e1);
        data.extend_from_slice(&e2);

        // Fake EOCD pointing to offset 0 (start)
        let eocd = EndOfCentralDirectory {
            disk_number: 0,
            central_dir_start_disk: 0,
            entries_on_this_disk: 0,
            total_entries: 0,
            central_dir_size: data.len() as u32,
            central_dir_offset: 0,
            comment_length: 0,
            comment: Arc::from([]),
        };

        let cd = CentralDirectory::parse(&data, &eocd).unwrap();
        assert_eq!(cd.entries.len(), 2);
        assert!(cd.entries.contains_key("a.txt"));
        assert!(cd.entries.contains_key("b.txt"));

        let b = cd.entries.get("b.txt").unwrap();
        assert_eq!(b.extra_field.as_ref(), b"extra information");
        assert_eq!(b.file_comment.as_ref(), b"comment field");
    }

    #[test]
    fn test_parse_central_directory_with_offset() {
        let entry = make_cde_record("offset.txt", b"", b"", 100, 200, 300);
        let mut file = vec![0xAA; 50]; // padding before
        let offset = file.len();
        file.extend_from_slice(&entry);

        let eocd = EndOfCentralDirectory {
            disk_number: 0,
            central_dir_start_disk: 0,
            entries_on_this_disk: 0,
            total_entries: 0,
            central_dir_size: entry.len() as u32,
            central_dir_offset: offset as u32,
            comment_length: 0,
            comment: Arc::from([]),
        };

        let cd = CentralDirectory::parse(&file, &eocd).unwrap();
        assert_eq!(cd.entries.len(), 1);
        assert!(cd.entries.contains_key("offset.txt"));
    }

    #[test]
    fn test_parse_central_directory_invalid_offset() {
        let data = vec![0x00; 10];
        let eocd = EndOfCentralDirectory {
            disk_number: 0,
            central_dir_start_disk: 0,
            entries_on_this_disk: 0,
            total_entries: 0,
            central_dir_size: 0,
            central_dir_offset: 9999, // invalid
            comment_length: 0,
            comment: Arc::from([]),
        };

        let result = CentralDirectory::parse(&data, &eocd);
        assert!(result.is_err(), "expected error for out-of-bounds offset");
    }
}
