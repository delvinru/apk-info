use std::sync::Arc;

use winnow::binary::{le_u16, le_u32};
use winnow::error::{ErrMode, Needed};
use winnow::prelude::*;
use winnow::token::take;

#[derive(Debug)]
pub(crate) struct LocalFileHeader {
    #[allow(unused)]
    pub(crate) version_needed: u16,

    #[allow(unused)]
    pub(crate) general_purpose_bit_flag: u16,

    pub(crate) compression_method: u16,

    #[allow(unused)]
    pub(crate) last_modification_time: u16,

    #[allow(unused)]
    pub(crate) last_modification_date: u16,

    #[allow(unused)]
    pub(crate) crc32: u32,

    pub(crate) compressed_size: u32,

    pub(crate) uncompressed_size: u32,

    #[allow(unused)]
    pub(crate) file_name_length: u16,

    #[allow(unused)]
    pub(crate) extra_field_length: u16,

    pub(crate) file_name: Arc<[u8]>,

    pub(crate) extra_field: Arc<[u8]>,
}

impl LocalFileHeader {
    const MAGIC: u32 = 0x04034b50;

    // Parse LocalFileHeader at given offset
    #[inline(always)]
    pub(crate) fn parse(input: &[u8], offset: usize) -> ModalResult<LocalFileHeader> {
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
            file_name: Arc::from(file_name),
            extra_field: Arc::from(extra_field),
        })
    }

    /// Get structure size
    ///
    /// 4 (MAGIC) + 26 (DATA) + file_name length + extra field length
    #[inline]
    pub(crate) fn size(&self) -> usize {
        30 + self.file_name.len() + self.extra_field.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_local_file_header(file_name: &[u8], extra_field: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(&LocalFileHeader::MAGIC.to_le_bytes()); // magic
        data.extend_from_slice(&20u16.to_le_bytes()); // version_needed
        data.extend_from_slice(&0u16.to_le_bytes()); // general_purpose_bit_flag
        data.extend_from_slice(&8u16.to_le_bytes()); // compression_method (deflate)
        data.extend_from_slice(&12345u16.to_le_bytes()); // last_modification_time
        data.extend_from_slice(&23456u16.to_le_bytes()); // last_modification_date
        data.extend_from_slice(&0xDEADBEEFu32.to_le_bytes()); // crc32
        data.extend_from_slice(&111u32.to_le_bytes()); // compressed_size
        data.extend_from_slice(&222u32.to_le_bytes()); // uncompressed_size
        data.extend_from_slice(&(file_name.len() as u16).to_le_bytes()); // file_name_length
        data.extend_from_slice(&(extra_field.len() as u16).to_le_bytes()); // extra_field_length

        data.extend_from_slice(file_name); // file_name
        data.extend_from_slice(extra_field); // extra_field

        data
    }

    #[test]
    fn test_parse_valid_local_file_header() {
        let file_name = b"test.txt";
        let extra_field = b"extra information";
        let data = make_local_file_header(file_name, extra_field);

        let parsed = LocalFileHeader::parse(&data, 0).unwrap();

        assert_eq!(parsed.version_needed, 20);
        assert_eq!(parsed.general_purpose_bit_flag, 0);
        assert_eq!(parsed.compression_method, 8);
        assert_eq!(parsed.last_modification_time, 12345);
        assert_eq!(parsed.last_modification_date, 23456);
        assert_eq!(parsed.crc32, 0xDEADBEEF);
        assert_eq!(parsed.compressed_size, 111);
        assert_eq!(parsed.uncompressed_size, 222);
        assert_eq!(parsed.file_name_length, file_name.len() as u16);
        assert_eq!(parsed.extra_field_length, extra_field.len() as u16);
        assert_eq!(parsed.file_name.as_ref(), file_name);
        assert_eq!(parsed.extra_field.as_ref(), extra_field);

        // Verify size() method
        assert_eq!(parsed.size(), 30 + file_name.len() + extra_field.len());
    }

    #[test]
    fn test_parse_valid_with_offset() {
        let header = make_local_file_header(b"qwerty.txt", b"1234");
        let mut data = vec![0x00; 10]; // prefix padding
        data.extend_from_slice(&header);

        let parsed = LocalFileHeader::parse(&data, 10).unwrap();
        assert_eq!(parsed.file_name.as_ref(), b"qwerty.txt");
        assert_eq!(parsed.extra_field.as_ref(), b"1234");
    }

    #[test]
    fn test_parse_invalid_magic() {
        let mut data = make_local_file_header(b"", b"");
        data[0] = 0x00; // corrupt magic
        let result = LocalFileHeader::parse(&data, 0);
        assert!(result.is_err(), "expected error due to invalid magic");
    }

    #[test]
    fn test_parse_out_of_bounds_offset() {
        let data = make_local_file_header(b"", b"");
        let result = LocalFileHeader::parse(&data, data.len() + 10);
        assert!(result.is_err(), "expected error for out-of-bounds offset");
    }

    #[test]
    fn test_size_calculation() {
        let file_name = b"foo";
        let extra_field = b"barbaz";
        let data = make_local_file_header(file_name, extra_field);
        let parsed = LocalFileHeader::parse(&data, 0).unwrap();

        // 30 + 3 + 6 = 39
        assert_eq!(parsed.size(), 39);
    }
}
