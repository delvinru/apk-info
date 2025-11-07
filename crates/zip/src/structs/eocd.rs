use std::sync::Arc;

use memchr::memmem;
use winnow::binary::{le_u16, le_u32};
use winnow::prelude::*;
use winnow::token::take;

#[derive(Debug)]
pub(crate) struct EndOfCentralDirectory {
    #[allow(unused)]
    pub(crate) disk_number: u16,

    #[allow(unused)]
    pub(crate) central_dir_start_disk: u16,

    #[allow(unused)]
    pub(crate) entries_on_this_disk: u16,

    #[allow(unused)]
    pub(crate) total_entries: u16,

    #[allow(unused)]
    pub(crate) central_dir_size: u32,

    pub(crate) central_dir_offset: u32,

    #[allow(unused)]
    pub(crate) comment_length: u16,

    #[allow(unused)]
    pub(crate) comment: Arc<[u8]>,
}

impl EndOfCentralDirectory {
    const MAGIC: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];

    #[inline(always)]
    const fn magic_u32() -> u32 {
        u32::from_le_bytes(Self::MAGIC)
    }

    /// Extract EOCD information
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<EndOfCentralDirectory> {
        let (
            _,
            disk_number,
            central_dir_start_disk,
            entries_on_this_disk,
            total_entries,
            central_dir_size,
            central_dir_offset,
            comment_length,
        ) = (
            le_u32.verify(|magic| *magic == Self::magic_u32()), // magic
            le_u16,                                             // disk_number
            le_u16,                                             // central_dir_start_disk
            le_u16,                                             // entries_on_this_disk
            le_u16,                                             // total_entries
            le_u32,                                             // central_dir_size
            le_u32,                                             // central_dir_offset
            le_u16,                                             // comment_length
        )
            .parse_next(input)?;

        let comment: &[u8] = take(comment_length).parse_next(input)?;

        Ok(EndOfCentralDirectory {
            disk_number,
            central_dir_start_disk,
            entries_on_this_disk,
            total_entries,
            central_dir_size,
            central_dir_offset,
            comment_length,
            comment: Arc::from(comment),
        })
    }

    /// Search EOCD magic from the end of the file
    pub(crate) fn find_eocd(input: &[u8], chunk_size: usize) -> Option<usize> {
        let mut end = input.len();

        while end > 0 {
            let start = end.saturating_sub(chunk_size);
            let chunk = &input[start..end];

            if let Some(pos) = memmem::rfind(chunk, &Self::MAGIC) {
                return Some(start + pos);
            }

            end = start;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_eocd(comment: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(&EndOfCentralDirectory::MAGIC); // magic
        data.extend_from_slice(&1u16.to_le_bytes()); // disk_number
        data.extend_from_slice(&2u16.to_le_bytes()); // central_dir_start_disk
        data.extend_from_slice(&3u16.to_le_bytes()); // entries_on_this_disk
        data.extend_from_slice(&4u16.to_le_bytes()); // total_entries
        data.extend_from_slice(&1234u32.to_le_bytes()); // central_dir_size
        data.extend_from_slice(&5678u32.to_le_bytes()); // central_dir_offset
        data.extend_from_slice(&(comment.len() as u16).to_le_bytes()); // comment_length
        data.extend_from_slice(comment);

        data
    }

    fn make_bad_eocd(comment: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(&EndOfCentralDirectory::MAGIC); // magic
        data.extend_from_slice(&1u16.to_le_bytes()); // disk_number
        data.extend_from_slice(&2u16.to_le_bytes()); // central_dir_start_disk
        data.extend_from_slice(&3u16.to_le_bytes()); // entries_on_this_disk
        data.extend_from_slice(&4u16.to_le_bytes()); // total_entries
        data.extend_from_slice(&1234u32.to_le_bytes()); // central_dir_size
        data.extend_from_slice(&5678u32.to_le_bytes()); // central_dir_offset
        data.extend_from_slice(&(0xffff as u16).to_le_bytes()); // comment_length
        data.extend_from_slice(comment);

        data
    }

    #[test]
    fn test_parse_valid_eocd_no_comment() {
        let data = make_eocd(&[]);
        let mut input = &data[..];
        let eocd = EndOfCentralDirectory::parse(&mut input).unwrap();

        assert_eq!(eocd.disk_number, 1);
        assert_eq!(eocd.central_dir_start_disk, 2);
        assert_eq!(eocd.entries_on_this_disk, 3);
        assert_eq!(eocd.total_entries, 4);
        assert_eq!(eocd.central_dir_size, 1234);
        assert_eq!(eocd.central_dir_offset, 5678);
        assert_eq!(eocd.comment_length, 0);
        assert!(eocd.comment.is_empty());
        assert!(input.is_empty()); // Should consume all bytes
    }

    #[test]
    fn test_parse_valid_eocd_with_comment() {
        let comment = b"some comment";
        let data = make_eocd(comment);
        let mut input = &data[..];
        let eocd = EndOfCentralDirectory::parse(&mut input).unwrap();

        assert_eq!(eocd.comment_length, comment.len() as u16);
        assert_eq!(eocd.comment.as_ref(), comment);
    }

    #[test]
    fn test_parse_invalid_magic() {
        // corrupt magic
        let mut data = make_eocd(&[]);
        data[0] = 0x00;
        let mut input = &data[..];

        let result = EndOfCentralDirectory::parse(&mut input);
        assert!(result.is_err(), "expected parse error for invalid magic");
    }

    #[test]
    fn test_find_eocd_basic() {
        let eocd = make_eocd(&[]);
        let mut file_data = vec![0x00; 100];
        let offset = 42;
        file_data.splice(offset..offset, eocd.clone());

        let found = EndOfCentralDirectory::find_eocd(&file_data, 64);
        assert_eq!(found, Some(offset));
    }

    #[test]
    fn test_find_eocd_not_found() {
        let data = vec![0x00; 128];
        let found = EndOfCentralDirectory::find_eocd(&data, 32);
        assert_eq!(found, None);
    }

    #[test]
    fn test_find_eocd_multiple_matches() {
        // Two EOCD-like sections, expect the last one
        let eocd = make_eocd(&[]);
        let mut data = Vec::new();
        data.extend_from_slice(&eocd);
        data.extend_from_slice(&[0x11; 10]);
        let last_offset = data.len();
        data.extend_from_slice(&eocd);

        let found = EndOfCentralDirectory::find_eocd(&data, 64);
        assert_eq!(found, Some(last_offset));
    }

    #[test]
    fn test_bad_comment_length() {
        let eocd = make_bad_eocd(&[]);
        let mut input = &eocd[..];

        let result = EndOfCentralDirectory::parse(&mut input);
        assert!(
            result.is_err(),
            "expected parse error for bad comment length"
        );
    }
}
