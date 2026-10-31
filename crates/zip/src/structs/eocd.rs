use std::sync::Arc;

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

    pub(crate) total_entries: u16,

    #[allow(unused)]
    pub(crate) central_dir_size: u32,

    #[allow(unused)]
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

        // Clamp the comment length to the bytes actually present.
        let comment_length = comment_length.min(input.len() as u16);
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
}

/// The 64-bit counterpart of the EOCD fields, written by ZIP64 archives.
///
/// See: <https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT> (4.3.14, 4.3.15)
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Zip64EndOfCentralDirectory {
    pub(crate) total_entries: u64,
    pub(crate) central_dir_size: u64,
    pub(crate) central_dir_offset: u64,
}

impl Zip64EndOfCentralDirectory {
    /// Length of the locator that sits right before the EOCD.
    pub(crate) const LOCATOR_LEN: usize = 20;

    /// Length of the fixed part of the ZIP64 EOCD record.
    pub(crate) const RECORD_LEN: usize = 56;

    const LOCATOR_MAGIC: u32 = 0x07064b50;
    const RECORD_MAGIC: u32 = 0x06064b50;

    /// Returns the declared ZIP64 EOCD record offset from a locator.
    pub(crate) fn parse_locator(locator: &[u8]) -> Option<u64> {
        if locator.len() < Self::LOCATOR_LEN || read_u32(locator, 0) != Self::LOCATOR_MAGIC {
            return None;
        }

        Some(read_u64(locator, 8))
    }

    /// Parses the fixed part of a ZIP64 EOCD record.
    pub(crate) fn parse_record(record: &[u8]) -> Option<Zip64EndOfCentralDirectory> {
        if record.len() < Self::RECORD_LEN || read_u32(record, 0) != Self::RECORD_MAGIC {
            return None;
        }

        Some(Zip64EndOfCentralDirectory {
            total_entries: read_u64(record, 32),
            central_dir_size: read_u64(record, 40),
            central_dir_offset: read_u64(record, 48),
        })
    }
}

fn read_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"))
}

fn read_u64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().expect("8 bytes"))
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
        data.extend_from_slice(&(0xffffu16).to_le_bytes()); // comment_length
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
    fn test_oversized_comment_length_is_tolerated() {
        // A `comment_length` larger than the remaining bytes must not fail the
        // parse: we clamp to what is present (mirroring Python's zipfile), so a
        // record with a bogus length but no comment bytes parses with an empty
        // comment.
        let eocd = make_bad_eocd(&[]);
        let mut input = &eocd[..];

        let result = EndOfCentralDirectory::parse(&mut input);
        assert!(
            result.is_ok(),
            "expected oversized comment length to be tolerated"
        );
        let parsed = result.unwrap();
        assert!(parsed.comment.is_empty());
    }

    #[test]
    fn zip64_locator_and_record_parse() {
        let mut locator = Vec::new();
        locator.extend_from_slice(&0x07064b50u32.to_le_bytes());
        locator.extend_from_slice(&0u32.to_le_bytes()); // disk
        locator.extend_from_slice(&(5u64 << 32).to_le_bytes()); // record offset
        locator.extend_from_slice(&1u32.to_le_bytes()); // total disks
        assert_eq!(
            Zip64EndOfCentralDirectory::parse_locator(&locator),
            Some(5 << 32)
        );

        let mut record = Vec::new();
        record.extend_from_slice(&0x06064b50u32.to_le_bytes());
        record.extend_from_slice(&44u64.to_le_bytes()); // record size
        record.extend_from_slice(&45u16.to_le_bytes()); // version made by
        record.extend_from_slice(&45u16.to_le_bytes()); // version needed
        record.extend_from_slice(&0u32.to_le_bytes()); // disk
        record.extend_from_slice(&0u32.to_le_bytes()); // cd disk
        record.extend_from_slice(&70000u64.to_le_bytes()); // entries on disk
        record.extend_from_slice(&70000u64.to_le_bytes()); // total entries
        record.extend_from_slice(&(1u64 << 33).to_le_bytes()); // cd size
        record.extend_from_slice(&(3u64 << 32).to_le_bytes()); // cd offset
        assert_eq!(
            Zip64EndOfCentralDirectory::parse_record(&record),
            Some(Zip64EndOfCentralDirectory {
                total_entries: 70000,
                central_dir_size: 1 << 33,
                central_dir_offset: 3 << 32,
            })
        );

        // wrong magic or too short
        assert_eq!(
            Zip64EndOfCentralDirectory::parse_locator(&record[..20]),
            None
        );
        assert_eq!(
            Zip64EndOfCentralDirectory::parse_record(&record[..40]),
            None
        );
    }
}
