use memchr::memmem;

use winnow::{
    binary::{le_u16, le_u32},
    prelude::*,
    token::take,
};

#[derive(Debug)]
pub struct EndOfCentralDirectory {
    pub disk_number: u16,
    pub central_dir_start_disk: u16,
    pub entries_on_this_disk: u16,
    pub total_entries: u16,
    pub central_dir_size: u32,
    pub central_dir_offset: u32,
    pub comment_length: u16,
    pub comment: Vec<u8>,
}

impl EndOfCentralDirectory {
    const MAGIC: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];

    #[inline(always)]
    const fn magic_u32() -> u32 {
        u32::from_le_bytes(Self::MAGIC)
    }

    pub fn parse(input: &mut &[u8]) -> ModalResult<EndOfCentralDirectory> {
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

        let comment = take(comment_length).parse_next(input)?;

        Ok(EndOfCentralDirectory {
            disk_number,
            central_dir_start_disk,
            entries_on_this_disk,
            total_entries,
            central_dir_size,
            central_dir_offset,
            comment_length,
            comment: comment.to_vec(), // can't use lifetime parameters due python limitations
        })
    }

    /// Searching magic from the end of the file
    pub fn find_eocd(input: &[u8], chunk_size: usize) -> Option<usize> {
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
