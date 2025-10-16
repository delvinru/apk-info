use winnow::{binary::le_u32, combinator::repeat, prelude::*};

use crate::structs::res_chunk_header::ResChunkHeader;

#[derive(Debug)]
pub struct XmlResourceMapType {
    pub header: ResChunkHeader,
    pub resource_ids: Vec<u32>,
}

impl XmlResourceMapType {
    pub fn parse(input: &mut &[u8]) -> ModalResult<XmlResourceMapType> {
        let header = ResChunkHeader::parse(input)?;
        let resource_ids = repeat(
            (header.size.saturating_sub(header.header_size as u32) / 4) as usize,
            le_u32,
        )
        .parse_next(input)?;

        Ok(XmlResourceMapType {
            header,
            resource_ids,
        })
    }
}
