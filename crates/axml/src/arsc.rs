use log::warn;
use winnow::prelude::*;

use crate::ARCSError;
use crate::structs::{
    ResChunkHeader, ResTableHeader, ResTablePackage, ResTablePackageHeader, ResourceType,
    StringPool,
};

pub struct ARSC {
    pub is_tampered: bool,

    header: ResTableHeader,
}

impl ARSC {
    pub fn new(input: &mut &[u8]) -> Result<ARSC, ARCSError> {
        if input.len() < 12 {
            return Err(ARCSError::TooSmallError);
        }

        let header = ResTableHeader::parse(input).map_err(|_| ARCSError::HeaderError)?;

        let mut is_tampered = false;

        // don't drop error, maybe another shit malware technique
        if header.header.type_ != ResourceType::Table {
            is_tampered = true;
        }

        if header.package_count < 1 {
            warn!(
                "expected at least one resource package, but got {}",
                header.package_count
            );
        }

        // TODO: parse based on package_count
        let string_pool = StringPool::parse(input).map_err(|_| ARCSError::StringPoolError)?;

        dbg!(string_pool);

        let package = ResTablePackage::parse(input).map_err(|_| ARCSError::ResourceTableError)?;

        Ok(ARSC {
            is_tampered,
            header,
        })
    }
}
