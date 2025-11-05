use log::{info, warn};

use crate::ARCSError;
use crate::structs::{
    ResTableConfig, ResTableEntry, ResTableHeader, ResTablePackage, ResourceType, StringPool,
};

pub struct ARSC {
    pub is_tampered: bool,

    header: ResTableHeader,
    string_pool: StringPool,
    package: ResTablePackage,
}

impl ARSC {
    pub fn new(input: &mut &[u8]) -> Result<ARSC, ARCSError> {
        if input.len() < 12 {
            return Err(ARCSError::TooSmallError);
        }

        let header = ResTableHeader::parse(input).map_err(|_| ARCSError::HeaderError)?;

        info!("{:#?}", header);

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

        let package = ResTablePackage::parse(input).map_err(|_| ARCSError::ResourceTableError)?;

        Ok(ARSC {
            is_tampered,
            header,
            string_pool,
            package,
        })
    }

    pub fn get_resource(&self, id: u32) {
        let config = ResTableConfig::default();
        let (package_id, type_id, entry_id) = self.split_resource_id(id);

        let entry = self.package.get_entry(&config, type_id, entry_id).unwrap();

        match entry {
            ResTableEntry::Default(e) => {
                info!(
                    "entry 0x{:08x} {:?} {:?}",
                    e.value.data,
                    e.value.data_type,
                    e.value.to_string(&self.string_pool)
                );
            }
            e => {
                warn!("for now don't how to handle this: {:#?}", e);
            }
        }
    }

    #[inline]
    fn split_resource_id(&self, id: u32) -> (u8, u8, u16) {
        (
            (id >> 24) as u8,
            ((id >> 16) & 0xff) as u8,
            (id & 0xffff) as u16,
        )
    }
}
