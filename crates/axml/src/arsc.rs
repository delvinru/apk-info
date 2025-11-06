use std::collections::HashMap;

use log::{info, warn};
use winnow::combinator::repeat;
use winnow::prelude::*;

use crate::ARCSError;
use crate::structs::{
    ResTableConfig, ResTableEntry, ResTableHeader, ResTablePackage, ResourceType,
    ResourceValueType, StringPool,
};

pub struct ARSC {
    pub is_tampered: bool,

    global_string_pool: StringPool,

    // HashMap< PackageID(u8), HashMap<TypeID(u8), HashMap<ResourceID(u8), HashMap<ResTableConfig, ResTableType > > > >
    packages: HashMap<u8, ResTablePackage>,
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

        let global_string_pool =
            StringPool::parse(input).map_err(|_| ARCSError::StringPoolError)?;

        let table_packages: Vec<ResTablePackage> =
            repeat(header.package_count as usize, ResTablePackage::parse)
                .parse_next(input)
                .map_err(|_| ARCSError::ResourceTableError)?;

        // There is often a single package, so we do a little optimization (i think)
        let packages = match table_packages.len() {
            0 => HashMap::new(),
            1 => {
                let pkg = table_packages
                    .into_iter()
                    .next()
                    .expect("is rust broken? one element must be");
                HashMap::from([((pkg.header.id & 0xff) as u8, pkg)])
            }
            _ => {
                let mut packages = HashMap::with_capacity(table_packages.len());
                for pkg in table_packages {
                    let id = (pkg.header.id & 0xff) as u8;
                    if packages.contains_key(&id) {
                        warn!(
                            "malformed resource packages, duplicate package id - 0x{:02x}, skipped",
                            id
                        );
                        continue;
                    }

                    packages.insert(id, pkg);
                }
                packages
            }
        };

        Ok(ARSC {
            is_tampered,
            global_string_pool,
            packages,
        })
    }

    pub fn get_resource(&self, id: u32) -> Option<String> {
        let config = ResTableConfig::default();
        let (package_id, type_id, entry_id) = self.split_resource_id(id);

        let package = self.packages.get(&package_id).unwrap();
        let entry = package.get_entry(&config, type_id, entry_id).unwrap();

        match entry {
            ResTableEntry::Default(e) => {
                info!(
                    "entry 0x{:08x} {:?} {:?}",
                    e.value.data,
                    e.value.data_type,
                    e.value.to_string(&self.global_string_pool)
                );

                // TODO: check this and create resolver, infinite loop possible
                match e.value.data_type {
                    ResourceValueType::Reference => self.get_resource(e.value.data),
                    _ => Some(e.value.to_string(&self.global_string_pool)),
                }
            }
            ResTableEntry::NoEntry => {
                panic!("got no entry");
            }
            e => {
                warn!("for now don't how to handle this: {:#?}", e);
                None
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
