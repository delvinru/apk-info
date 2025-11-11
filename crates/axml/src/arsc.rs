use std::cell::RefCell;
use std::collections::HashMap;

use log::warn;
use winnow::combinator::repeat;
use winnow::prelude::*;

use crate::errors::ARCSError;
use crate::structs::{
    ResTableConfig, ResTableEntry, ResTableHeader, ResTablePackage, ResourceValueType, StringPool,
};

/// Represents an Android Resource Table (ARSC) file.
///
/// This struct holds the parsed global string pool and resource packages.
/// It provides methods to query resources by ID or by name.
#[derive(Debug)]
pub struct ARSC {
    global_string_pool: StringPool,
    packages: HashMap<u8, ResTablePackage>,

    /// Cache for resolved reference names to avoid repeated lookups.
    reference_names: RefCell<HashMap<u32, String>>,
}

impl ARSC {
    /// Parses raw ARSC bytes into an `ARSC` structure.
    pub fn new(input: &mut &[u8]) -> Result<ARSC, ARCSError> {
        if input.len() < 12 {
            return Err(ARCSError::TooSmallError);
        }

        let header = ResTableHeader::parse(input).map_err(|_| ARCSError::HeaderError)?;

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
            global_string_pool,
            packages,
            // preallocate some space
            reference_names: RefCell::new(HashMap::with_capacity(32)),
        })
    }

    /// Retrieves a resource value by its numeric ID.
    ///
    /// Recursively resolves references if the value is a reference type.
    pub fn get_resource_value(&self, id: u32) -> Option<String> {
        // TODO: need somehow option for dynamic config, not hardcoded
        let config = ResTableConfig::default();

        let (package_id, type_id, entry_id) = self.split_resource_id(id);

        let entry = self
            .packages
            .get(&package_id)?
            .find_entry(&config, type_id, entry_id)?;

        match entry {
            ResTableEntry::Default(e) => match e.value.data_type {
                ResourceValueType::Reference => {
                    // recursion protect?
                    if e.value.data == id {
                        return None;
                    }

                    self.get_resource_value(e.value.data)
                }
                _ => Some(e.value.to_string(&self.global_string_pool, Some(self))),
            },
            // if got nothing - gg
            ResTableEntry::NoEntry => None,
            e => {
                warn!("for now don't how to handle this: {:#?}", e);
                None
            }
        }
    }

    /// Retrieves a resource value by its resolved name.
    pub fn get_resource_value_by_name(&self, name: &str) -> Option<String> {
        let (&id, _) = self
            .reference_names
            .borrow()
            .iter()
            .find(|(_, v)| v == &name)?;

        self.get_resource_value(id)
    }

    /// Returns the full resource name for a given resource ID.
    ///
    /// Uses a cache to speed up repeated lookups.
    pub fn get_resource_name(&self, id: u32) -> Option<String> {
        // fast path: if we've already have this name in cache
        if let Some(name) = self.reference_names.borrow().get(&id) {
            return Some(name.clone());
        }

        // split id into components
        let (package_id, type_id, entry_id) = self.split_resource_id(id);

        // lookup package
        let package = self.packages.get(&package_id)?;

        // default config
        // TODO: need somehow option for dynamic config, not hardcoded
        let config = ResTableConfig::default();

        // search entry
        let entry = package.find_entry(&config, type_id, entry_id)?;

        // get full name
        let name = package.get_entry_full_name(entry, type_id)?;

        // save in cache
        self.reference_names.borrow_mut().insert(id, name.clone());

        Some(name)
    }

    /// Splits a 32-bit resource ID into its package ID, type ID, and entry ID.
    #[inline(always)]
    fn split_resource_id(&self, id: u32) -> (u8, u8, u16) {
        (
            (id >> 24) as u8,
            ((id >> 16) & 0xff) as u8,
            (id & 0xffff) as u16,
        )
    }
}
