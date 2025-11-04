use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::{Hash, Hasher};

use log::{info, warn};
use winnow::binary::{le_u16, le_u32, u8};
use winnow::combinator::repeat;
use winnow::error::{ErrMode, StrContext, StrContextValue};
use winnow::prelude::*;
use winnow::token::take;

use crate::structs::{
    ResChunkHeader, ResTableConfig, ResTableConfigFlags, ResourceType, ResourceValue, StringPool,
};

// TODO: maybe add as type definition, idk
// https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/tools/aapt/ResourceTable.cpp;l=1769;drc=61197364367c9e404c7da6900658f1b16c42d0da;bpv=0;bpt=1
// pub(crate) enum PackageType {
//     App = 0x7f,
//     System = 0x01,
//     SharedLibrary = 0x00,

//     Unknown(u32),
// }

/// Header for a resrouce table
///
/// [Source code](https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h;l=906?q=ResourceTypes.h&ss=android)
#[derive(Debug)]
pub(crate) struct ResTableHeader {
    pub(crate) header: ResChunkHeader,

    /// The number of [ResTablePackage] structures
    pub(crate) package_count: u32,
}

impl ResTableHeader {
    #[inline(always)]
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<ResTableHeader> {
        (ResChunkHeader::parse, le_u32)
            .map(|(header, package_count)| ResTableHeader {
                header,
                package_count,
            })
            .parse_next(input)
    }
}

/// A collection of resource data types withing a package
///
/// Followed by one or more [ResTableType] and [ResTableTypeSpec] structures containing the entry values for each resource type
///
/// [Source code](https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h;l=919?q=ResourceTypes.h&ss=android)
pub(crate) struct ResTablePackageHeader {
    pub(crate) header: ResChunkHeader,

    /// If this is a base package, its ID.
    ///
    /// Package IDs start at 1(corresponding to the value of the package bits in a resource identifier)
    /// 0 meands this is not a base package
    pub(crate) id: u32,

    /// Actual name of this package, \0-terminated
    pub(crate) name: [u8; 256],

    /// Offset to [StringPool] defining the resource type symbol table
    /// If zero, this package is inheriting from another base package (overriding specific values in it)
    pub(crate) type_strings: u32,

    /// Last index into `type_strings` that is for public use by others
    pub(crate) last_public_type: u32,

    /// Offset to [StringPool] defining the resource key symbol table
    /// If zero, this package is inheriting from another base package (overriding specific values in it)
    pub(crate) key_strings: u32,

    /// Last index into `key_strings` that is for public use by other
    pub(crate) last_public_key: u32,

    /// TODO: The source code does not describe the purpose of this field.
    pub(crate) type_id_offset: u32,
}

impl ResTablePackageHeader {
    #[inline(always)]
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<ResTablePackageHeader> {
        (
            ResChunkHeader::parse,
            le_u32,
            take(256usize),
            le_u32,
            le_u32,
            le_u32,
            le_u32,
            le_u32,
        )
            .map(
                |(
                    header,
                    id,
                    name,
                    type_strings,
                    last_public_type,
                    key_strings,
                    last_public_key,
                    type_id_offset,
                )| ResTablePackageHeader {
                    header,
                    id,
                    name: name.try_into().expect("expected 256 name length"),
                    type_strings,
                    last_public_type,
                    key_strings,
                    last_public_key,
                    type_id_offset,
                },
            )
            .parse_next(input)
    }

    /// Get a real package name from `name` slice
    pub(crate) fn name(&self) -> String {
        let utf16_str: Vec<u16> = self
            .name
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .take_while(|&c| c != 0)
            .collect();

        String::from_utf16(&utf16_str).unwrap_or_default()
    }
}

impl fmt::Debug for ResTablePackageHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResTablePackageHeader")
            .field("header", &self.header)
            .field("id", &self.id)
            .field("name", &self.name())
            .field("type_strings", &self.type_strings)
            .field("last_public_type", &self.last_public_type)
            .field("key_strings", &self.key_strings)
            .field("last_public_key", &self.last_public_key)
            .field("type_id_offset", &self.type_id_offset)
            .finish()
    }
}

/// A specification of the resources defined by a particular type
///
/// There should be one of these chunks for each resource type
///
/// [Source code](https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h;l=1448?q=ResourceTypes.h&ss=android)
#[derive(Debug)]
pub(crate) struct ResTableTypeSpec {
    pub(crate) header: ResChunkHeader,

    /// The type identifier this chunk is holding.
    /// Type IDs start at 1 (corresponding to the value of the type bits in a resource identifier).
    /// 0 is invalid.
    pub(crate) id: u8,

    /// Must be 0 (in documentation)
    ///
    /// Ideally, need to check this value, but this is not done on purpose
    ///
    /// Malware can intentionally change the value to break parsers
    pub(crate) res0: u8,

    /// Used to be reserved, if >0 specifies the number of [ResTableType] entries for this spec
    pub(crate) types_count: u16,

    /// Number of uint32_t entry configuration masks that follow
    pub(crate) entry_count: u32,

    /// Configuration mask
    pub(crate) type_spec_flags: Vec<ResTableConfigFlags>,
}

impl ResTableTypeSpec {
    pub(crate) fn parse(
        header: ResChunkHeader,
        input: &mut &[u8],
    ) -> ModalResult<ResTableTypeSpec> {
        let (id, res0, types_count, entry_count) = (
            u8.verify(|id| *id != 0)
                .context(StrContext::Label("ResTableTypeSpec.id"))
                .context(StrContext::Expected(StrContextValue::Description(
                    "ResTableTypeSpec.id has an id of 0",
                ))),
            u8,
            le_u16,
            le_u32,
        )
            .parse_next(input)?;

        // TODO: add validation that id is not 0
        // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/libs/androidfw/ResourceTypes.cpp;l=6987;

        let type_spec_flags = repeat(
            entry_count as usize,
            le_u32.map(ResTableConfigFlags::from_bits_truncate),
        )
        .parse_next(input)?;

        Ok(ResTableTypeSpec {
            header,
            id,
            res0,
            types_count,
            entry_count,
            type_spec_flags,
        })
    }
}

bitflags::bitflags! {
    pub(crate) struct ResTableFlag: u16 {
        /// If set, this is a complex entry, holding a set of name/value mappings.
        const FLAG_COMPLEX = 0x0001;

        /// If set, this resource has been declared public, so libraries are allowed to reference it.
        const FLAG_PUBLIC = 0x0002;

        /// If set, this is a weak resource and may be overridden by strong resources of the same name/type.
        const FLAG_WEAK = 0x0004;

        /// If set, this is a compact entry with data type and value directly encoded in this entry.
        const FLAG_COMPACT = 0x0008;

        /// If set, this entry relies on read/write Android feature flags.
        const FLAG_USES_FEATURE_FLAGS = 0x0010;
    }
}

#[derive(Debug)]
pub(crate) struct ResTableMap {
    /// The resource identifier defining this mapping's name.
    /// For attribute resources, 'name' can be one of the following special resource types
    /// to supply meta-data about the attribute; for all other resource types it must be an attribute resource.
    ///
    /// NOTE: This is actually `ResTable_ref`, but for simplicity don't use that
    pub(crate) name: u32,

    pub(crate) value: ResourceValue,
}

impl ResTableMap {
    #[inline(always)]
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<ResTableMap> {
        (le_u32, ResourceValue::parse)
            .map(|(name, value)| ResTableMap { name, value })
            .parse_next(input)
    }
}

/// Defining a parent map resource from which to inherit values
#[derive(Debug)]
pub(crate) struct ResTableMapEntry {
    /// Number of bytes in this structure
    pub(crate) size: u16,

    /// Flags describes in [`ResTableFlag`]
    pub(crate) flags: u16,

    /// Reference to [`ResTablePackage::key_strings`]
    pub(crate) index: u32,

    /// Resource identifier of the parent mapping, or 0 if there is none.
    /// This is always treated as a TYPE_DYNAMIC_REFERENCE.
    pub(crate) parent: u32,

    /// Number of name/value pairs that follow for [`ResTableFlag::FLAG_COMPLEX`]
    pub(crate) count: u32,

    /// Actual values of this entry
    pub(crate) values: Vec<ResTableMap>,
}

impl ResTableMapEntry {
    pub(crate) fn parse(
        size: u16,
        flags: u16,
        index: u32,
        input: &mut &[u8],
    ) -> ModalResult<ResTableMapEntry> {
        let (parent, count) = (le_u32, le_u32).parse_next(input)?;
        let values = repeat(count as usize, ResTableMap::parse).parse_next(input)?;

        Ok(ResTableMapEntry {
            size,
            flags,
            index,
            parent,
            count,
            values,
        })
    }
}

/// A compact entry is indicated by [`ResTableFlag::FLAG_COMPACT`] with falgs at the same offset as normal entry
///
/// This is only for simple data values
#[derive(Debug)]
pub(crate) struct ResTableEntryCompact {
    /// key index is encoded in 16-bit
    pub(crate) key: u16,

    /// Flags describes in [`ResTableFlag`]
    pub(crate) flags: u16,

    /// data is encoded directly in this entry
    pub(crate) data: u32,
}

#[derive(Debug)]
pub(crate) struct ResTableEntryDefault {
    /// Number of bytes in this structure
    pub(crate) size: u16,

    /// Flags describes in [`ResTableFlag`]
    pub(crate) flags: u16,

    /// Reference to [`ResTablePackage::key_strings`]
    pub(crate) index: u32,

    pub(crate) value: ResourceValue,
}

/// This is the beginning of information about an entry in the resource table
///
/// [Source code](https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h;l=1583?q=ResTable_config&ss=android)
#[derive(Debug)]
pub(crate) enum ResTableEntry {
    NoEntry,
    Complex(ResTableMapEntry),
    Compact(ResTableEntryCompact),
    Default(ResTableEntryDefault),
}

impl ResTableEntry {
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<ResTableEntry> {
        // By default assume that we dealing with `Full` union
        let (size, flags, index) = (le_u16, le_u16, le_u32).parse_next(input)?;

        if Self::is_complex(flags) {
            let entry = ResTableMapEntry::parse(size, flags, index, input)?;
            Ok(ResTableEntry::Complex(entry))
        } else if Self::is_compact(flags) {
            Ok(ResTableEntry::Compact(ResTableEntryCompact {
                key: size,
                flags,
                data: index,
            }))
        } else {
            let value = ResourceValue::parse(input)?;
            Ok(ResTableEntry::Default(ResTableEntryDefault {
                size,
                flags,
                index,
                value,
            }))
        }
    }

    #[inline(always)]
    pub(crate) fn is_complex(flags: u16) -> bool {
        ResTableFlag::from_bits_truncate(flags).contains(ResTableFlag::FLAG_COMPLEX)
    }

    #[inline(always)]
    #[allow(unused)]
    pub(crate) fn is_public(flags: u16) -> bool {
        ResTableFlag::from_bits_truncate(flags).contains(ResTableFlag::FLAG_PUBLIC)
    }

    #[inline(always)]
    #[allow(unused)]
    pub(crate) fn is_weak(flags: u16) -> bool {
        ResTableFlag::from_bits_truncate(flags).contains(ResTableFlag::FLAG_WEAK)
    }

    #[inline(always)]
    pub(crate) fn is_compact(flags: u16) -> bool {
        ResTableFlag::from_bits_truncate(flags).contains(ResTableFlag::FLAG_COMPACT)
    }

    #[inline(always)]
    #[allow(unused)]
    pub(crate) fn uses_feature_flags(flags: u16) -> bool {
        ResTableFlag::from_bits_truncate(flags).contains(ResTableFlag::FLAG_USES_FEATURE_FLAGS)
    }
}

bitflags::bitflags! {
    #[derive(Debug)]
    pub(crate) struct ResTableTypeFlags: u8 {
        /// If set, the entry is sparse, and encodes both the entry ID and offset into each entry,
        /// and a binary search is used to find the key. Only available on platforms >= O.
        /// Mark any types that use this with a v26 qualifier to prevent runtime issues on older
        /// platforms.
        const SPARCE   = 0x01;

        /// If set, the offsets to the entries are encoded in 16-bit, real_offset = offset * 4u
        /// An 16-bit offset of 0xffffu means a NO_ENTRY
        const OFFSET16 = 0x02;
    }
}

/// A collection of resource entries for a specific resource data type.
///
/// If the [`ResTableTypeFlags::SPARCE`] flag is **not** set in [`flags`], this structure
/// is followed by an array of `u32` values corresponding to the array of
/// type strings in the [`ResTable_package::typeStrings`] string block.
/// Each element holds an index from `entriesStart`; a value of [`NO_ENTRY`]
/// indicates that the entry is not defined.
///
/// If the [`ResTableTypeFlags::SPARCE`] flag **is** set in [`flags`], this structure
/// is followed by an array of [`ResTable_sparseTypeEntry`] elements defining
/// only the entries that have values for this type. Each entry is sorted by
/// its entry ID so that a binary search can be performed. The ID and offset
/// are encoded in a single `u32`. See [`ResTable_sparseTypeEntry`] for details.
///
/// Multiple chunks of this type may exist for a particular resource type,
/// each providing different configuration variations for that resource’s values.
///
/// Ideally, there would be an additional ordered index of entries to enable
/// binary search by string name.
///
/// [Source code](https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h;l=1500?q=ResTable_config&ss=android)
#[derive(Debug)]
pub(crate) struct ResTableType {
    pub(crate) header: ResChunkHeader,

    /// The type identifier this chunk is holding
    ///
    /// Type IDs start at 1 (corresponding to the value of the type bits in a resource identifier)
    /// 0 is invalid
    pub(crate) id: u8,

    /// Declares type of this resource
    pub(crate) flags: u8,

    /// The documentation says that this field should always be 0.
    ///
    /// NOTE: the value is intentionally not checked, because malware can break parsers
    pub(crate) reserved: u16,

    /// Number of uint32_t entry indices that follow
    pub(crate) entry_count: u32,

    /// Offset from header where ... data starts
    /// TODO: add link to structure
    /// TODO: expecting due to this shit parameter malware will sometimes fuckup resources
    pub(crate) entries_start: u32,

    /// Configuration this collection of entries is designed for
    /// This always must be last
    pub(crate) config: ResTableConfig,

    /// TODO: expecting due to this shit parameter malware will sometimes fuckup resources
    pub(crate) entry_offsets: Vec<u32>,

    /// Defined entries in this type
    pub(crate) entries: Vec<ResTableEntry>,
}

impl ResTableType {
    pub(crate) fn parse(header: ResChunkHeader, input: &mut &[u8]) -> ModalResult<ResTableType> {
        let (id, flags, reserved, entry_count, entries_start) =
            (u8, u8, le_u16, le_u32, le_u32).parse_next(input)?;

        let config = ResTableConfig::parse(input)?;

        let is_offset16 = Self::is_offset16(flags);

        // TODO: handle "sparse" flag
        let entry_offsets: Vec<u32> = if is_offset16 {
            repeat(entry_count as usize, le_u16.map(|x| x as u32)).parse_next(input)?
        } else {
            repeat(entry_count as usize, le_u32).parse_next(input)?
        };

        let entries = entry_offsets
            .iter()
            .map(|&offset| {
                let is_no_entry = if is_offset16 {
                    offset as u16 == u16::MAX
                } else {
                    offset == u32::MAX
                };

                if is_no_entry {
                    Ok(ResTableEntry::NoEntry)
                } else {
                    ResTableEntry::parse(input)
                }
            })
            .collect::<ModalResult<_>>()?;

        Ok(ResTableType {
            header,
            id,
            flags,
            reserved,
            entry_count,
            entries_start,
            config,
            entry_offsets,
            entries,
        })
    }

    #[inline(always)]
    pub(crate) fn is_sparse(flags: u8) -> bool {
        ResTableTypeFlags::from_bits_truncate(flags).contains(ResTableTypeFlags::SPARCE)
    }

    #[inline(always)]
    pub(crate) fn is_offset16(flags: u8) -> bool {
        ResTableTypeFlags::from_bits_truncate(flags).contains(ResTableTypeFlags::OFFSET16)
    }

    /// Get "real" id to resolve name from [`ResTablePackage::type_strings`]
    ///
    /// [Source Code](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/libs/androidfw/ResourceTypes.cpp;l=7073;drc=61197364367c9e404c7da6900658f1b16c42d0da;bpv=1;bpt=1)
    #[inline(always)]
    pub(crate) fn id(&self) -> u8 {
        self.id.saturating_sub(1)
    }
}

impl Hash for ResTableType {
    /// Generate hash based on config hash
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.config.hash(state);
    }
}

#[derive(Debug)]
pub(crate) struct ResTablePackage {
    pub(crate) header: ResTablePackageHeader,
    pub(crate) type_strings: StringPool,
    pub(crate) key_strings: StringPool,

    pub(crate) resources: HashMap<ResTableConfig, HashMap<u8, Vec<ResTableEntry>>>,
}

impl ResTablePackage {
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<ResTablePackage> {
        let package_header = ResTablePackageHeader::parse(input)?;

        let type_strings = StringPool::parse(input)?;
        let key_strings = StringPool::parse(input)?;

        // requires fastloop by resource id => resource
        // for example: 0x7f010000 => anim/abc_fade_in or res/anim/abc_fade_in.xml type=XML

        // HashMap<package_id, HashMap<Config, HashMap<type_id, HashMap<entry_id, Entries>>>>
        let mut resources: HashMap<ResTableConfig, HashMap<u8, Vec<ResTableEntry>>> =
            HashMap::with_capacity(32);

        loop {
            let header = match ResChunkHeader::parse(input) {
                Ok(v) => v,
                Err(ErrMode::Backtrack(_)) => {
                    return Ok(ResTablePackage {
                        header: package_header,
                        type_strings,
                        key_strings,
                        resources,
                    });
                }
                Err(e) => return Err(e),
            };

            // info!("header {:?}", header);

            match header.type_ {
                ResourceType::TableType => {
                    let type_type = ResTableType::parse(header, input)?;

                    let config_entry = resources.entry(type_type.config).or_default();
                    let type_entry = config_entry.entry(type_type.id).or_default();

                    type_entry.extend(type_type.entries);
                }
                ResourceType::TableTypeSpec => {
                    let type_spec = ResTableTypeSpec::parse(header, input)?;
                }
                _ => {
                    warn!("got unknown header: {:?}", header);
                }
            }
        }
    }

    /// Generate Resource Id based on algorithm from AOSP
    ///
    /// [Source Code](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/tools/aapt/ResourceTable.h;l=224;drc=61197364367c9e404c7da6900658f1b16c42d0da;bpv=1;bpt=1)
    #[inline(always)]
    fn generate_res_id(package_id: u32, type_id: u32, name_id: u32) -> u32 {
        name_id | (type_id << 16) | (package_id << 24)
    }

    pub(crate) fn get_entry(
        &self,
        config: &ResTableConfig,
        type_id: u8,
        entry_id: u16,
    ) -> Option<&ResTableEntry> {
        let found_config = self.resources.get(&config).unwrap();
        let found_type = found_config.get(&type_id).unwrap();

        for (idx, entry) in found_type.iter().enumerate() {
            if (idx as u16) == entry_id {
                match &entry {
                    ResTableEntry::Compact(e) => {
                        info!(
                            "resource (compact) 0x{:08x} \"{}\"",
                            Self::generate_res_id(self.header.id, type_id as u32, idx as u32,),
                            self.key_strings.get(e.data).unwrap_or(&String::new()),
                        )
                    }
                    ResTableEntry::Complex(e) => {
                        info!(
                            "resource (complex) 0x{:08x} \"{}\"",
                            Self::generate_res_id(self.header.id, type_id as u32, idx as u32,),
                            self.key_strings.get(e.index).unwrap_or(&String::new()),
                        )
                    }
                    ResTableEntry::Default(e) => {
                        info!(
                            "type ({}) resource (default) 0x{:08x} \"{}\"",
                            self.type_strings
                                .get(type_id.saturating_sub(1) as u32)
                                .unwrap_or(&String::new()),
                            Self::generate_res_id(self.header.id, type_id as u32, idx as u32,),
                            self.key_strings.get(e.index).unwrap_or(&String::new()),
                        );
                    }
                    ResTableEntry::NoEntry => continue,
                }

                return Some(entry);
            }
        }

        None
    }
}
