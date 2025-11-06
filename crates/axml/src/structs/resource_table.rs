use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::Hash;

use log::{debug, error, info, warn};
use winnow::binary::{le_u16, le_u32, u8};
use winnow::combinator::repeat;
use winnow::error::{ErrMode, Needed, StrContext, StrContextValue};
use winnow::prelude::*;
use winnow::stream::Stream;
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

/// Header for a resource table
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

    /// The source code does not describe the purpose of this field
    ///
    /// In old versions this field doesn't exists - https://xrefandroid.com/android-4.4.4_r1/xref/frameworks/base/include/androidfw/ResourceTypes.h#782
    ///
    /// Example sample: `d6c670c7a27105f082108d89c6d6b983bdeba6cef36d357b2c4c2bfbc4189aab`
    pub(crate) type_id_offset: u32,
}

impl ResTablePackageHeader {
    #[inline(always)]
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<ResTablePackageHeader> {
        let (header, id, name, type_strings, last_public_type, key_strings, last_public_key) = (
            ResChunkHeader::parse,
            le_u32,
            take(256usize),
            le_u32,
            le_u32,
            le_u32,
            le_u32,
        )
            .parse_next(input)?;

        let name = name.try_into().expect("expected 256 bytes for name field");
        let header_size = header.header_size;
        let expected_size = Self::size_of() as u16;

        let mut type_id_offset = 0;

        match header_size {
            s if s == expected_size => {
                // new structure, with type_id_offset
                type_id_offset = le_u32.parse_next(input)?;
            }
            s if s == expected_size - 4 => {
                // old structure, without type_id_offset
            }
            _ => {
                // malformed structure
                type_id_offset = le_u32.parse_next(input)?;

                let skipped = header_size.saturating_sub(expected_size);
                let _ = take(skipped as usize).parse_next(input)?;
                warn!(
                    "malformed resource table package, skipped {} bytes",
                    skipped
                );
            }
        }

        Ok(ResTablePackageHeader {
            header,
            id,
            name,
            type_strings,
            last_public_type,
            key_strings,
            last_public_key,
            type_id_offset,
        })
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

    /// Get size in bytes of this structure
    #[inline(always)]
    pub(crate) const fn size_of() -> usize {
        // header - ResChunkHeader
        // 4 bytes - string_count
        // 256 bytes - name
        // 4 bytes - type_strings
        // 4 bytes - last_public_type
        // 4 bytes - key_strings
        // 4 bytes - last_public_key
        // 4 bytes - type_id_offset
        ResChunkHeader::size_of() + 4 + 256 + 4 + 4 + 4 + 4 + 4
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
    #[derive(Debug)]
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
            Ok(ResTableEntry::Default(ResTableEntryDefault {
                size,
                flags,
                index,
                value: ResourceValue::parse(input)?,
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

        // whatsapp is doing some kind of crap with offsets, so we need to make a slice on this particular piece of data
        // da8963f347c26ede58c1087690f1af8ef308cd778c5aaf58094eeb57b6962b21
        let entries_size = header.size.saturating_sub(entries_start) as usize;
        let (entries_slice, rest) = input
            .split_at_checked(entries_size)
            .ok_or_else(|| ErrMode::Incomplete(Needed::Unknown))?;

        *input = rest;
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
                    let mut slice = &entries_slice[offset as usize..];

                    ResTableEntry::parse(&mut slice)
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

/// A shared library package-id to package name entry
pub(crate) struct ResTableLibraryEntry {
    /// The package-i this shared library was assigned at build time
    ///
    /// We use a uint32 to keep the structure aligned on a uint32 boundary
    pub(crate) package_id: u32,

    /// The package name of the shared library. \0 terminated
    pub(crate) package_name: [u8; 256],
}

impl ResTableLibraryEntry {
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<ResTableLibraryEntry> {
        (le_u32, take(256usize))
            .map(
                |(package_id, package_name): (u32, &[u8])| ResTableLibraryEntry {
                    package_id,
                    package_name: package_name
                        .try_into()
                        .expect("expected 256 bytes for package_name"),
                },
            )
            .parse_next(input)
    }

    /// Get a real package name from `package_name` slice
    pub(crate) fn package_name(&self) -> String {
        let utf16_str: Vec<u16> = self
            .package_name
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .take_while(|&c| c != 0)
            .collect();

        String::from_utf16(&utf16_str).unwrap_or_default()
    }
}

impl fmt::Debug for ResTableLibraryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResTableLibraryEntry")
            .field("package_id", &self.package_id)
            .field("package_name", &self.package_name())
            .finish()
    }
}

/// A package-id to package name mapping for any shared libraries used in this resource table
/// The package-ids' encoded in this resource table may be different than the id's assigned at runtime
/// We must be able to translate the package-id's based on the package name
///
/// [Source code](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h;l=1735;drc=61197364367c9e404c7da6900658f1b16c42d0da)
#[derive(Debug)]
pub(crate) struct ResTableLibrary {
    pub(crate) header: ResChunkHeader,

    /// The number of shared libraries linked in this resource table
    pub(crate) count: u32,

    pub(crate) entries: Vec<ResTableLibraryEntry>,
}

impl ResTableLibrary {
    pub(crate) fn parse(header: ResChunkHeader, input: &mut &[u8]) -> ModalResult<ResTableLibrary> {
        let count = le_u32.parse_next(input)?;
        let entries = repeat(count as usize, ResTableLibraryEntry::parse).parse_next(input)?;

        Ok(ResTableLibrary {
            header,
            count,
            entries,
        })
    }
}

/// Specifies the set of resourcers that are explicitly allowd to be overlaid by RPOs
pub(crate) struct ResTableOverlayble {
    pub(crate) header: ResChunkHeader,

    /// The name of the overlaybalbe set of resources that overlays target
    pub(crate) name: [u8; 512],

    /// The component responsible for enabling and disabling overlays targeting this chunk
    pub(crate) actor: [u8; 512],
}

impl ResTableOverlayble {
    pub(crate) fn parse(
        header: ResChunkHeader,
        input: &mut &[u8],
    ) -> ModalResult<ResTableOverlayble> {
        let (name, actor) = (take(512usize), take(512usize)).parse_next(input)?;

        Ok(ResTableOverlayble {
            header,
            name: name
                .try_into()
                .expect("expected 512 bytes for overlayble name"),
            actor: actor
                .try_into()
                .expect("expected 512 bytes for overlayble actor"),
        })
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

    /// Get a real actor from `actor` slice
    pub(crate) fn actor(&self) -> String {
        let utf16_str: Vec<u16> = self
            .actor
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .take_while(|&c| c != 0)
            .collect();

        String::from_utf16(&utf16_str).unwrap_or_default()
    }
}

impl fmt::Debug for ResTableOverlayble {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResTableOverlayble")
            .field("name", &self.name())
            .field("actor", &self.actor())
            .finish()
    }
}

bitflags::bitflags! {
    /// Flags for all possible overlayable policy options.
    ///
    /// Any changes to this set should also update
    /// `aidl/android/os/OverlayablePolicy.aidl`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PolicyFlags: u32 {
        /// No flags set.
        const NONE              = 0x0000_0000;
        /// Any overlay can overlay these resources.
        const PUBLIC            = 0x0000_0001;
        /// The overlay must reside on or have existed on the system partition before an upgrade.
        const SYSTEM_PARTITION  = 0x0000_0002;
        /// The overlay must reside on or have existed on the vendor partition before an upgrade.
        const VENDOR_PARTITION  = 0x0000_0004;
        /// The overlay must reside on or have existed on the product partition before an upgrade.
        const PRODUCT_PARTITION = 0x0000_0008;
        /// The overlay must be signed with the same signature as the package containing the target resource.
        const SIGNATURE         = 0x0000_0010;
        /// The overlay must reside on or have existed on the odm partition before an upgrade.
        const ODM_PARTITION     = 0x0000_0020;
        /// The overlay must reside on or have existed on the oem partition before an upgrade.
        const OEM_PARTITION     = 0x0000_0040;
        /// The overlay must be signed with the same signature as the actor declared for the target resource.
        const ACTOR_SIGNATURE   = 0x0000_0080;
        /// The overlay must be signed with the same signature as the reference package declared in the SystemConfig.
        const CONFIG_SIGNATURE  = 0x0000_0100;
    }
}

#[derive(Debug)]
pub(crate) struct ResTableOverlayblePolicy {
    pub(crate) header: ResChunkHeader,

    pub(crate) policy_flags: PolicyFlags,

    /// The number of ResTable_ref that follow this header
    pub(crate) entry_count: u32,

    pub(crate) entries: Vec<u32>,
}

impl ResTableOverlayblePolicy {
    pub(crate) fn parse(
        header: ResChunkHeader,
        input: &mut &[u8],
    ) -> ModalResult<ResTableOverlayblePolicy> {
        let (policy_flags, entry_count) = (le_u32, le_u32).parse_next(input)?;

        let entries = repeat(entry_count as usize, le_u32).parse_next(input)?;

        Ok(ResTableOverlayblePolicy {
            header,
            policy_flags: PolicyFlags::from_bits_truncate(policy_flags),
            entry_count,
            entries,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ResTablePackage {
    pub(crate) header: ResTablePackageHeader,
    pub(crate) type_strings: StringPool,
    pub(crate) key_strings: StringPool,

    // requires fastloop by resource id => resource
    // for example: 0x7f010000 => anim/abc_fade_in or res/anim/abc_fade_in.xml type=XML
    pub(crate) resources: BTreeMap<ResTableConfig, HashMap<u8, Vec<ResTableEntry>>>,
}

impl ResTablePackage {
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<ResTablePackage> {
        let (package_header, type_strings, key_strings) = (
            ResTablePackageHeader::parse,
            StringPool::parse,
            StringPool::parse,
        )
            .parse_next(input)?;

        let mut resources: BTreeMap<ResTableConfig, HashMap<u8, Vec<ResTableEntry>>> =
            BTreeMap::new();

        loop {
            // save position before parsing header
            // requires for restoring position
            let checkpoint = input.checkpoint();

            let header = match ResChunkHeader::parse(input) {
                // got other package, need return
                Ok(v) if v.type_ == ResourceType::TablePackage => {
                    input.reset(&checkpoint);
                    break;
                }
                Ok(v) => v,
                Err(ErrMode::Backtrack(_)) => break,
                Err(e) => return Err(e),
            };

            match header.type_ {
                ResourceType::TableTypeSpec => {
                    // idk what should i do with this value
                    let _ = ResTableTypeSpec::parse(header, input)?;
                }
                ResourceType::TableType => {
                    let type_type = ResTableType::parse(header, input)?;

                    resources
                        .entry(type_type.config)
                        .or_default()
                        .entry(type_type.id)
                        .or_insert_with(|| type_type.entries);
                }
                ResourceType::TableLibrary => {
                    // idk what should i do with this value
                    let _ = ResTableLibrary::parse(header, input)?;
                }
                ResourceType::TableOverlayable => {
                    let _ = ResTableOverlayble::parse(header, input)?;
                }
                ResourceType::TableOverlayablePolicy => {
                    let _ = ResTableOverlayblePolicy::parse(header, input)?;
                }
                _ => warn!("got unknown header: {:?}", header),
            }
        }

        Ok(ResTablePackage {
            header: package_header,
            type_strings,
            key_strings,
            resources,
        })
    }

    /// Generate Resource Id based on algorithm from AOSP
    ///
    /// [Source Code](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/tools/aapt/ResourceTable.h;l=224;drc=61197364367c9e404c7da6900658f1b16c42d0da;bpv=1;bpt=1)
    #[inline(always)]
    fn generate_res_id(package_id: u32, type_id: u32, name_id: u32) -> u32 {
        name_id | (type_id << 16) | (package_id << 24)
    }

    // interesting sample - 197f49dec3aacc2855d08ee5ee2ae5635885b0163ecb50d2e21b68de59eb336a - need somehow fallback config or something
    pub(crate) fn get_entry(
        &self,
        config: &ResTableConfig,
        type_id: u8,
        entry_id: u16,
    ) -> Option<&ResTableEntry> {
        fn log_entry(
            res_id: u32,
            type_id: u8,
            entry: &ResTableEntry,
            key_strings: &StringPool,
            type_strings: &StringPool,
        ) {
            match entry {
                ResTableEntry::Compact(e) => {
                    if let Some(key) = key_strings.get(e.data) {
                        info!("resource (compact) 0x{:08x} \"{}\"", res_id, key);
                    }
                }
                ResTableEntry::Complex(e) => {
                    if let Some(key) = key_strings.get(e.index) {
                        info!("resource (complex) 0x{:08x} \"{}\"", res_id, key);
                    }
                }
                ResTableEntry::Default(e) => {
                    let unknown = "unknown".to_owned();
                    let type_name = type_strings
                        .get(type_id.saturating_sub(1) as u32)
                        .unwrap_or(&unknown);

                    if let Some(key) = key_strings.get(e.index) {
                        info!(
                            "type ({}) resource (default) 0x{:08x} \"{}\"",
                            type_name, res_id, key
                        );
                    }
                }
                ResTableEntry::NoEntry => {
                    info!("resource (noentry) 0x{:08x}", res_id);
                }
            }
        }

        if let Some(type_map) = self.resources.get(config) {
            if let Some(entries) = type_map.get(&type_id) {
                if let Some(entry) = entries.get(entry_id as usize) {
                    if !matches!(entry, ResTableEntry::NoEntry) {
                        let res_id =
                            Self::generate_res_id(self.header.id, type_id as u32, entry_id as u32);
                        log_entry(
                            res_id,
                            type_id,
                            entry,
                            &self.key_strings,
                            &self.type_strings,
                        );
                        return Some(entry);
                    }
                }
            }
        }

        for (other_config, type_map) in &self.resources {
            // skip original config
            if other_config == config {
                continue;
            }

            if let Some(entries) = type_map.get(&type_id) {
                if let Some(entry) = entries.get(entry_id as usize) {
                    if !matches!(entry, ResTableEntry::NoEntry) {
                        let res_id =
                            Self::generate_res_id(self.header.id, type_id as u32, entry_id as u32);
                        log_entry(
                            res_id,
                            type_id,
                            entry,
                            &self.key_strings,
                            &self.type_strings,
                        );
                        return Some(entry);
                    }
                }
            }
        }

        // can't find anything
        None
    }
}
