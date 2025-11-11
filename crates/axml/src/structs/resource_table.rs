use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::Hash;

use log::{debug, info, warn};
use winnow::binary::{le_u16, le_u32, u8};
use winnow::combinator::repeat;
use winnow::error::{ErrMode, Needed, StrContext, StrContextValue};
use winnow::prelude::*;
use winnow::stream::Stream;
use winnow::token::take;

use crate::structs::{
    ResChunkHeader, ResTableConfig, ResTableConfigFlags, ResourceHeaderType, ResourceValue,
    StringPool,
};

/// Header for a resource table
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#906>
#[derive(Debug)]
pub struct ResTableHeader {
    pub header: ResChunkHeader,

    /// The number of [ResTablePackage] structures
    pub package_count: u32,
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
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#919>
pub struct ResTablePackageHeader {
    pub header: ResChunkHeader,

    /// If this is a base package, its ID.
    ///
    /// Package IDs start at 1(corresponding to the value of the package bits in a resource identifier)
    /// 0 meands this is not a base package
    pub id: u32,

    /// Actual name of this package, \0-terminated
    pub name: [u8; 256],

    /// Offset to [StringPool] defining the resource type symbol table
    /// If zero, this package is inheriting from another base package (overriding specific values in it)
    pub type_strings: u32,

    /// Last index into `type_strings` that is for public use by others
    pub last_public_type: u32,

    /// Offset to [StringPool] defining the resource key symbol table
    /// If zero, this package is inheriting from another base package (overriding specific values in it)
    pub key_strings: u32,

    /// Last index into `key_strings` that is for public use by other
    pub last_public_key: u32,

    /// The source code does not describe the purpose of this field
    ///
    /// In old versions this field doesn't exists - <https://xrefandroid.com/android-4.4.4_r1/xref/frameworks/base/include/androidfw/ResourceTypes.h#782>
    ///
    /// Example sample: `d6c670c7a27105f082108d89c6d6b983bdeba6cef36d357b2c4c2bfbc4189aab`
    pub type_id_offset: u32,
}

impl ResTablePackageHeader {
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
                info!(
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
    pub fn name(&self) -> String {
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
    pub const fn size_of() -> usize {
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

/// A specification of the resources defined by a particular type.
///
/// There should be one of these chunks for each resource type.
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1448>
#[derive(Debug)]
pub struct ResTableTypeSpec {
    pub header: ResChunkHeader,

    /// The type identifier this chunk is holding.
    /// Type IDs start at 1 (corresponding to the value of the type bits in a resource identifier).
    /// 0 is invalid.
    pub id: u8,

    /// Must be 0 (in documentation)
    ///
    /// Ideally, need to check this value, but this is not done on purpose
    ///
    /// Malware can intentionally change the value to break parsers
    pub res0: u8,

    /// Used to be reserved, if >0 specifies the number of [ResTableType] entries for this spec
    pub types_count: u16,

    /// Number of uint32_t entry configuration masks that follow
    pub entry_count: u32,

    /// Configuration mask
    pub type_spec_flags: Vec<ResTableConfigFlags>,
}

impl ResTableTypeSpec {
    #[inline]
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
    pub struct ResTableFlag: u16 {
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

/// A single name/value mapping that is part of a complex resource.
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1696>
#[derive(Debug)]
pub struct ResTableMap {
    /// The resource identifier defining this mapping's name.
    /// For attribute resources, 'name' can be one of the following special resource types
    /// to supply meta-data about the attribute; for all other resource types it must be an attribute resource.
    ///
    /// NOTE: This is actually `ResTable_ref`, but for simplicity don't use that
    pub name: u32,

    /// this mapping's value
    pub value: ResourceValue,
}

impl ResTableMap {
    #[inline(always)]
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<ResTableMap> {
        (le_u32, ResourceValue::parse)
            .map(|(name, value)| ResTableMap { name, value })
            .parse_next(input)
    }
}

/// Defining a parent map resource from which to inherit values.
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1683>
#[derive(Debug)]
pub struct ResTableMapEntry {
    /// Number of bytes in this structure
    pub size: u16,

    /// Flags describes in [`ResTableFlag`]
    pub flags: u16,

    /// Reference to [ResTablePackage::key_strings]
    pub index: u32,

    /// Resource identifier of the parent mapping, or 0 if there is none.
    ///
    /// This is always treated as a TYPE_DYNAMIC_REFERENCE.
    pub parent: u32,

    /// Number of name/value pairs that follow for [ResTableFlag::FLAG_COMPLEX]
    pub count: u32,

    /// Actual values of this entry
    pub values: Vec<ResTableMap>,
}

impl ResTableMapEntry {
    #[inline(always)]
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

/// A compact entry is indicated by [ResTableFlag::FLAG_COMPACT] with falgs at the same offset as normal entry.
///
/// This is only for simple data values.
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1621>
#[derive(Debug)]
pub struct ResTableEntryCompact {
    /// key index is encoded in 16-bit.
    pub key: u16,

    /// Flags describes in [`ResTableFlag`].
    pub flags: u16,

    /// data is encoded directly in this entry.
    pub data: u32,
}

/// Default table entry
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1603>
#[derive(Debug)]
pub struct ResTableEntryDefault {
    /// Number of bytes in this structure
    pub size: u16,

    /// Flags describes in [`ResTableFlag`]
    pub flags: u16,

    /// Reference to [ResTablePackage::key_strings]
    pub index: u32,

    pub value: ResourceValue,
}

/// This is the beginning of information about an entry in the resource table
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1583>
#[derive(Debug)]
pub enum ResTableEntry {
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
    pub fn is_complex(flags: u16) -> bool {
        ResTableFlag::from_bits_truncate(flags).contains(ResTableFlag::FLAG_COMPLEX)
    }

    #[inline(always)]
    pub fn is_public(flags: u16) -> bool {
        ResTableFlag::from_bits_truncate(flags).contains(ResTableFlag::FLAG_PUBLIC)
    }

    #[inline(always)]
    // TODO: don't know how to handle this flag for now
    pub fn is_weak(flags: u16) -> bool {
        ResTableFlag::from_bits_truncate(flags).contains(ResTableFlag::FLAG_WEAK)
    }

    #[inline(always)]
    pub fn is_compact(flags: u16) -> bool {
        ResTableFlag::from_bits_truncate(flags).contains(ResTableFlag::FLAG_COMPACT)
    }

    #[inline(always)]
    // TODO: don't know how to handle this flag for now
    pub fn uses_feature_flags(flags: u16) -> bool {
        ResTableFlag::from_bits_truncate(flags).contains(ResTableFlag::FLAG_USES_FEATURE_FLAGS)
    }
}

bitflags::bitflags! {
    #[derive(Debug)]
    pub struct ResTableTypeFlags: u8 {
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
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1500>
#[derive(Debug)]
pub struct ResTableType {
    pub header: ResChunkHeader,

    /// The type identifier this chunk is holding
    ///
    /// Type IDs start at 1 (corresponding to the value of the type bits in a resource identifier)
    /// 0 is invalid
    pub id: u8,

    /// Declares type of this resource
    pub flags: u8,

    /// The documentation says that this field should always be 0.
    ///
    /// <div class="warning">
    ///     The value is intentionally not checked, because malware can break parsers.
    /// </div>
    pub reserved: u16,

    /// Number of uint32_t entry indices that follow
    pub entry_count: u32,

    /// Offset from header where [ResTableEntry] data starts
    pub entries_start: u32,

    /// Configuration this collection of entries is designed for
    /// This always must be last.
    pub config: ResTableConfig,

    pub entry_offsets: Vec<u32>,

    /// Defined entries in this type
    pub entries: Vec<ResTableEntry>,
}

impl ResTableType {
    pub(crate) fn parse(header: ResChunkHeader, input: &mut &[u8]) -> ModalResult<ResTableType> {
        let start_chunk = input.len();

        let (id, flags, reserved, entry_count, entries_start, config) =
            (u8, u8, le_u16, le_u32, le_u32, ResTableConfig::parse).parse_next(input)?;

        // handle sparse flag based on jadx code
        // https://github.com/skylot/jadx/blob/master/jadx-core/src/main/java/jadx/core/xmlgen/ResTableBinaryParser.java#L276
        let entry_offsets: Vec<u32> = if Self::is_sparse(flags) {
            repeat(
                entry_count as usize,
                (le_u16, le_u16).map(|(_, x)| {
                    if x == u16::MAX {
                        u32::MAX
                    } else {
                        u32::from(x) << 2
                    }
                }),
            )
            .parse_next(input)?
        } else if Self::is_offset16(flags) {
            repeat(
                entry_count as usize,
                le_u16.map(|x| {
                    if x == u16::MAX {
                        u32::MAX
                    } else {
                        u32::from(x) << 2
                    }
                }),
            )
            .parse_next(input)?
        } else {
            repeat(entry_count as usize, le_u32).parse_next(input)?
        };

        // whatsapp is doing some kind of crap with offsets, so we need to make a slice on this particular piece of data
        // da8963f347c26ede58c1087690f1af8ef308cd778c5aaf58094eeb57b6962b21
        // also sometimes 2 bytes are missing - wtf? a kind of alignment, not found anywhere?
        // jeb, jadx - they just skip it, so and i
        let alignment_bytes = start_chunk.saturating_sub(input.len()) & 0x3;
        if alignment_bytes != 0 {
            debug!("skipping {} alignment bytes", alignment_bytes);
            let _ = take(alignment_bytes).parse_next(input)?;
        }

        let entries_size = header.size.saturating_sub(entries_start) as usize;
        let (entries_slice, rest) = input
            .split_at_checked(entries_size)
            .ok_or_else(|| ErrMode::Incomplete(Needed::Unknown))?;

        *input = rest;

        let mut entries = Vec::with_capacity(entry_count as usize);
        let entries_len = entries_slice.len();

        for &offset in &entry_offsets {
            if offset == u32::MAX {
                entries.push(ResTableEntry::NoEntry);
                continue;
            }

            let offset = offset as usize;
            if offset >= entries_len {
                return Err(ErrMode::Incomplete(Needed::Unknown));
            }

            let mut slice = &entries_slice[offset..];
            entries.push(ResTableEntry::parse(&mut slice)?);
        }

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
    pub fn is_sparse(flags: u8) -> bool {
        ResTableTypeFlags::from_bits_truncate(flags).contains(ResTableTypeFlags::SPARCE)
    }

    #[inline(always)]
    pub fn is_offset16(flags: u8) -> bool {
        ResTableTypeFlags::from_bits_truncate(flags).contains(ResTableTypeFlags::OFFSET16)
    }
}

/// A shared library package-id to package name entry.
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1798>
pub struct ResTableLibraryEntry {
    /// The package-i this shared library was assigned at build time
    ///
    /// We use a uint32 to keep the structure aligned on a uint32 boundary
    pub package_id: u32,

    /// The package name of the shared library. \0 terminated
    pub package_name: [u8; 256],
}

impl ResTableLibraryEntry {
    #[inline(always)]
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

    /// Get a real package name from `package_name` slice.
    pub fn package_name(&self) -> String {
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
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1787>
#[derive(Debug)]
pub struct ResTableLibrary {
    pub header: ResChunkHeader,

    /// The number of shared libraries linked in this resource table
    pub count: u32,

    pub entries: Vec<ResTableLibraryEntry>,
}

impl ResTableLibrary {
    #[inline(always)]
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
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1834>
pub struct ResTableOverlayble {
    pub header: ResChunkHeader,

    /// The name of the overlaybalbe set of resources that overlays target.
    pub name: [u8; 512],

    /// The component responsible for enabling and disabling overlays targeting this chunk.
    pub actor: [u8; 512],
}

impl ResTableOverlayble {
    #[inline(always)]
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

    /// Get a real package name from `name` slice.
    pub fn name(&self) -> String {
        let utf16_str: Vec<u16> = self
            .name
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .take_while(|&c| c != 0)
            .collect();

        String::from_utf16(&utf16_str).unwrap_or_default()
    }

    /// Get a real actor from `actor` slice.
    pub fn actor(&self) -> String {
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

/// Holds a list of resource ids that are protected from being overlaid by as set of policies.
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1850>
#[derive(Debug)]
pub struct ResTableOverlayblePolicy {
    pub header: ResChunkHeader,

    pub policy_flags: PolicyFlags,

    /// The number of ResTable_ref that follow this header
    pub entry_count: u32,

    pub entries: Vec<u32>,
}

impl ResTableOverlayblePolicy {
    #[inline(always)]
    pub(crate) fn parse(
        header: ResChunkHeader,
        input: &mut &[u8],
    ) -> ModalResult<ResTableOverlayblePolicy> {
        let (policy_flags, entry_count) =
            (le_u32.map(PolicyFlags::from_bits_truncate), le_u32).parse_next(input)?;
        let entries = repeat(entry_count as usize, le_u32).parse_next(input)?;

        Ok(ResTableOverlayblePolicy {
            header,
            policy_flags,
            entry_count,
            entries,
        })
    }
}

/// Maps the staged (non-finalized) resource id to its finalized resource id
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1822>
#[derive(Debug)]
pub struct ResTableStagedAliasEntry {
    /// The compile-time staged resource id to rewrite
    pub staged_res_id: u32,

    /// The compile-time finalized resource id to which the staged resource id should be rewritten
    pub finalized_res_id: u32,
}

impl ResTableStagedAliasEntry {
    #[inline(always)]
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<ResTableStagedAliasEntry> {
        (le_u32, le_u32)
            .map(
                |(staged_res_id, finalized_res_id)| ResTableStagedAliasEntry {
                    staged_res_id,
                    finalized_res_id,
                },
            )
            .parse_next(input)
    }
}

/// A map that allows rewriting staged (non-finalized) resource ids to therir finalized counterparts
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1811>
#[derive(Debug)]
pub struct ResTableStagedAlias {
    pub header: ResChunkHeader,

    /// The number of [ResTableStagedAliasEntry] that follow this header
    pub count: u32,

    pub entries: Vec<ResTableStagedAliasEntry>,
}

impl ResTableStagedAlias {
    #[inline(always)]
    pub(crate) fn parse(
        header: ResChunkHeader,
        input: &mut &[u8],
    ) -> ModalResult<ResTableStagedAlias> {
        let count = le_u32.parse_next(input)?;
        let entries = repeat(count as usize, ResTableStagedAliasEntry::parse).parse_next(input)?;

        Ok(ResTableStagedAlias {
            header,
            count,
            entries,
        })
    }
}

#[derive(Debug)]
pub struct ResTablePackage {
    pub header: ResTablePackageHeader,
    pub type_strings: StringPool,
    pub key_strings: StringPool,

    // requires fastloop by resource id => resource
    // for example: 0x7f010000 => anim/abc_fade_in or res/anim/abc_fade_in.xml type=XML
    pub resources: BTreeMap<ResTableConfig, HashMap<u8, Vec<ResTableEntry>>>,
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
                Ok(v) if v.type_ == ResourceHeaderType::TablePackage => {
                    input.reset(&checkpoint);
                    break;
                }
                Ok(v) => v,
                Err(ErrMode::Backtrack(_)) => break,
                Err(e) => return Err(e),
            };

            match header.type_ {
                ResourceHeaderType::TableTypeSpec => {
                    // idk what should i do with this value
                    let _ = ResTableTypeSpec::parse(header, input)?;
                }
                ResourceHeaderType::TableType => {
                    let type_type = ResTableType::parse(header, input)?;

                    resources
                        .entry(type_type.config)
                        .or_default()
                        .entry(type_type.id)
                        .or_insert_with(|| type_type.entries);
                }
                ResourceHeaderType::TableLibrary => {
                    // idk what should i do with this value
                    let _ = ResTableLibrary::parse(header, input)?;
                }
                ResourceHeaderType::TableOverlayable => {
                    let _ = ResTableOverlayble::parse(header, input)?;
                }
                ResourceHeaderType::TableOverlayablePolicy => {
                    let _ = ResTableOverlayblePolicy::parse(header, input)?;
                }
                ResourceHeaderType::TableStagedAlias => {
                    let _ = ResTableStagedAlias::parse(header, input)?;
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

    /// Searches for the specified resource in the current package
    pub fn find_entry(
        &self,
        config: &ResTableConfig,
        type_id: u8,
        entry_id: u16,
    ) -> Option<&ResTableEntry> {
        // fast track?
        if let Some(type_map) = self.resources.get(config)
            && let Some(entries) = type_map.get(&type_id)
            && let Some(entry) = entries.get(entry_id as usize)
            && !matches!(entry, ResTableEntry::NoEntry)
        {
            return Some(entry);
        }

        for (other_config, type_map) in &self.resources {
            // skip original config
            if other_config == config {
                continue;
            }

            if let Some(entries) = type_map.get(&type_id)
                && let Some(entry) = entries.get(entry_id as usize)
                && !matches!(entry, ResTableEntry::NoEntry)
            {
                return Some(entry);
            }
        }

        // can't find anything - gg
        None
    }

    /// Constructs the full name of the resource with the type
    #[inline]
    pub fn get_entry_full_name(&self, entry: &ResTableEntry, type_id: u8) -> Option<String> {
        Some(format!(
            "{}/{}",
            self.type_strings.get(type_id.saturating_sub(1) as u32)?,
            self.get_entry_key(entry)?
        ))
    }

    /// Allows you to get the name of a resource depending on its type.
    #[inline]
    fn get_entry_key(&self, entry: &ResTableEntry) -> Option<&String> {
        match entry {
            ResTableEntry::Compact(e) => self.key_strings.get(e.data),
            ResTableEntry::Complex(e) => self.key_strings.get(e.index),
            ResTableEntry::Default(e) => self.key_strings.get(e.index),
            ResTableEntry::NoEntry => None,
        }
    }
}
