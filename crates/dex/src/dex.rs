use std::sync::Arc;

use winnow::binary::{be_u16, be_u32, le_u32, u8};
use winnow::combinator::repeat;
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;
use winnow::token::take;

use crate::errors::DexError;

#[derive(Debug)]
pub struct Dex {
    /// Information about dex header
    pub header: DexHeader,

    /// Dex strings
    pub string_ids: Vec<Arc<String>>,

    /// Dex types
    pub type_ids: Vec<Arc<String>>,
}

impl Dex {
    /// The constant is used to indicate the endiannes of the file in whic it is found.
    ///
    /// This constant means - little-endian.
    ///
    /// See: <https://source.android.com/docs/core/runtime/dex-format#endian-constant>
    const ENDIAN_CONSTANT: u32 = 0x12345678;

    /// The constant is used to indicate the endiannes of the file in whic it is found.
    ///
    /// This constant means - big-endian.
    ///
    /// See: <https://source.android.com/docs/core/runtime/dex-format#endian-constant>
    const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;

    /// Parse given dex file
    ///
    /// ```ignore
    /// let dex = Dex::new(input).expect("can't parse dex file");
    /// ```
    pub fn new(input: &mut &[u8]) -> Result<Dex, DexError> {
        let data = &input[0..];

        // parse dex header
        let header = Self::parse_dex_header(input).map_err(|_| DexError::InvalidHeader)?;

        // parse strings
        let string_ids =
            Self::parse_string_ids(input, &header, data).map_err(|_| DexError::StringsError)?;

        // parse_types
        let type_ids =
            Self::parse_type_ids(input, &header, &string_ids).map_err(|_| DexError::TypesError)?;

        Ok(Dex {
            header,
            string_ids,
            type_ids,
        })
    }

    fn parse_dex_header(input: &mut &[u8]) -> ModalResult<DexHeader> {
        let (magic, _, version, _) = (
            be_u32.verify(|magic| *magic == 0x6465780A),
            u8.verify(|v| *v == 0x30),
            be_u16.try_map(|v| DexVersion::try_from(v)),
            u8.verify(|v| *v == 0x00),
        )
            .parse_next(input)?;

        let (
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_off,
            map_off,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            field_ids_size,
            field_ids_off,
            method_ids_size,
            method_ids_off,
            class_defs_size,
            class_defs_off,
            data_size,
            data_off,
        ) = (
            le_u32,                              // checksum
            take(20usize).map(|v| Arc::from(v)), // signature
            le_u32,                              // file_size
            le_u32,                              // header_size
            le_u32.verify(|&tag| {
                tag == Self::ENDIAN_CONSTANT || tag == Self::REVERSE_ENDIAN_CONSTANT
            }), // endian_tag
            le_u32,                              // link_size
            le_u32,                              // link_off
            le_u32,                              // map_off
            le_u32,                              // string_ids_size
            le_u32,                              // string_ids_off
            le_u32.verify(|&size| size <= u16::MAX.into()), // type_ids_size
            le_u32,                              // type_ids_off
            le_u32.verify(|&size| size <= u16::MAX.into()), // proto_ids_size
            le_u32,                              // proto_ids_off
            le_u32,                              // field_ids_size
            le_u32,                              // field_ids_off
            le_u32,                              // method_ids_size
            le_u32,                              // method_ids_off
            le_u32,                              // class_defs_size
            le_u32,                              // class_defs_off
            le_u32,                              // data_size
            le_u32,                              // data_off
        )
            .parse_next(input)?;

        let mut container_size = 0;
        let mut header_offset = 0;
        if version >= DexVersion::DEX41 {
            (container_size, header_offset) = (le_u32, le_u32).parse_next(input)?;
        }

        Ok(DexHeader {
            magic,
            version,
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_off,
            map_off,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            field_ids_size,
            field_ids_off,
            method_ids_size,
            method_ids_off,
            class_defs_size,
            class_defs_off,
            data_size,
            data_off,
            container_size,
            header_offset,
        })
    }

    fn parse_string_ids(
        input: &mut &[u8],
        header: &DexHeader,
        data: &[u8],
    ) -> ModalResult<Vec<Arc<String>>> {
        // dex file doesn't contains strings
        // it's a strange case, but it need to be checked
        if header.string_ids_off == 0 {
            return Ok(Vec::new());
        }

        let string_offsets: Vec<u32> =
            repeat(header.string_ids_size as usize, le_u32).parse_next(input)?;

        Ok(string_offsets
            .into_iter()
            .filter_map(|offset| Self::parse_string_from_offset(data, offset))
            .map(Arc::new)
            .collect())
    }

    fn parse_string_from_offset(data: &[u8], offset: u32) -> Option<String> {
        data.get(offset as usize..).and_then(|mut data| {
            let utf16size = Self::uleb128(&mut data).ok()?;
            let bytes = take::<usize, &[u8], ContextError>(utf16size as usize)
                .parse_next(&mut data)
                .ok()?;

            let s = simd_cesu8::mutf8::decode_lossy(bytes).to_string();
            Some(s)
        })
    }

    fn parse_type_ids(
        input: &mut &[u8],
        header: &DexHeader,
        string_ids: &[Arc<String>],
    ) -> ModalResult<Vec<Arc<String>>> {
        // dex file doesn't contains types
        // it's a strange case, but it need to be checked
        if header.type_ids_off == 0 {
            return Ok(Vec::new());
        }

        let descriptor_indexes: Vec<u32> =
            repeat(header.type_ids_size as usize, le_u32).parse_next(input)?;

        Ok(descriptor_indexes
            .into_iter()
            .filter_map(|idx| string_ids.get(idx as usize).cloned())
            .collect())
    }

    fn uleb128(input: &mut &[u8]) -> ModalResult<u64> {
        let mut val = 0u64;
        let mut shift = 0u32;

        let mut byte: u8;

        loop {
            byte = u8.parse_next(input)?;
            let b = (byte & 0x7f) as u64;
            val |= b
                .checked_shl(shift)
                .ok_or(ErrMode::Cut(ContextError::new()))?;

            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }

        Ok(val)
    }
}

/// Known dex versions
///
/// See: <https://source.android.com/docs/core/runtime/dex-format#dex-file-magic>
#[derive(Default, Debug, Clone, PartialEq, PartialOrd)]
pub enum DexVersion {
    #[default]
    DEX35,
    DEX36,
    DEX37,
    DEX38,
    DEX39,
    DEX40,
    DEX41,
}

impl TryFrom<u16> for DexVersion {
    type Error = DexError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x3335 => Ok(DexVersion::DEX35),
            0x3336 => Ok(DexVersion::DEX36),
            0x3337 => Ok(DexVersion::DEX37),
            0x3338 => Ok(DexVersion::DEX38),
            0x3339 => Ok(DexVersion::DEX39),
            0x3430 => Ok(DexVersion::DEX40),
            0x3431 => Ok(DexVersion::DEX41),
            _ => Err(DexError::UnknownVersion(value)),
        }
    }
}

impl From<DexVersion> for u32 {
    fn from(value: DexVersion) -> Self {
        match value {
            DexVersion::DEX35 => 35,
            DexVersion::DEX36 => 36,
            DexVersion::DEX37 => 37,
            DexVersion::DEX38 => 38,
            DexVersion::DEX39 => 39,
            DexVersion::DEX40 => 40,
            DexVersion::DEX41 => 41,
        }
    }
}

/// Abstraction over dex header
///
/// See: <https://source.android.com/docs/core/runtime/dex-format#header-item>
#[derive(Default, Debug, Clone)]
pub struct DexHeader {
    /// Magic value
    pub magic: u32,

    /// Known dex version
    pub version: DexVersion,

    /// Adler32 checksum of the file
    ///
    /// Used to detect file corruption
    pub checksum: u32,

    /// SHA-1 signature of the file
    ///
    /// Used to uniquely identify files
    pub signature: Arc<[u8]>,

    /// Size of the entire file (including the header) in bytes
    pub file_size: u32,

    /// Size of the header (this entire section) in bytes
    pub header_size: u32,

    /// Endiannes tag - [Dex::ENDIAN_CONSTANT] or [Dex::REVERSE_ENDIAN_CONSTANT]
    pub endian_tag: u32,

    /// Size of the link section
    ///
    /// 0 - if this file isn't statically linked
    pub link_size: u32,

    /// Offset from the start of the file to the link section
    ///
    /// 0 - if `link_size == 0`
    pub link_off: u32,

    /// Offset from the start of the file to the map item
    pub map_off: u32,

    /// Count of strings in the string identifiers list
    pub string_ids_size: u32,

    /// Offset from the start of the file to the string identifiers list
    ///
    /// 0 - if `string_ids_size == 0`
    pub string_ids_off: u32,

    /// Count of elements in the type identifiers list, at most 65535
    pub type_ids_size: u32,

    /// Offset from the start of the file to the type identifiers list
    ///
    /// 0 - if `type_ids_size == 0`
    pub type_ids_off: u32,

    /// Count of elements in the prototype identifiers list, at most 65535
    pub proto_ids_size: u32,

    /// Offset from the start of the file to the prototype identifiers list
    ///
    /// 0 - if `proto_ids_size == 0`
    pub proto_ids_off: u32,

    /// Count of elements in the field identifiers list
    pub field_ids_size: u32,

    /// Offset from the start of the file to the field identifiers list
    ///
    /// 0 - if `field_ids_size == 0`
    pub field_ids_off: u32,

    /// Count of elements in the method identifiers list
    pub method_ids_size: u32,

    /// Offset from the start of the file to the method identifiers list
    ///
    /// 0 - if `method_ids_size == 0`
    pub method_ids_off: u32,

    /// Count of elements in the class definitions list
    pub class_defs_size: u32,

    /// Offset from the start of the file to the class definitions list
    ///
    /// 0 - if `class_defs_size == 0`
    pub class_defs_off: u32,

    /// Size of `data` section in bytes.
    ///
    /// Must be an event multiple of sizeof(uint)
    ///
    /// Unused in [DexVersion::DEX41] or later
    pub data_size: u32,

    /// Offset from the start of the file to the start of the `data` section
    ///
    /// Must be an event multiple of sizeof(uint)
    ///
    /// Unused in [DexVersion::DEX41] or later
    pub data_off: u32,

    /// Size of the entire file (including other dex headers and their data)
    ///
    /// Unused in [DexVersion::DEX40] or earlier
    pub container_size: u32,

    /// Offset from the start of the file to the start of this header
    ///
    /// Unused in [DexVersion::DEX40] or earlier
    pub header_offset: u32,
}
