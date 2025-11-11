use std::fmt::Write;

use winnow::binary::{le_u8, le_u16, le_u32};
use winnow::prelude::*;

use crate::ARSC;
use crate::structs::{StringPool, system_types};

/// Possible blocks that may occur in `AndroidManifest.xml`
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#239>
#[derive(Debug, PartialEq, Default, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum ResourceHeaderType {
    #[default]
    Null = 0x0000,
    StringPool = 0x0001,
    Table = 0x0002,
    Xml = 0x0003,

    // Chunk types in XmlType
    // Just use XmlStartNamespaceType instead of XmlFirstChunkType
    // XmlFirstChunkType = 0x0100,
    XmlStartNamespace = 0x0100,
    XmlEndNamespace = 0x0101,
    XmlStartElement = 0x0102,
    XmlEndElement = 0x0103,
    XmlCdata = 0x0104,
    XmlLastChunk = 0x017f,
    XmlResourceMap = 0x0180,

    // Chunk types in TableType
    TablePackage = 0x0200,
    TableType = 0x0201,
    TableTypeSpec = 0x0202,
    TableLibrary = 0x0203,
    TableOverlayable = 0x0204,
    TableOverlayablePolicy = 0x0205,
    TableStagedAlias = 0x0206,

    Unknown(u16),
}

impl From<u16> for ResourceHeaderType {
    fn from(value: u16) -> Self {
        match value {
            0x0000 => ResourceHeaderType::Null,
            0x0001 => ResourceHeaderType::StringPool,
            0x0002 => ResourceHeaderType::Table,
            0x0003 => ResourceHeaderType::Xml,
            0x0100 => ResourceHeaderType::XmlStartNamespace,
            0x0101 => ResourceHeaderType::XmlEndNamespace,
            0x0102 => ResourceHeaderType::XmlStartElement,
            0x0103 => ResourceHeaderType::XmlEndElement,
            0x0104 => ResourceHeaderType::XmlCdata,
            0x017f => ResourceHeaderType::XmlLastChunk,
            0x0180 => ResourceHeaderType::XmlResourceMap,
            0x0200 => ResourceHeaderType::TablePackage,
            0x0201 => ResourceHeaderType::TableType,
            0x0202 => ResourceHeaderType::TableTypeSpec,
            0x0203 => ResourceHeaderType::TableLibrary,
            0x0204 => ResourceHeaderType::TableOverlayable,
            0x0205 => ResourceHeaderType::TableOverlayablePolicy,
            0x0206 => ResourceHeaderType::TableStagedAlias,
            other => ResourceHeaderType::Unknown(other),
        }
    }
}

/// Header that appears at the front of every data chunk in a resource
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#220>
#[derive(Debug, Default)]
pub struct ResChunkHeader {
    /// Type identifier for this chunk. The meaning of this value depends on the containing chunk.
    pub type_: ResourceHeaderType,

    /// Size of the chunk header (in bytes).  Adding this value to
    /// the address of the chunk allows you to find its associated data
    /// (if any).
    pub header_size: u16,

    /// Total size of this chunk (in bytes).  This is the chunkSize plus
    /// the size of any data associated with the chunk.  Adding this value
    /// to the chunk allows you to completely skip its contents (including
    /// any child chunks).  If this value is the same as chunkSize, there is
    /// no data associated with the chunk.
    pub size: u32,
}

impl ResChunkHeader {
    #[inline]
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<ResChunkHeader> {
        (le_u16, le_u16, le_u32)
            .map(|(type_, header_size, size)| ResChunkHeader {
                type_: ResourceHeaderType::from(type_),
                header_size,
                size,
            })
            .parse_next(input)
    }

    /// Get the size of the data without taking into account the size of the structure itself
    #[inline(always)]
    pub fn content_size(&self) -> u32 {
        // u16 (type_) + u16 (header_size) + u32 (size)
        self.size.saturating_sub(2 + 2 + 4)
    }

    /// Get the size of this structure in bytes
    #[inline(always)]
    pub const fn size_of() -> usize {
        // 2 bytes - ResourceTypes
        // 2 bytes - header_size
        // 4 bytes - size
        2 + 2 + 4
    }
}

/// Type of the data value
#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ResourceValueType {
    /// The `data` is either 0 or 1, specifying this resource is either undefined or empty, respectively.
    Null = 0x00,

    /// The `data` holds a ResTable_ref — a reference to another resource table entry.
    Reference = 0x01,

    /// The `data` holds an attribute resource identifier.
    Attribute = 0x02,

    /// The `data` holds an index into the containing resource table's global value string pool.
    String = 0x03,

    /// The `data` holds a single-precision floating point number.
    Float = 0x04,

    /// The `data` holds a complex number encoding a dimension value, such as "100in".
    Dimension = 0x05,

    /// The `data` holds a complex number encoding a fraction of a container.
    Fraction = 0x06,

    /// The `data` is a raw integer value of the form n..n.
    Dec = 0x10,

    /// The `data` is a raw integer value of the form 0xn..n.
    Hex = 0x11,

    /// The `data` is either 0 or 1, for input "false" or "true" respectively.
    Boolean = 0x12,

    /// The `data` is a raw integer value of the form #aarrggbb.
    ColorArgb8 = 0x1c,

    /// The `data` is a raw integer value of the form #rrggbb.
    ColorRgb8 = 0x1d,

    /// The `data` is a raw integer value of the form #argb.
    ColorArgb4 = 0x1e,

    /// The `data` is a raw integer value of the form #rgb.
    ColorRgb4 = 0x1f,

    /// Unknown type value
    Unknown(u8),
}

impl From<u8> for ResourceValueType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => ResourceValueType::Null,
            0x01 => ResourceValueType::Reference,
            0x02 => ResourceValueType::Attribute,
            0x03 => ResourceValueType::String,
            0x04 => ResourceValueType::Float,
            0x05 => ResourceValueType::Dimension,
            0x06 => ResourceValueType::Fraction,
            0x10 => ResourceValueType::Dec,
            0x11 => ResourceValueType::Hex,
            0x12 => ResourceValueType::Boolean,
            0x1c => ResourceValueType::ColorArgb8,
            0x1d => ResourceValueType::ColorRgb8,
            0x1e => ResourceValueType::ColorArgb4,
            0x1f => ResourceValueType::ColorRgb4,
            v => ResourceValueType::Unknown(v),
        }
    }
}

/// Representation of a value in a resource, supplying type information
#[derive(Debug, PartialEq, Eq)]
pub struct ResourceValue {
    /// Number of bytes in this structure
    pub size: u16,

    /// Always set to 0
    pub res: u8,

    /// Type of the data value
    pub data_type: ResourceValueType,

    /// Data itself
    pub data: u32,
}

impl ResourceValue {
    const RADIX_MULTS: [f64; 4] = [0.00390625, 3.051758e-005, 1.192093e-007, 4.656613e-010];
    const DIMENSION_UNITS: [&str; 6] = ["px", "dip", "sp", "pt", "in", "mm"];
    const COMPLEX_UNIT_MASK: u32 = 0x0F;
    const FRACTION_UNITS: [&str; 2] = ["%", "%p"];

    #[inline]
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<ResourceValue> {
        (le_u16, le_u8, le_u8, le_u32)
            .map(|(size, res, data_type, data)| ResourceValue {
                size,
                res,
                data,
                data_type: ResourceValueType::from(data_type),
            })
            .parse_next(input)
    }

    pub fn to_string(&self, string_pool: &StringPool, arsc: Option<&ARSC>) -> String {
        let mut out = String::with_capacity(32);

        match self.data_type {
            ResourceValueType::Reference => {
                out.push('@');

                if self.is_system_type() {
                    if let Some(name) = system_types::get_type_name(&self.data) {
                        out.push_str(name);
                    } else {
                        // fallback
                        write!(&mut out, "{:08x}", self.data).unwrap();
                    }
                } else if let Some(arsc) = arsc {
                    if let Some(value) = arsc.get_resource_name(self.data) {
                        out.push_str(&value);
                        return out;
                    } else {
                        // fallback
                        write!(&mut out, "{:08x}", self.data).unwrap();
                    }
                } else {
                    // fallback
                    write!(&mut out, "{:08x}", self.data).unwrap();
                }

                out
            }

            ResourceValueType::Attribute => {
                if self.is_system_type() {
                    if let Some(name) = system_types::get_type_name(&self.data) {
                        out.push_str(name);
                    } else {
                        // fallback
                        write!(&mut out, "@{:08x}", self.data).unwrap();
                    }
                } else {
                    write!(&mut out, "?{:08x}", self.data).unwrap();
                }

                out
            }

            ResourceValueType::String => {
                // direct clone or fallback to empty
                string_pool.get(self.data).cloned().unwrap_or_default()
            }

            ResourceValueType::Float => {
                // avoid heap
                let f = f32::from_bits(self.data);
                write!(&mut out, "{}", f).unwrap();
                out
            }

            ResourceValueType::Dimension => {
                let idx = (self.data & Self::COMPLEX_UNIT_MASK) as usize;
                let unit = Self::DIMENSION_UNITS.get(idx).unwrap_or(&"");
                write!(&mut out, "{}{}", self.complex_to_float(), unit).unwrap();
                out
            }

            ResourceValueType::Fraction => {
                let idx = (self.data & Self::COMPLEX_UNIT_MASK) as usize;
                let unit = Self::FRACTION_UNITS.get(idx).unwrap_or(&"");
                write!(&mut out, "{}{}", self.complex_to_float() * 100.0, unit).unwrap();
                out
            }

            ResourceValueType::Dec => {
                write!(&mut out, "{}", self.data as i32).unwrap();
                out
            }

            ResourceValueType::Hex => {
                write!(&mut out, "0x{:08x}", self.data).unwrap();
                out
            }

            ResourceValueType::Boolean => {
                if self.data == 0 {
                    "false".into()
                } else {
                    "true".into()
                }
            }

            ResourceValueType::ColorArgb8
            | ResourceValueType::ColorRgb8
            | ResourceValueType::ColorArgb4
            | ResourceValueType::ColorRgb4 => {
                write!(&mut out, "#{:08x}", self.data).unwrap();
                out
            }

            _ => {
                write!(&mut out, "<0x{:x}, type {:?}>", self.data, self.data_type).unwrap();
                out
            }
        }
    }

    #[inline(always)]
    pub fn complex_to_float(&self) -> f64 {
        ((self.data & 0xFFFFFF00) as f64) * Self::RADIX_MULTS[((self.data >> 4) & 3) as usize]
    }

    #[inline(always)]
    pub fn is_system_type(&self) -> bool {
        self.data >> 24 == 1
    }
}
