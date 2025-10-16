use winnow::{
    binary::{le_u16, le_u32},
    prelude::*,
};

#[derive(Debug, PartialEq, Default, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum ResourceType {
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

impl From<u16> for ResourceType {
    fn from(value: u16) -> Self {
        match value {
            0x0000 => ResourceType::Null,
            0x0001 => ResourceType::StringPool,
            0x0002 => ResourceType::Table,
            0x0003 => ResourceType::Xml,
            0x0100 => ResourceType::XmlStartNamespace,
            0x0101 => ResourceType::XmlEndNamespace,
            0x0102 => ResourceType::XmlStartElement,
            0x0103 => ResourceType::XmlEndElement,
            0x0104 => ResourceType::XmlCdata,
            0x017f => ResourceType::XmlLastChunk,
            0x0180 => ResourceType::XmlResourceMap,
            0x0200 => ResourceType::TablePackage,
            0x0201 => ResourceType::TableType,
            0x0202 => ResourceType::TableTypeSpec,
            0x0203 => ResourceType::TableLibrary,
            0x0204 => ResourceType::TableOverlayable,
            0x0205 => ResourceType::TableOverlayablePolicy,
            0x0206 => ResourceType::TableStagedAlias,
            other => ResourceType::Unknown(other),
        }
    }
}

/// Header that appears at the front of every data chunk in a resource
///
/// See: https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h;l=220?q=ResourceTypes.h&ss=android
#[derive(Debug, Default)]
pub struct ResChunkHeader {
    /// Type identifier for this chunk.  The meaning of this value depends
    /// on the containing chunk.
    pub type_: ResourceType,

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
    pub fn parse(input: &mut &[u8]) -> ModalResult<ResChunkHeader> {
        (le_u16, le_u16, le_u32)
            .map(|(type_, header_size, size)| ResChunkHeader {
                type_: ResourceType::from(type_),
                header_size,
                size,
            })
            .parse_next(input)
    }
}
