use log::warn;
use winnow::{
    binary::{le_u16, le_u32, le_u8},
    combinator::repeat,
    prelude::*,
    token::take,
};

use crate::structs::{res_chunk_header::ResChunkHeader, res_string_pool::StringPool};

/// Type of the data value
#[derive(Debug, Default)]
#[repr(u8)]
pub enum ResourceValueType {
    /// The 'data' is either 0 or 1, specifying this resource is either undefined or empty, respectively.
    #[default]
    Null = 0x00,

    /// The 'data' holds a ResTable_ref — a reference to another resource table entry.
    Reference = 0x01,

    /// The 'data' holds an attribute resource identifier.
    Attribute = 0x02,

    /// The 'data' holds an index into the containing resource table's global value string pool.
    String = 0x03,

    /// The 'data' holds a single-precision floating point number.
    Float = 0x04,

    /// The 'data' holds a complex number encoding a dimension value, such as "100in".
    Dimension = 0x05,

    /// The 'data' holds a complex number encoding a fraction of a container.
    Fraction = 0x06,

    /// The 'data' is a raw integer value of the form n..n.
    Dec = 0x10,

    /// The 'data' is a raw integer value of the form 0xn..n.
    Hex = 0x11,

    /// The 'data' is either 0 or 1, for input "false" or "true" respectively.
    Boolean = 0x12,

    /// The 'data' is a raw integer value of the form #aarrggbb.
    ColorArgb8 = 0x1c,

    /// The 'data' is a raw integer value of the form #rrggbb.
    ColorRgb8 = 0x1d,

    /// The 'data' is a raw integer value of the form #argb.
    ColorArgb4 = 0x1e,

    /// The 'data' is a raw integer value of the form #rgb.
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
            other => ResourceValueType::Unknown(other),
        }
    }
}

#[derive(Debug)]
pub struct XMLResourceMap {
    pub header: ResChunkHeader,
    pub resource_ids: Vec<u32>,
}

impl XMLResourceMap {
    pub fn parse(input: &mut &[u8]) -> ModalResult<XMLResourceMap> {
        let header = ResChunkHeader::parse(input)?;
        let resource_ids = repeat(
            (header.size.saturating_sub(header.header_size as u32) / 4) as usize,
            le_u32,
        )
        .parse_next(input)?;

        Ok(XMLResourceMap {
            header,
            resource_ids,
        })
    }
}

/// Basic XML tree node. A single item in the XML document.
#[derive(Debug, Default)]
pub struct XMLHeader {
    pub(crate) header: ResChunkHeader,

    /// Line number in original source file at which this element appeared
    pub line_number: u32,

    // Optional XML comment that was associated with this element; -1 if none
    pub comment: u32,
}

impl XMLHeader {
    pub fn parse(input: &mut &[u8], header: ResChunkHeader) -> ModalResult<XMLHeader> {
        let (line_number, comment) = (le_u32, le_u32).parse_next(input)?;

        Ok(XMLHeader {
            header,
            line_number,
            comment,
        })
    }

    /// Get the size of the data without taking into account the size of the structure itself
    #[inline(always)]
    pub fn content_size(&self) -> u32 {
        // u32 (line_number) + u32 (comment)
        self.header.content_size().saturating_sub(4 + 4)
    }
}

pub trait XmlElement {
    fn parse(input: &mut &[u8], header: XMLHeader) -> ModalResult<Self>
    where
        Self: Sized;
}

/// Extended XML tree node for namespace start/end nodes
#[derive(Debug)]
pub struct XmlNamespace {
    pub header: XMLHeader,
    /// The prefix of the namespace
    pub prefix: u32,

    /// The URI of the namespace
    pub uri: u32,
}

impl XmlElement for XmlNamespace {
    fn parse(input: &mut &[u8], header: XMLHeader) -> ModalResult<Self>
    where
        Self: Sized,
    {
        let (prefix, uri) = (le_u32, le_u32).parse_next(input)?;

        Ok(XmlNamespace {
            header,
            prefix,
            uri,
        })
    }
}

/// Representation of a value in a resource, supplying type information
#[derive(Debug, Default)]
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
    pub fn parse(input: &mut &[u8]) -> ModalResult<ResourceValue> {
        (le_u16, le_u8, le_u8, le_u32)
            .map(|(size, res, data_type, data)| ResourceValue {
                size,
                res,
                data,
                data_type: ResourceValueType::from(data_type),
            })
            .parse_next(input)
    }

    pub fn to_string(&self, string_pool: &StringPool) -> String {
        match self.data_type {
            ResourceValueType::Reference => format!("@{}{:08X}", self.fmt_package(), self.data),
            ResourceValueType::Attribute => format!("?{}{:08X}", self.fmt_package(), self.data),
            ResourceValueType::String => string_pool.get(self.data).cloned().unwrap_or_default(),
            ResourceValueType::Float => f32::from_bits(self.data).to_string(),
            ResourceValueType::Dimension => format!(
                "{}{}",
                self.complex_to_float(),
                Self::DIMENSION_UNITS[(self.data & Self::COMPLEX_UNIT_MASK) as usize]
            ),
            ResourceValueType::Fraction => format!(
                "{}{}",
                self.complex_to_float() * 100f64,
                Self::FRACTION_UNITS[(self.data & Self::COMPLEX_UNIT_MASK) as usize]
            ),
            ResourceValueType::Dec => self.data.to_string(),
            ResourceValueType::Hex => format!("0x{:08X}", self.data),
            ResourceValueType::Boolean => {
                format!("{}", if self.data == 0 { "false" } else { "true" })
            }
            ResourceValueType::ColorArgb8
            | ResourceValueType::ColorRgb8
            | ResourceValueType::ColorArgb4
            | ResourceValueType::ColorRgb4 => format!("#{:08X}", self.data),
            _ => format!("<0x{:X}, type {:?}>", self.data, self.data_type),
        }
    }

    #[inline(always)]
    pub fn complex_to_float(&self) -> f64 {
        ((self.data & 0xFFFFFF00) as f64) * Self::RADIX_MULTS[((self.data >> 4) & 3) as usize]
    }

    #[inline(always)]
    pub fn fmt_package(&self) -> &str {
        if self.data >> 24 == 1 {
            "android:"
        } else {
            ""
        }
    }
}

#[derive(Debug, Default)]
pub struct XmlAttributeElement {
    /// Namespace of this attribute
    pub namespace_uri: u32,

    /// Name of this attribute
    pub name: u32,

    /// The original raw string value of this attribute
    pub value: u32,

    /// Processed typed value of this attribute
    pub typed_value: ResourceValue,

    attribute_name: String,
    attribute_value: String,
}

impl XmlAttributeElement {
    const DEFAULT_ATTRIBUTE_SIZE: u16 = 0x14;

    #[inline]
    pub fn parse(
        attribute_size: u16,
    ) -> impl FnMut(&mut &[u8]) -> ModalResult<XmlAttributeElement> {
        move |input: &mut &[u8]| {
            let (namespace_uri, name, value) = (le_u32, le_u32, le_u32).parse_next(input)?;
            let typed_value = ResourceValue::parse(input)?;

            // sometimes attribute size != 20, need to scroll through the data
            let _ = take(attribute_size.saturating_sub(Self::DEFAULT_ATTRIBUTE_SIZE))
                .parse_next(input)?;

            Ok(XmlAttributeElement {
                namespace_uri,
                name,
                value,
                typed_value,
                ..XmlAttributeElement::default()
            })
        }
    }

    #[inline]
    pub fn set_name(&mut self, name: String) {
        self.attribute_name = name
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.attribute_name
    }

    #[inline]
    pub fn set_value(&mut self, value: String) {
        self.attribute_value = value
    }

    #[inline]
    pub fn value(&self) -> &str {
        &self.attribute_value
    }
}

#[derive(Debug, Default)]
pub struct XmlStartElement {
    pub header: XMLHeader,
    /// String of the full namespace of this element
    pub namespace_uri: u32,

    /// String name of this node
    pub name: u32,

    /// Byte offset from the start of this structure where the attributes start
    pub attribute_start: u16,

    /// Size of the ...
    pub attribute_size: u16,

    /// Number of attributes associated with element
    pub attribute_count: u16,

    /// Index (1-based) of the "id" attribute. 0 if none.
    pub id_index: u16,

    /// Index (1-based) of the "class" attribute. 0 if none.
    pub class_index: u16,

    /// Index (1-based) of the "style" attribute. 0 if none.
    pub style_index: u16,

    /// List of associated attributes
    pub attributes: Vec<XmlAttributeElement>,

    element_name: String,
}

impl XmlElement for XmlStartElement {
    fn parse(input: &mut &[u8], header: XMLHeader) -> ModalResult<Self>
    where
        Self: Sized,
    {
        let start = input.len();

        let (
            namespace_uri,
            name,
            attribute_start,
            attribute_size,
            attribute_count,
            id_index,
            class_index,
            style_index,
        ) = (
            le_u32, // namespace_uri
            le_u32, // name
            le_u16, // attribute_start
            le_u16, // attribute_size
            le_u16, // attribute_count
            le_u16, // id_index
            le_u16, // class_index
            le_u16, // style_index
        )
            .parse_next(input)?;

        // TODO: need somehow show this "garbage" indicator
        // consume some garbage until attribute_start - probably packing techniques, idk
        // default "attribute_start" is 0x14, so we take garbage value and subtract
        let tampered_attribute_size =
            attribute_start.saturating_sub(XmlAttributeElement::DEFAULT_ATTRIBUTE_SIZE);
        if tampered_attribute_size != 0 {
            warn!("skip tampered attribute size: {}", attribute_start);
            take(attribute_start.saturating_sub(XmlAttributeElement::DEFAULT_ATTRIBUTE_SIZE))
                .parse_next(input)?;
        }

        let attributes = repeat(
            attribute_count as usize,
            XmlAttributeElement::parse(attribute_size),
        )
        .parse_next(input)?;

        let readed_bytes = start - input.len();

        // TODO: need somehow show this "garbage" indicator
        // consume garbage data after readed chunk
        let tampered_chunk_size = header.content_size().saturating_sub(readed_bytes as u32);
        if tampered_chunk_size != 0 {
            warn!("skip garbage bytes in chunk: {}", tampered_chunk_size);
            take(tampered_chunk_size).parse_next(input)?;
        }

        Ok(XmlStartElement {
            header,
            namespace_uri,
            name,
            attribute_start,
            attribute_size,
            attribute_count,
            id_index,
            class_index,
            style_index,
            attributes,
            ..XmlStartElement::default()
        })
    }
}

impl XmlStartElement {
    pub fn set_name(&mut self, name: String) {
        self.element_name = name
    }

    pub fn name(&self) -> &str {
        &self.element_name
    }
}

#[derive(Debug, Default)]
pub struct XmlEndElement {
    pub header: XMLHeader,
    pub namespace_uri: u32,
    pub name: u32,

    element_name: String,
}

impl XmlElement for XmlEndElement {
    fn parse(input: &mut &[u8], header: XMLHeader) -> ModalResult<Self>
    where
        Self: Sized,
    {
        let (namespace_uri, name) = (le_u32, le_u32).parse_next(input)?;

        Ok(XmlEndElement {
            header,
            namespace_uri,
            name,
            ..XmlEndElement::default()
        })
    }
}

impl XmlEndElement {
    pub fn set_name(&mut self, name: String) {
        self.element_name = name
    }

    pub fn name(&self) -> &str {
        &self.element_name
    }
}

/// Extended XML tree node for CDATA tags - includes the CDATA string.
#[derive(Debug)]
pub struct XmlCData {
    pub header: XMLHeader,

    // The raw CDATA character data
    pub data: u32,

    // The typed value of the character data if this is a CDATA node
    pub typed_data: ResourceValue,
}

impl XmlElement for XmlCData {
    fn parse(input: &mut &[u8], header: XMLHeader) -> ModalResult<Self>
    where
        Self: Sized,
    {
        let data = le_u32(input)?;
        let typed_data = ResourceValue::parse(input)?;

        Ok(XmlCData {
            header,
            data,
            typed_data,
        })
    }
}

#[derive(Debug)]
pub enum XmlNodeElements {
    XmlStartNamespace(XmlNamespace),
    XmlEndNamespace(XmlNamespace),
    XmlStartElement(XmlStartElement),
    XmlEndElement(XmlEndElement),
    XmlCData(XmlCData),
    Unknown,
}
