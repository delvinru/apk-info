use winnow::{
    binary::{le_u16, le_u32, le_u8},
    combinator::repeat,
    prelude::*,
    token::take,
};

use crate::structs::{res_chunk_header::ResChunkHeader, res_string_pool::StringPool};

#[derive(Debug, Default)]
#[repr(u8)]
pub enum ResourceValueType {
    #[default]
    Null = 0x00,
    Reference = 0x01,
    Attribute = 0x02,
    String = 0x03,
    Float = 0x04,
    Dimension = 0x05,
    Fraction = 0x06,
    Dec = 0x10,
    Hex = 0x11,
    Boolean = 0x12,
    ColorArgb8 = 0x1c,
    ColorRgb8 = 0x1d,
    ColorArgb4 = 0x1e,
    ColorRgb4 = 0x1f,
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

#[derive(Debug, Default)]
pub struct XMLHeader {
    pub header: ResChunkHeader,
    pub line_number: u32,
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
}

pub trait XmlElement {
    fn parse(input: &mut &[u8], header: XMLHeader) -> ModalResult<Self>
    where
        Self: Sized;
}

#[derive(Debug)]
pub struct XmlStartNamespace {
    pub header: XMLHeader,
    pub prefix: u32,
    pub uri: u32,
}

impl XmlElement for XmlStartNamespace {
    fn parse(input: &mut &[u8], header: XMLHeader) -> ModalResult<Self>
    where
        Self: Sized,
    {
        let (prefix, uri) = (le_u32, le_u32).parse_next(input)?;

        Ok(XmlStartNamespace {
            header,
            prefix,
            uri,
        })
    }
}

#[derive(Debug)]
pub struct XmlEndNamespace {
    pub header: XMLHeader,
    pub prefix: u32,
    pub uri: u32,
}

impl XmlElement for XmlEndNamespace {
    fn parse(input: &mut &[u8], header: XMLHeader) -> ModalResult<Self>
    where
        Self: Sized,
    {
        let (prefix, uri) = (le_u32, le_u32).parse_next(input)?;

        Ok(XmlEndNamespace {
            header,
            prefix,
            uri,
        })
    }
}

#[derive(Debug, Default)]
pub struct ResourceValue {
    pub size: u16,
    pub res: u8,
    pub data_type: ResourceValueType,
    pub data: u32,
}

impl ResourceValue {
    const RADIX_MULTS: [f64; 4] = [0.00390625, 3.051758e-005, 1.192093e-007, 4.656613e-010];
    const DIMENSION_UNITS: [&str; 6] = ["px", "dip", "sp", "pt", "in", "mm"];
    const COMPLEX_UNIT_MASK: u32 = 0x0F;
    const FRACTION_UNITS: [&str; 2] = ["%", "%p"];

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
    pub namespace_uri: u32,
    pub name: u32,
    pub value: u32,
    pub typed_value: ResourceValue,

    attribute_name: String,
    attribute_value: String,
}

impl XmlAttributeElement {
    const DEFAULT_ATTRIBUTE_SIZE: u16 = 0x14;

    pub fn parse(
        attribute_size: u16,
    ) -> impl FnMut(&mut &[u8]) -> ModalResult<XmlAttributeElement> {
        move |input: &mut &[u8]| {
            let (namespace_uri, name, value) = (le_u32, le_u32, le_u32).parse_next(input)?;
            let typed_value = ResourceValue::parse(input)?;

            // sometimes attribute size != 0x20, need to scroll through the data
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
    pub namespace_uri: u32,
    pub name: u32,
    pub attribute_start: u16,
    pub attribute_size: u16,
    pub attribute_count: u16,
    pub id_index: u16,
    pub class_index: u16,
    pub style_index: u16,
    pub attributes: Vec<XmlAttributeElement>,

    // emit additional attributes
    pub tampered_xml: bool,

    element_name: String,
}

impl XmlStartElement {
    const BASE_SIZE: u32 = 36;
}

impl XmlElement for XmlStartElement {
    fn parse(input: &mut &[u8], header: XMLHeader) -> ModalResult<Self>
    where
        Self: Sized,
    {
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

        let attributes = repeat(
            attribute_count as usize,
            XmlAttributeElement::parse(attribute_size),
        )
        .parse_next(input)?;

        // check if garbage data at the end, often in malware
        let mut tampered_xml = false;
        let readed_bytes = Self::BASE_SIZE + (attribute_count * attribute_size) as u32;
        let remaining_bytes = header.header.size.saturating_sub(readed_bytes);
        if remaining_bytes != 0 {
            tampered_xml = true;
            let _ = take(remaining_bytes as usize).parse_next(input)?;
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
            tampered_xml,
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

#[derive(Debug)]
pub struct XmlCData {
    pub header: XMLHeader,
    pub data: u32,
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
    XmlStartNamespace(XmlStartNamespace),
    XmlEndNamespace(XmlEndNamespace),
    XmlStartElement(XmlStartElement),
    XmlEndElement(XmlEndElement),
    XmlCData(XmlCData),
    Unknown,
}
