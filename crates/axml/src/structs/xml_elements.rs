use log::debug;
use winnow::binary::{le_u16, le_u32};
use winnow::combinator::repeat;
use winnow::prelude::*;
use winnow::token::take;

use crate::structs::{ResChunkHeader, ResourceValue, system_types};

#[derive(Debug)]
pub struct XMLResourceMap {
    pub header: ResChunkHeader,

    pub resource_ids: Vec<u32>,
}

impl XMLResourceMap {
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<XMLResourceMap> {
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

    #[inline]
    pub fn get_attr(&self, idx: u32) -> Option<&str> {
        self.resource_ids
            .get(idx as usize)
            .and_then(|v| system_types::get_type_name(v))
    }
}

/// Basic XML tree node. A single item in the XML document.
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#632>
#[derive(Debug, Default)]
pub struct XMLHeader {
    pub header: ResChunkHeader,

    /// Line number in original source file at which this element appeared
    pub line_number: u32,

    /// Optional XML comment that was associated with this element; -1 if none
    pub comment: u32,
}

impl XMLHeader {
    #[inline]
    pub(crate) fn parse(input: &mut &[u8], header: ResChunkHeader) -> ModalResult<XMLHeader> {
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

pub trait XmlParse {
    fn parse(input: &mut &[u8], header: XMLHeader) -> ModalResult<Self>
    where
        Self: Sized;
}

/// Extended XML tree node for namespace start/end nodes.
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#660>
#[derive(Debug)]
pub struct XmlNamespace {
    pub header: XMLHeader,

    /// The prefix of the namespace
    pub prefix: u32,

    /// The URI of the namespace
    pub uri: u32,
}

impl XmlParse for XmlNamespace {
    #[inline]
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

/// XML Attribute
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#718>
#[derive(Debug)]
pub struct XmlAttributeElement {
    /// Namespace of this attribute
    pub namespace_uri: u32,

    /// Name of this attribute
    pub name: u32,

    /// The original raw string value of this attribute
    pub value: u32,

    /// Processed typed value of this attribute
    pub typed_value: ResourceValue,
}

impl XmlAttributeElement {
    const DEFAULT_ATTRIBUTE_SIZE: u16 = 0x14;

    pub(crate) fn parse(
        attribute_size: u16,
    ) -> impl FnMut(&mut &[u8]) -> ModalResult<XmlAttributeElement> {
        move |input: &mut &[u8]| {
            let (namespace_uri, name, value, typed_value) =
                (le_u32, le_u32, le_u32, ResourceValue::parse).parse_next(input)?;

            // sometimes attribute size != 20, need to scroll through the data
            if let Some(extra) = attribute_size.checked_sub(Self::DEFAULT_ATTRIBUTE_SIZE)
                && extra > 0
            {
                let _ = take(extra).parse_next(input)?;
            }

            Ok(XmlAttributeElement {
                namespace_uri,
                name,
                value,
                typed_value,
            })
        }
    }
}

/// Extended XML tree node for start tags - includes attribute information.
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#688>
#[derive(Debug)]
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
}

impl XmlParse for XmlStartElement {
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

        // consume some garbage until attribute_start - probably packing techniques, idk
        // default "attribute_start" is 0x14, so we take garbage value and subtract
        let tampered_attribute_size =
            attribute_start.saturating_sub(XmlAttributeElement::DEFAULT_ATTRIBUTE_SIZE);
        if tampered_attribute_size != 0 {
            debug!("skip tampered attribute size: {}", attribute_start);

            let _ =
                take(attribute_start.saturating_sub(XmlAttributeElement::DEFAULT_ATTRIBUTE_SIZE))
                    .parse_next(input)?;
        }

        let attributes = repeat(
            attribute_count as usize,
            XmlAttributeElement::parse(attribute_size),
        )
        .parse_next(input)?;

        let readed_bytes = start - input.len();

        // consume garbage data after readed chunk
        let tampered_chunk_size = header.content_size().saturating_sub(readed_bytes as u32);
        if tampered_chunk_size != 0 {
            debug!("skip garbage bytes in chunk: {}", tampered_chunk_size);
            let _ = take(tampered_chunk_size).parse_next(input)?;
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
        })
    }
}

/// Extended XML tree node for element start/end nodes.
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#673>
#[derive(Debug)]
pub struct XmlEndElement {
    pub header: XMLHeader,

    /// String of the full namespace of this element.
    pub namespace_uri: u32,

    /// String anme of this node if it as an ELEMENT;
    ///
    /// The raw character data if this is a CDATA node.
    pub name: u32,
}

impl XmlParse for XmlEndElement {
    #[inline]
    fn parse(input: &mut &[u8], header: XMLHeader) -> ModalResult<Self>
    where
        Self: Sized,
    {
        let (namespace_uri, name) = (le_u32, le_u32).parse_next(input)?;

        Ok(XmlEndElement {
            header,
            namespace_uri,
            name,
        })
    }
}

/// Extended XML tree node for CDATA tags - includes the CDATA string.
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#647>
#[derive(Debug)]
pub struct XmlCData {
    pub header: XMLHeader,

    /// The raw CDATA character data
    pub data: u32,

    /// The typed value of the character data if this is a CDATA node
    pub typed_data: ResourceValue,
}

impl XmlParse for XmlCData {
    #[inline]
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
