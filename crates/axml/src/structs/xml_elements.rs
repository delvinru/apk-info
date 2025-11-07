use std::slice;

use log::debug;
use winnow::binary::{le_u16, le_u32};
use winnow::combinator::repeat;
use winnow::prelude::*;
use winnow::token::take;

use crate::axml::system_types;
use crate::structs::{ResChunkHeader, ResourceValue};

#[derive(Debug)]
pub(crate) struct XMLResourceMap {
    #[allow(unused)]
    pub(crate) header: ResChunkHeader,

    pub(crate) resource_ids: Vec<u32>,
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

    #[inline]
    pub fn get_attr(&self, idx: u32) -> Option<&str> {
        self.resource_ids
            .get(idx as usize)
            .and_then(|v| system_types::get_attr(v))
    }
}

/// Basic XML tree node. A single item in the XML document.
#[derive(Debug, Default)]
pub(crate) struct XMLHeader {
    pub(crate) header: ResChunkHeader,

    /// Line number in original source file at which this element appeared
    #[allow(unused)]
    pub(crate) line_number: u32,

    /// Optional XML comment that was associated with this element; -1 if none
    #[allow(unused)]
    pub(crate) comment: u32,
}

impl XMLHeader {
    #[inline]
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

pub trait XmlParse {
    fn parse(input: &mut &[u8], header: XMLHeader) -> ModalResult<Self>
    where
        Self: Sized;
}

/// Extended XML tree node for namespace start/end nodes
#[derive(Debug)]
pub(crate) struct XmlNamespace {
    #[allow(unused)]
    pub(crate) header: XMLHeader,

    /// The prefix of the namespace
    #[allow(unused)]
    pub(crate) prefix: u32,

    /// The URI of the namespace
    #[allow(unused)]
    pub(crate) uri: u32,
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

#[derive(Debug)]
pub(crate) struct XmlAttributeElement {
    /// Namespace of this attribute
    pub(crate) namespace_uri: u32,

    /// Name of this attribute
    pub(crate) name: u32,

    /// The original raw string value of this attribute
    #[allow(unused)]
    pub(crate) value: u32,

    /// Processed typed value of this attribute
    pub(crate) typed_value: ResourceValue,
}

impl XmlAttributeElement {
    const DEFAULT_ATTRIBUTE_SIZE: u16 = 0x14;

    pub fn parse(
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

#[derive(Debug)]
pub(crate) struct XmlStartElement {
    #[allow(unused)]
    pub(crate) header: XMLHeader,

    /// String of the full namespace of this element
    #[allow(unused)]
    pub(crate) namespace_uri: u32,

    /// String name of this node
    pub(crate) name: u32,

    /// Byte offset from the start of this structure where the attributes start
    #[allow(unused)]
    pub(crate) attribute_start: u16,

    /// Size of the ...
    #[allow(unused)]
    pub(crate) attribute_size: u16,

    /// Number of attributes associated with element
    #[allow(unused)]
    pub(crate) attribute_count: u16,

    /// Index (1-based) of the "id" attribute. 0 if none.
    #[allow(unused)]
    pub(crate) id_index: u16,

    /// Index (1-based) of the "class" attribute. 0 if none.
    #[allow(unused)]
    pub(crate) class_index: u16,

    /// Index (1-based) of the "style" attribute. 0 if none.
    #[allow(unused)]
    pub(crate) style_index: u16,

    /// List of associated attributes
    pub(crate) attributes: Vec<XmlAttributeElement>,
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

#[derive(Debug)]
pub(crate) struct XmlEndElement {
    #[allow(unused)]
    pub(crate) header: XMLHeader,

    #[allow(unused)]
    pub(crate) namespace_uri: u32,

    #[allow(unused)]
    pub(crate) name: u32,
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
#[derive(Debug)]
pub(crate) struct XmlCData {
    #[allow(unused)]
    pub(crate) header: XMLHeader,

    /// The raw CDATA character data
    #[allow(unused)]
    pub(crate) data: u32,

    /// The typed value of the character data if this is a CDATA node
    #[allow(unused)]
    pub(crate) typed_data: ResourceValue,
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

#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct Attribute {
    prefix: Option<String>,
    name: String,
    value: String,
}

impl Attribute {
    pub(crate) fn new(prefix: Option<&str>, name: &str, value: &str) -> Attribute {
        Self {
            prefix: prefix.map(String::from),
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }

    #[inline(always)]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    #[inline(always)]
    pub(crate) fn value(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Display for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(prefix) = &self.prefix {
            write!(f, "{}:{}=\"{}\"", prefix, self.name, self.value)
        } else {
            write!(f, "{}=\"{}\"", self.name, self.value)
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Element {
    name: String,
    attributes: Vec<Attribute>,
    childrens: Vec<Element>,
}

impl Element {
    pub(crate) fn new(name: &str) -> Element {
        Element {
            name: name.to_owned(),
            ..Default::default()
        }
    }

    pub(crate) fn set_attribute(mut self, name: &str, value: &str) -> Element {
        self.attributes.push(Attribute::new(None, name, value));
        self
    }

    pub(crate) fn set_attribute_with_prefix(
        mut self,
        prefix: Option<&str>,
        name: &str,
        value: &str,
    ) -> Element {
        self.attributes.push(Attribute::new(prefix, name, value));
        self
    }

    #[inline(always)]
    pub(crate) fn append_child(&mut self, child: Element) {
        self.childrens.push(child);
    }

    pub(crate) fn childrens(&self) -> impl Iterator<Item = &Element> {
        ElementIter {
            iter: self.childrens.iter(),
        }
    }

    pub(crate) fn attributes(&self) -> impl Iterator<Item = &Attribute> {
        AttributeIter {
            iter: self.attributes.iter(),
        }
    }

    #[inline(always)]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline(always)]
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|x| x.name() == name)
            .map(|x| x.value())
    }

    pub(crate) fn fmt_with_indent(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        indent: usize,
    ) -> std::fmt::Result {
        let indent_str = "  ".repeat(indent);

        write!(f, "{}<{}", indent_str, self.name)?;

        if self.attributes.len() > 1 {
            let indent_str = "  ".repeat(indent + 1);

            write!(f, "\n{}", indent_str)?;

            for (idx, attr) in self.attributes.iter().enumerate() {
                write!(f, "{}", attr)?;

                if idx != self.attributes.len() - 1 {
                    write!(f, "\n{}", indent_str)?;
                }
            }
        } else if self.attributes.len() == 1 {
            // safe unwrap, checked that contains at least 1 item
            write!(f, " {}", self.attributes.first().unwrap())?;
        }

        if self.childrens.is_empty() {
            writeln!(f, "/>")?;
        } else {
            writeln!(f, ">")?;

            for child in &self.childrens {
                child.fmt_with_indent(f, indent + 1)?;
            }

            writeln!(f, "{}</{}>", indent_str, self.name)?;
        }

        Ok(())
    }
}

impl std::fmt::Display for Element {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // default xml header
        writeln!(f, "<?xml version=\"1.0\" encoding=\"utf-8\"?>")?;

        // pretty print
        self.fmt_with_indent(f, 0)
    }
}

pub(crate) struct ElementIter<'a> {
    iter: slice::Iter<'a, Element>,
}

impl<'a> Iterator for ElementIter<'a> {
    type Item = &'a Element;

    fn next(&mut self) -> Option<Self::Item> {
        for item in &mut self.iter {
            return Some(item);
        }
        None
    }
}

pub(crate) struct AttributeIter<'a> {
    iter: slice::Iter<'a, Attribute>,
}

impl<'a> Iterator for AttributeIter<'a> {
    type Item = &'a Attribute;

    fn next(&mut self) -> Option<Self::Item> {
        for item in &mut self.iter {
            return Some(item);
        }
        None
    }
}
